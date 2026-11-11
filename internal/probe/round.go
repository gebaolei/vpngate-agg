package probe

import (
	"context"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// RoundOptions 是一轮探测的调度参数。
type RoundOptions struct {
	Concurrency int
	HistoryKeep int
	// BatchSize/BatchDelay 控制结果写回的粒度：任一条件满足就写一批。
	//
	// 每个结果都抢写锁会把界面的列表查询挤成一列；攒批又把实时性丢掉。
	// 默认 32 个或 1.5 秒一批，实测是「进度条在动、列表不卡」的折中。
	BatchSize  int
	BatchDelay time.Duration
	// Stagger 是每个探测之间的最小间隔，用来对上游客气一点。
	Stagger time.Duration
}

func (o RoundOptions) withDefaults() RoundOptions {
	if o.Concurrency <= 0 {
		o.Concurrency = 32
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 32
	}
	if o.BatchDelay <= 0 {
		o.BatchDelay = 1500 * time.Millisecond
	}
	if o.HistoryKeep <= 0 {
		o.HistoryKeep = 8
	}
	return o
}

// RunRound 并发探测一批节点。
//
// apply 会被调度线程串行调用（不是探测线程），所以实现方不需要自己加锁，
// 但也不能长阻塞 —— 写盘之类的慢活要放到别处。
// onProgress 同理，用于推进度。
func RunRound(ctx context.Context, prober *Prober, targets []Target, opt RoundOptions,
	apply func(map[string]*model.ProbeResult), onProgress func(done, ok int, last string)) (*model.JobState, error) {
	opt = opt.withDefaults()
	job := &model.JobState{Kind: "probe", Status: "running", StartedAt: time.Now().UTC(), Total: len(targets)}
	if len(targets) == 0 {
		job.Status = "done"
		job.EndedAt = time.Now().UTC()
		return job, nil
	}

	ch := make(chan Target, 64)
	results := make(chan *model.ProbeResult, 256)

	var wg sync.WaitGroup
	workers := opt.Concurrency
	if workers > len(targets) {
		workers = len(targets)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				if ctx.Err() != nil {
					return
				}
				results <- prober.Probe(ctx, t)
				if opt.Stagger > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(opt.Stagger):
					}
				}
			}
		}()
	}

	// 投喂：单独一个 goroutine，取消时能收尾，否则 worker 退完就没人从 ch 取
	// 东西了，wg.Wait 会永久卡在这里。
	go func() {
		defer close(ch)
		for _, t := range targets {
			select {
			case ch <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 结果聚合：单线程消费，攒够一批就 apply 一次。
	go func() {
		wg.Wait()
		close(results)
	}()

	// 预建端点索引：O(n) 一次，比每条结果线性扫一遍好（一轮几千条）。
	index := buildIndex(targets)
	batch := map[string]*model.ProbeResult{}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if apply != nil {
			apply(batch)
		}
		batch = map[string]*model.ProbeResult{}
	}
	ticker := time.NewTicker(opt.BatchDelay)
	defer ticker.Stop()

	for res := range results {
		job.Done++
		if res.OK {
			job.OK++
		} else if model.NegativeResult(*res) {
			job.Failed++
		} else {
			// UDP 无回包、被取消这类「说不清」不算失败，单独计数免得把 ETA 算歪。
			job.Skipped++
		}
		job.LastNode = res.Host
		if job.Done > 0 {
			elapsed := time.Since(job.StartedAt)
			eta := elapsed * time.Duration(job.Total-job.Done) / time.Duration(job.Done)
			if eta < 0 {
				eta = 0
			}
			job.ETASeconds = int64(eta.Seconds())
		}
		if id := lookupID(index, res); id != "" {
			batch[id] = res
		}
		if onProgress != nil {
			onProgress(job.Done, job.OK, res.Host)
		}
		if len(batch) >= opt.BatchSize {
			flush()
			ticker.Reset(opt.BatchDelay)
			continue
		}
		select {
		case <-ticker.C:
			flush()
		default:
		}
	}
	flush()

	job.EndedAt = time.Now().UTC()
	switch {
	case ctx.Err() != nil:
		job.Status = "cancelled"
		job.Message = "被取消: " + ctx.Err().Error()
	default:
		job.Status = "done"
	}
	return job, ctx.Err()
}

// buildIndex 建「proto|host|port → 节点 ID」的索引。
//
// 同一个端点上挂着多个节点是常事（志愿者换 hostname 不换 IP:PORT），
// 这里保留第一个 ID，让它们共享同一份观测 —— 这是合理的，
// 因为我们测的就是那个端点。
func buildIndex(targets []Target) map[string]string {
	out := make(map[string]string, len(targets))
	for _, t := range targets {
		k := indexKey(t.Proto, t.Host, t.Port)
		if _, ok := out[k]; !ok {
			out[k] = t.ID
		}
	}
	return out
}

func indexKey(proto, host string, port int) string {
	return proto + "|" + host + "|" + itoa(port)
}

// lookupID 按观测结果反查节点 ID。ProbeResult 里不带 ID：它是探测器给出的
// 「客观观测」，不该混进本地身份。
func lookupID(index map[string]string, res *model.ProbeResult) string {
	if id, ok := index[indexKey(res.Proto, res.Host, res.Port)]; ok {
		return id
	}
	// 回退：探测过程中 host 被解析成了 IP（域名节点），而索引里存的是域名。
	// 这时按端口和协议找不到，就当作没找到 —— 不猜。
	return ""
}
