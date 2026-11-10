// Package app 把数据源、探测、纯净度和存储接在一起。
//
// 这里是唯一知道「全局流程」的地方：web 层只调用这些方法，CLI 也只调用这些
// 方法，两边行为不会漂。每一类任务（刷新/探测/纯净度）同时只允许一个实例，
// 否则手动点一下界面按钮就会和定时器打架，同一批节点被打两遍。
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/purity"
	"github.com/gebaolei/vpngate-agg/internal/source"
	"github.com/gebaolei/vpngate-agg/internal/store"
)

// App 是运行时核心。
type App struct {
	// cfgMu 护住 cfg：界面上改来源开关会整体换掉它，而探测/拉取线程一直在读。
	// 两边不加锁读会被竞态检测器抓出来，也会让一轮里前半段用新配置、后半段用旧的。
	cfgMu  sync.RWMutex
	cfg    config.Config
	store  *store.Store
	purity *purity.Service
	client *source.Client

	mirrors *source.MirrorStore
	bus     *Bus
	log     *log.Logger

	mu      sync.Mutex
	running map[string]context.CancelFunc
	// saveMu 串行化落盘，避免定时器、任务结束、退出三处同时写 pool.json。
	saveMu sync.Mutex
}

// New 装配依赖。数据目录会被创建；磁盘上已有的池子直接可用。
func New(cfg config.Config, logger *log.Logger) (*App, error) {
	if logger == nil {
		logger = log.Default()
	}
	st, err := store.New(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	client := source.NewClient(cfg.Sources.UserAgent)
	a := &App{
		cfg:     cfg,
		store:   st,
		purity:  purity.New(cfg.Purity, cfg.DataDir),
		client:  client,
		mirrors: source.NewMirrorStore(cfg.DataDir, client),
		bus:     NewBus(256),
		log:     logger,
		running: map[string]context.CancelFunc{},
	}
	// 缓存里的结论可能是旧汇总规则算的（例如新增的家宽推导）。purity.New 已经
	// 离线重算过一遍（不联网），这里把新结论同步回节点，并重算家宽 —— 节点上存的
	// 是结论副本，不同步就会继续顶着旧类型和旧家宽标记，最长顶满缓存 TTL。
	if n := a.purity.UpgradeCache(); n > 0 {
		a.log.Printf("[app] 纯净度缓存按新规则重算，%d 条结论有变化", a.SyncCachedPurity())
		if err := a.purity.Save(); err != nil {
			a.log.Printf("[app] 保存纯净度缓存失败: %v", err)
		}
	}
	return a, nil
}

// SyncCachedPurity 把缓存里的最新结论同步回节点，返回改了多少节点。
//
// 需要它是因为列表要直接显示类型和分，所以每个节点存了一份结论副本；缓存一改
// （规则升级、手工清缓存）就得显式刷一次，否则界面还是旧的。
func (a *App) SyncCachedPurity() int {
	var updated int
	seen := map[string]bool{}
	for _, n := range a.store.All() {
		if n.Purity == nil || seen[n.IP] {
			continue
		}
		seen[n.IP] = true
		cur := a.purity.Cached(n.IP)
		if cur == nil {
			continue
		}
		if cur.IPType == n.Purity.IPType && cur.TypeSource == n.Purity.TypeSource && cur.Score == n.Purity.Score {
			continue
		}
		a.store.ApplyPurity(cur)
		updated++
	}
	// 家宽是类型的推论，单独再对一遍（ApplyPurity 只换结论本身）。
	for _, n := range a.store.All() {
		if n.Purity == nil {
			continue
		}
		want := purity.IsCleanResidential(n.Purity)
		if n.Residential != nil && *n.Residential == want {
			continue
		}
		a.store.SetResidential(n.ID, want)
	}
	return updated
}

// Store 暴露节点池。
func (a *App) Store() *store.Store { return a.store }

// Purity 暴露纯净度服务（界面的来源健康状态要从这里取）。
func (a *App) Purity() *purity.Service { return a.purity }

// Config 返回当前配置的一份快照。任务一开始就该取一份快照用到底，
// 不要边跑边读：中途改了开关会让一轮里出现两套参数。
func (a *App) Config() config.Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg
}

// Bus 返回事件总线（SSE 订阅用）。
func (a *App) Bus() *Bus { return a.bus }

// busy 尝试占住某类任务；已经在跑就返回 false。
func (a *App) busy(kind string) (context.Context, func(), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.running[kind]; ok {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.running[kind] = cancel
	unlock := func() {
		a.mu.Lock()
		delete(a.running, kind)
		a.mu.Unlock()
		cancel()
	}
	return ctx, unlock, true
}

// Cancel 取消一类任务。返回是否真的有在跑的任务。
func (a *App) Cancel(kind string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cancel, ok := a.running[kind]
	if !ok {
		return false
	}
	cancel()
	return true
}

// Running 返回当前正在跑的任务种类。
func (a *App) Running() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.running))
	for k := range a.running {
		out = append(out, k)
	}
	return out
}

// Refresh 拉一轮节点列表并并进池子。
//
// 失败时不动池子：所有源都失败会返回错误，上一轮的数据继续可用。
// 这是必须的 —— 网络抖一下就把池子清空的话，界面上会变成「一个节点都没有」，
// 而且探测也没得测了。
func (a *App) Refresh(ctx context.Context) (*model.JobState, error) {
	ctx, done, ok := a.busy("refresh")
	if !ok {
		return nil, errors.New("已经有一轮刷新在跑")
	}
	defer done()

	job := &model.JobState{Kind: "refresh", Status: "running", StartedAt: time.Now().UTC(), Message: "正在拉取节点源"}
	a.store.SetJob("refresh", job)
	a.bus.Publish("refresh:start", map[string]any{"at": job.StartedAt})

	agg, err := source.Aggregate(ctx, a.Config().Sources, a.client, a.mirrors, a.store.PrevCounts())
	job.EndedAt = time.Now().UTC()
	if err != nil {
		job.Status = "failed"
		job.Message = err.Error()
		a.store.SetJob("refresh", job)
		a.mirrors.NoteFailure(time.Now())
		a.bus.Publish("refresh:done", map[string]any{"ok": false, "err": err.Error()})
		return job, err
	}

	diff := a.store.ApplyRefresh(agg, store.EvictionFrom(a.Config().Sources))
	// 过期淘汰只看「多久没见」，不看「池子多大」：官方主站 + 全部镜像一轮能给到
	// 几千个，而探测一轮、写盘、拉纯净度都随池子线性变贵。所以再按容量上限裁一次。
	trimmed := a.trimToCapacity()
	left := diff.Total - trimmed
	written, cerr := a.store.PutConfigs(agg.Configs)
	if cerr != nil {
		// 配置写盘失败不能算整轮失败：节点元数据已经进池子了，
		// 缺正文的节点在下载时会再拉一次。
		a.log.Printf("[app] 写配置正文失败（下一轮会重试）: %v", cerr)
		agg.Warnings = append(agg.Warnings, "配置正文写盘失败: "+cerr.Error())
	}
	job.Status = "done"
	job.Total = len(agg.Nodes)
	job.Done = len(agg.Nodes)
	job.OK = diff.Added
	job.Skipped = diff.Removed() + trimmed
	// 消失数分开写：过期是上游轮换，淘汰是把连续失败的 TCP 节点请出去，
	// 自营剔除是用户不想要官方机房出口（开关 keep_vpngate_own），容量裁掉是
	// 池子超出 max_nodes。
	job.Message = fmt.Sprintf("节点 %d（新增 %d，过期清除 %d，缺席淘汰 %d，自营机房剔除 %d，容量裁掉 %d），配置正文新增 %d",
		left, diff.Added, diff.Expired, diff.Purged, diff.DroppedOwn, trimmed, written)

	// 家宽/自营判定不联网，顺手就做，让界面立刻有「residential」这一列。
	if n := a.RefreshResidential(); n > 0 {
		job.Message += fmt.Sprintf("，自营/机房判定 %d", n)
	}
	a.store.SetJob("refresh", job)
	if err := a.SaveState(); err != nil {
		a.log.Printf("[app] 保存节点池失败: %v", err)
		job.Message += "；保存失败: " + err.Error()
	}
	a.bus.Publish("refresh:done", map[string]any{
		"ok": true, "nodes": left, "added": diff.Added,
		"expired": diff.Expired, "purged": diff.Purged, "dropped_own": diff.DroppedOwn,
		"trimmed": trimmed, "max_nodes": a.Config().Sources.MaxNodes,
		"stats": a.store.Stats(), "warnings": agg.Warnings,
	})
	a.log.Printf("[app] 刷新完成: %s", job.Message)
	return job, nil
}

// RefreshResidential 用不联网的内置规则标注「自营机房」，
// 已经有纯净度结论的节点则用纯净度判「家宽」。返回改动数。
func (a *App) RefreshResidential() int {
	var changed int
	for _, n := range a.store.All() {
		if n.Residential != nil && n.Purity == nil {
			// 已经判过、且没有新的纯净度证据支持改判 —— 不重复动。
			continue
		}
		if n.Purity != nil {
			a.store.SetResidential(n.ID, purity.IsCleanResidential(n.Purity))
			changed++
			continue
		}
		if hosting, why := purity.BuiltinHosting(n.IP, n.HostName); hosting {
			f := false
			a.store.SetResidential(n.ID, f)
			_ = why
			changed++
		}
	}
	return changed
}

// trimToCapacity 按当前配置的容量上限裁一次，返回裁掉的数量。
//
// 每轮刷新之后、启动加载之后、以及界面上改上限之后都走这里：三处必须是同一套
// 规则，否则会出现「改了数字但池子没变」这种看起来没生效的状态。
func (a *App) trimToCapacity() int {
	return a.trimTo(store.EvictionFrom(a.Config().Sources))
}

// trimTo 是同一件事，但参数已经拿在手上。PatchConfig 走这条：它持着 cfgMu，
// 再回头调 Config() 会自己等自己。而且那里要用的是刚算出来的新配置。
func (a *App) trimTo(ev store.Eviction) int {
	d := a.store.Trim(ev)
	if d.Trimmed > 0 {
		a.bus.Publish("pool:trim", map[string]any{
			"trimmed": d.Trimmed, "total": d.Total, "max_nodes": ev.MaxNodes,
		})
	}
	return d.Trimmed
}

// EnsureConfig 保证某个节点的 .ovpn 正文在本地，返回正文。已经本地有了就不发请求。
//
// 第三方累积池节点的正文以前是「按需从 CDN 取」的；那个源删掉后，缺正文只剩下
// 一条补救路：重拉一轮官方全量（正文就在 CSV 里）。重拉还没有就是这个节点已经不
// 在官方名单里了，直接报错，别给界面一份空文件。
func (a *App) EnsureConfig(ctx context.Context, id string) ([]byte, error) {
	n, ok := a.store.Get(id)
	if !ok {
		return nil, errors.New("节点不存在")
	}
	if n.ConfigSHA256 == "" {
		return nil, errors.New("这个节点没有配置摘要")
	}
	if cfg, ok := a.store.Config(n.ConfigSHA256); ok {
		return cfg, nil
	}
	// 正文不在盘上（自己删过 data 目录、或者节点是第三方源时代的遗留）：
	// 重拉一轮官方名单是最省事的补救，代价是一轮抓取。
	if _, err := a.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("本地正文缺失且重拉失败: %w", err)
	}
	if cfg, ok := a.store.Config(n.ConfigSHA256); ok {
		a.store.MarkConfigLocal(id)
		return cfg, nil
	}
	return nil, errors.New("重拉之后仍然没有这份配置正文（节点多半已不在官方名单里）")
}

// SaveState 把节点池和纯净度缓存落盘。串行为主，代价小、避免互相踩。
func (a *App) SaveState() error {
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	var errs []string
	if err := a.store.Save(); err != nil {
		errs = append(errs, "节点池: "+err.Error())
	}
	if err := a.purity.Save(); err != nil {
		errs = append(errs, "纯净度缓存: "+err.Error())
	}
	if len(errs) > 0 {
		return errors.New(joinSemi(errs))
	}
	return nil
}

func joinSemi(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += "; "
		}
		out += x
	}
	return out
}

// HTTPClient 给 web 层留的口子（下载配置之类要走网络时用）。
// 现在没用到，保留是为了以后加「按需代理」时不用再翻 app 的接口。
func (a *App) HTTPClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }
