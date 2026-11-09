package app

import (
	"encoding/json"
	"sync"
	"time"
)

// Event 是一条推送给界面的事件。
type Event struct {
	Type string    `json:"type"`
	Data any       `json:"data,omitempty"`
	At   time.Time `json:"at"`
}

// Bus 是一个极简的发布订阅。
//
// 关键取舍：发布方永不阻塞。探测线程每秒可能产生几十条进度事件，
// 而 SSE 客户端可能因为网络慢、标签页切到后台等原因不读 socket。
// 队列满就直接丢最旧的一条 —— 进度事件本来就是可丢的，
// 客户端会在下一次 done/stats 事件里拿到全量状态。
type Bus struct {
	mu     sync.Mutex
	subs   map[chan Event]bool
	size   int
	drops  int64
	latest []Event // 最近 N 条，给新连上的客户端补历史
}

// NewBus 造一个总线，history 是保留的最近事件条数。
func NewBus(queueSize int) *Bus {
	if queueSize <= 0 {
		queueSize = 128
	}
	return &Bus{subs: map[chan Event]bool{}, size: queueSize, latest: make([]Event, 0, 32)}
}

// Publish 投递事件，不阻塞。
func (b *Bus) Publish(kind string, data any) {
	e := Event{Type: kind, Data: data, At: time.Now().UTC()}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.latest = append(b.latest, e)
	if len(b.latest) > 32 {
		b.latest = b.latest[len(b.latest)-32:]
	}
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			// 满了：丢最旧的一条再塞，保证客户端看到的是最新进展。
			select {
			case <-ch:
				b.drops++
			default:
			}
			select {
			case ch <- e:
			default:
			}
		}
	}
}

// Subscribe 注册一个订阅者，返回事件通道和取消函数。
// 取消函数必须调用，否则 SSE 连接断开后会泄漏一个 goroutine 和通道。
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, b.size)
	b.mu.Lock()
	// 先补最近的事件：客户端刷新页面后不该看不到正在跑的任务进度。
	latest := append([]Event(nil), b.latest...)
	b.subs[ch] = true
	b.mu.Unlock()
	for _, e := range latest {
		select {
		case ch <- e:
		default:
		}
	}
	return ch, func() {
		b.mu.Lock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
}

// Drops 返回累计丢弃的事件数（排障用：一直涨说明有客户端读得太慢）。
func (b *Bus) Drops() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.drops
}

// EncodeEvent 把事件编成 SSE 的一行。单独放这里是为了 web 层只关心 HTTP。
func EncodeEvent(e Event) ([]byte, error) {
	blob, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append([]byte("data: "), append(blob, '\n', '\n')...), nil
}
