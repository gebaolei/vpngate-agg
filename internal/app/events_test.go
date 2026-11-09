package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBusDeliversToEverySubscriber(t *testing.T) {
	b := NewBus(8)
	ch1, cancel1 := b.Subscribe()
	ch2, cancel2 := b.Subscribe()
	defer cancel1()
	defer cancel2()

	b.Publish("probe:progress", map[string]any{"done": 1})

	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case e := <-ch:
			if e.Type != "probe:progress" {
				t.Errorf("订阅者 %d 收到 %q", i, e.Type)
			}
			if e.At.IsZero() {
				t.Errorf("事件没时间戳")
			}
		case <-time.After(time.Second):
			t.Errorf("订阅者 %d 没收到事件", i)
		}
	}
	if got := len(ch1); got != len(ch2) {
		t.Errorf("两个订阅者的队列长度不一样: %d vs %d", got, len(ch2))
	}
}

// 刷新页面的客户端不该看不到正在跑的任务进度：订阅时先补最近的事件。
func TestBusReplaysRecentEvents(t *testing.T) {
	// 队列开得比历史上限（32）大，否则补发的时候本身就会溢出。
	b := NewBus(64)
	for i := 0; i < 40; i++ {
		b.Publish("probe:progress", map[string]any{"done": i})
	}
	ch, cancel := b.Subscribe()
	defer cancel()

	var got []Event
	for {
		select {
		case e := <-ch:
			got = append(got, e)
		default:
			goto done
		}
	}
done:
	if len(got) != 32 {
		t.Fatalf("补发了 %d 条，期望最近 32 条", len(got))
	}
	// 补发的必须是最新那 32 条而不是最早的：
	// 用户刷新后要看的是「现在到哪了」，不是这一轮从头重放。
	if first := got[0].Data.(map[string]any)["done"].(int); first != 8 {
		t.Errorf("补发批的第一条 = %v，期望 done=8（更早的 0-7 该被挤掉）", first)
	}
	if last := got[len(got)-1].Data.(map[string]any)["done"].(int); last != 39 {
		t.Errorf("补发批的最后一条 = %v，期望 done=39", last)
	}
}

// 发布方绝不能阻塞：SSE 客户端读得慢（标签页切后台、网络差）时，
// 探测线程不该被拖住。
func TestBusPublishNeverBlocks(t *testing.T) {
	b := NewBus(2)
	ch, cancel := b.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			b.Publish("probe:progress", i)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("没人读队列，Publish 被卡住了")
	}

	// 队列里剩下的应该是最靠后的一批，而不是最早的。
	var last any
	for {
		select {
		case e := <-ch:
			last = e.Data
		default:
			goto out
		}
	}
out:
	if last.(int) != 199 {
		t.Errorf("慢消费者最后看到的是 %v，期望最新一条 199（丢旧不丢新）", last)
	}
	if b.Drops() == 0 {
		t.Error("溢出却没记丢弃数，排障时就看不出有客户端读得太慢")
	}
}

func TestBusUnsubscribe(t *testing.T) {
	b := NewBus(4)
	ch, cancel := b.Subscribe()
	b.Publish("a", 1)
	cancel()
	// 取消前已经进队列的事件仍要能读到，读完之后通道必须是关掉的
	// （SSE 处理线程靠这个关闭信号退出，否则泄漏一个 goroutine）。
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				goto closed
			}
		case <-time.After(time.Second):
			t.Fatal("取消后通道没关")
		}
	}
closed:
	// 取消两次不能 panic，取消后发布也不能碰到已关的通道。
	cancel()
	b.Publish("b", 2)
	// 剩下的订阅者（如果有）还得能继续收。
	if _, cancelOther := b.Subscribe(); cancelOther != nil {
		cancelOther()
	}
}

func TestNewBusDefaultQueue(t *testing.T) {
	// 队列大小传 0/负数时要回落到默认值：调度器传错数不该导致每条事件都丢。
	for _, size := range []int{0, -5} {
		b := NewBus(size)
		ch, cancel := b.Subscribe()
		b.Publish("x", 1)
		select {
		case <-ch:
		default:
			t.Errorf("queueSize=%d 时事件没进队列", size)
		}
		cancel()
	}
}

func TestEncodeEventSSEShape(t *testing.T) {
	// SSE 的格式是 data: <json>\n\n；前端按行拆，多一个前缀就解不出来。
	line, err := EncodeEvent(Event{Type: "refresh:done", Data: map[string]any{"ok": true}, At: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	s := string(line)
	if !strings.HasPrefix(s, "data: ") || !strings.HasSuffix(s, "}\n\n") {
		t.Errorf("SSE 行格式不对: %q", s)
	}
	var got Event
	if err := json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(s, "data: "), "\n\n")), &got); err != nil {
		t.Fatalf("解不出来: %v (%s)", err, s)
	}
	if got.Type != "refresh:done" || got.At.IsZero() {
		t.Errorf("解出的事件 = %+v", got)
	}
	if m, ok := got.Data.(map[string]any); !ok || m["ok"] != true {
		t.Errorf("data 丢了: %+v", got.Data)
	}

	// 没有 data 的事件（比如纯心跳）不该带个 null 字段。
	bare, err := EncodeEvent(Event{Type: "ping", At: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bare), `"data"`) {
		t.Errorf("空 data 也被编码了: %s", bare)
	}

	// data 里有 chan 这类编不出来的值时要报错，不能 panic：
	// 一个事件的编码问题不该把整条 SSE 连接带崩。
	if _, err := EncodeEvent(Event{Type: "bad", Data: make(chan int)}); err == nil {
		t.Error("编不出来的 data 应报错")
	}
}
