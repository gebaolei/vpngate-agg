package source

import "testing"

// 并发闸要跟着本轮源数量走：源比并发多就会分波次，最坏耗时翻倍 —— 官方主站被墙、
// 要靠镜像补位的时候，这个慢是用户能感觉到的。但也不能没上限地刷官方镜像站，
// 那几个是志愿者给的缓存页。
func TestSourceWorkersScalesWithSources(t *testing.T) {
	for slots, want := range map[int]int{-1: 1, 0: 1, 1: 1, 3: 3, 6: 6, 9: 6} {
		if got := sourceWorkers(slots); got != want {
			t.Errorf("sourceWorkers(%d) = %d，期望 %d", slots, got, want)
		}
	}
}
