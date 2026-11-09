package purity

import (
	"testing"

	"github.com/gebaolei/vpngate-agg/internal/config"
)

// 界面上改「限流次数（每分钟）」必须当场生效：令牌桶是按速率建出来的，
// 不重建桶就会继续按老速率放行，界面上改了等于没改。
func TestUpdateRPMAppliesToBuckets(t *testing.T) {
	svc := New(config.PurityConfig{
		Enabled:           true,
		TTLHours:          24,
		RequestsPerMinute: 40,
		Providers:         map[string]bool{"ipquery": true},
	}, t.TempDir())

	if got := svc.rateFor("ipquery"); got != 40/60.0 {
		t.Fatalf("起始速率 = %v，期望 40/分", got)
	}
	svc.UpdateRPM(120)
	if got := svc.rateFor("ipquery"); got != 2.0 {
		t.Errorf("改限流后速率 = %v，期望 2（120 次/分）", got)
	}

	old := svc.bucketFor("ipquery")
	if old == nil {
		t.Fatal("没建出令牌桶")
	}
	svc.UpdateRPM(20)
	if svc.bucketFor("ipquery") == old {
		t.Error("改限流后没有重建令牌桶，还会按老速率跑")
	}

	// 填 0 / 负数回到默认，而不是把速率压成 0 —— 那等于整轮纯净度扫描卡死。
	svc.UpdateRPM(0)
	if got := svc.rateFor("ipquery"); got != 40/60.0 {
		t.Errorf("填 0 之后速率 = %v，期望回到默认 40/分", got)
	}

	// 带 key 的来源放宽 3 倍这条规则不能被 UpdateRPM 弄丢。
	svc.stats["ipquery"].HasKey = true
	svc.UpdateRPM(30)
	if got := svc.rateFor("ipquery"); got != 90/60.0 {
		t.Errorf("带 key 的速率 = %v，期望 1.5（30×3 次/分）", got)
	}
}
