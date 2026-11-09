package app

import (
	"errors"
	"fmt"

	"github.com/gebaolei/vpngate-agg/internal/config"
)

// ConfigPatch 是界面上允许改的那几项开关和运行参数（POST /api/settings）。
//
// 字段全用指针：要区分「这次请求没提这一项」和「明确要修改/改成 false」。
type ConfigPatch struct {
	// ---- 节点配置 ----
	// 官方主站不在这里：它是必开的来源，界面和接口都不给关掉。真要关（比如部署在
	// 根本连不上 www.vpngate.net 的网络里，不想每轮白等一次超时）只能改配置文件。
	MirrorsEnabled  *bool `json:"mirrors_enabled,omitempty"`
	CDNEnabled      *bool `json:"cdn_enabled,omitempty"`
	CDNPoolEnabled  *bool `json:"cdn_pool_enabled,omitempty"`
	KeepVpngateOwn  *bool `json:"keep_vpngate_own,omitempty"`
	MirrorsMax      *int  `json:"mirrors_max,omitempty"`
	KeepDays        *int  `json:"keep_days,omitempty"`
	PurgeFailRounds *int  `json:"purge_fail_rounds,omitempty"`

	// ---- 可用性探查 ----
	ProbeEnabled           *bool `json:"probe_enabled,omitempty"`
	ProbeHandshake         *bool `json:"probe_handshake,omitempty"`
	ProbeIntervalMinutes   *int  `json:"probe_interval_minutes,omitempty"`
	ProbeConcurrency       *int  `json:"probe_concurrency,omitempty"`
	ProbeTCPTimeoutSeconds *int  `json:"probe_tcp_timeout_seconds,omitempty"`
	ProbeUDPTimeoutSeconds *int  `json:"probe_udp_timeout_seconds,omitempty"`

	// ---- IP 纯净度检查 ----
	PurityEnabled           *bool `json:"purity_enabled,omitempty"`
	PurityRequestsPerMinute *int  `json:"purity_requests_per_minute,omitempty"`
	PurityRPM               *int  `json:"purity_rpm,omitempty"`
}

// PatchConfig 应用开关、校验、写回配置文件，然后换上新的内存配置。
//
// 顺序是「先算出完整的新配置 → 校验 → 落盘 → 才换内存里的那份」：校验或写盘失败
// 就整个不做，不会出现界面上显示已改、磁盘上却还是旧的这种两头不一致。
func (a *App) PatchConfig(p ConfigPatch) (config.Config, error) {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()

	next := a.cfg

	// 1. 节点配置
	if p.MirrorsEnabled != nil {
		next.Sources.Mirrors.Enabled = *p.MirrorsEnabled
	}
	if p.CDNEnabled != nil {
		next.Sources.CDN.Enabled = *p.CDNEnabled
	}
	if p.CDNPoolEnabled != nil {
		next.Sources.CDN.UsePool = *p.CDNPoolEnabled
	}
	if p.KeepVpngateOwn != nil {
		next.Sources.KeepVpngateOwn = *p.KeepVpngateOwn
	}
	if p.MirrorsMax != nil {
		next.Sources.Mirrors.MaxMirrors = *p.MirrorsMax
	}
	if p.KeepDays != nil {
		if *p.KeepDays < 1 || *p.KeepDays > 90 {
			return a.cfg, fmt.Errorf("最长缺席天数范围为 1 ~ 90 天，给的是 %d", *p.KeepDays)
		}
		next.Sources.KeepDays = *p.KeepDays
	}
	if p.PurgeFailRounds != nil {
		if *p.PurgeFailRounds < 1 || *p.PurgeFailRounds > 12 {
			return a.cfg, fmt.Errorf("最大失败次数范围为 1 ~ 12 轮，给的是 %d", *p.PurgeFailRounds)
		}
		next.Sources.PurgeFailRounds = *p.PurgeFailRounds
	}

	// 2. 可用性探查
	if p.ProbeEnabled != nil {
		next.Probe.Enabled = *p.ProbeEnabled
	}
	if p.ProbeHandshake != nil {
		next.Probe.Handshake = *p.ProbeHandshake
	}
	if p.ProbeIntervalMinutes != nil {
		if *p.ProbeIntervalMinutes < 5 || *p.ProbeIntervalMinutes > 1440 {
			return a.cfg, fmt.Errorf("探测间隔范围为 5 ~ 1440 分钟，给的是 %d", *p.ProbeIntervalMinutes)
		}
		next.Probe.IntervalMinutes = *p.ProbeIntervalMinutes
	}
	if p.ProbeConcurrency != nil {
		if *p.ProbeConcurrency < 1 || *p.ProbeConcurrency > 512 {
			return a.cfg, fmt.Errorf("探测并发范围为 1 ~ 512，给的是 %d", *p.ProbeConcurrency)
		}
		next.Probe.Concurrency = *p.ProbeConcurrency
	}
	if p.ProbeTCPTimeoutSeconds != nil {
		if *p.ProbeTCPTimeoutSeconds < 1 || *p.ProbeTCPTimeoutSeconds > 30 {
			return a.cfg, fmt.Errorf("TCP 超时范围为 1 ~ 30 秒，给的是 %d", *p.ProbeTCPTimeoutSeconds)
		}
		next.Probe.TCPTimeoutSeconds = *p.ProbeTCPTimeoutSeconds
	}
	if p.ProbeUDPTimeoutSeconds != nil {
		if *p.ProbeUDPTimeoutSeconds < 1 || *p.ProbeUDPTimeoutSeconds > 30 {
			return a.cfg, fmt.Errorf("UDP 超时范围为 1 ~ 30 秒，给的是 %d", *p.ProbeUDPTimeoutSeconds)
		}
		next.Probe.UDPTimeoutSeconds = *p.ProbeUDPTimeoutSeconds
	}

	// 3. IP 纯净度检查
	if p.PurityEnabled != nil {
		next.Purity.Enabled = *p.PurityEnabled
	}
	rpm := p.PurityRequestsPerMinute
	if rpm == nil {
		rpm = p.PurityRPM
	}
	if rpm != nil {
		if *rpm < 1 || *rpm > 600 {
			return a.cfg, fmt.Errorf("纯净度每分钟限流范围为 1 ~ 600 次，给的是 %d", *rpm)
		}
		next.Purity.RequestsPerMinute = *rpm
	}

	// 三个来源一个都不剩就是脚枪。界面上只给两个开关，所以这条现在只在
	// 「配置文件里把主站也关了」时才会碰到。
	if !next.Sources.Vpngate.Enabled && !next.Sources.Mirrors.Enabled && !next.Sources.CDN.Enabled {
		return a.cfg, errors.New("三个来源不能全关掉：那样池子里只剩历史数据，再也拉不到新节点")
	}
	if err := next.Validate(); err != nil {
		return a.cfg, fmt.Errorf("参数不合法: %w", err)
	}
	if err := next.Save(); err != nil {
		return a.cfg, fmt.Errorf("写配置文件失败: %w", err)
	}
	a.cfg = next

	// 纯净度限流变动即时生效
	if rpm != nil && a.purity != nil {
		a.purity.UpdateRPM(next.Purity.RequestsPerMinute)
	}

	return next, nil
}

// setCfg 给测试用：改一份配置并顺手过校验。生产路径一律走 PatchConfig
// （它还要落盘，测试里不该往临时目录写文件）。
func (a *App) setCfg(fn func(*config.Config)) {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	next := a.cfg
	fn(&next)
	_ = next.Validate()
	a.cfg = next
}
