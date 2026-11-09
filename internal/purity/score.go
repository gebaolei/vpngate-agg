package purity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// MergeOptions 是汇总时可调的少量参数。
type MergeOptions struct {
	// MinProviders: 有效来源数不足时不把结论标成可信（界面显示「证据不足」）。
	MinProviders int
	// RawKeepBytes: 每个来源保留多少原始响应字节给界面核对。
	RawKeepBytes int
	// TargetWeight: 认为「证据充分」需要的权重和。2.2 ≈ 一个免费源 + 一个带 key 的专业源。
	TargetWeight float64
}

func (o MergeOptions) withDefaults() MergeOptions {
	if o.MinProviders <= 0 {
		o.MinProviders = 1
	}
	if o.RawKeepBytes < 0 {
		o.RawKeepBytes = 0
	} else if o.RawKeepBytes == 0 {
		o.RawKeepBytes = 900
	}
	if o.TargetWeight <= 0 {
		o.TargetWeight = 2.2
	}
	return o
}

// Merge 把所有来源的 Signals 汇总成一个可展示的结论。
//
// 汇总规则（全部写在这里，界面上的「为什么」就靠它）：
//  1. 风险因子按权重投票，任何一个专业源明确说是就算「是」——
//     把机房误判成家宽，代价是用户连上之后被目标站风控，比反过来严重。
//  2. 风险分是各来源原生分数的加权平均；来源自己没给分的，已由
//     riskFromFactors 按因子换算，不在这里重复打分。
//  3. 再对风险分设下限（floor）：Tor/机房/匿名出口即使各家分数都不高，
//     也不可能是「纯净」。
//  4. 证据不足时把分数往中性值（62）收，而不是给一个好看的 100 或难看的 5。
func Merge(q Query, sigs []*Signals, opt MergeOptions) *model.PurityResult {
	opt = opt.withDefaults()
	res := &model.PurityResult{
		IP:        q.IP,
		IPType:    model.TypeUnknown,
		TypeLabel: model.TypeLabels[model.TypeUnknown],
		Providers: []model.ProviderVerdict{},
		Reasons:   []string{},
		CheckedAt: nowUTC(),
		TTLHours:  0,
	}
	if len(sigs) == 0 {
		res.Score = 55
		res.Level = model.LevelOfScore(res.Score)
		res.Reasons = append(res.Reasons, "没有任何可用来源，结论是中性值")
		return res
	}

	var valid []*Signals
	for _, s := range sigs {
		if s == nil {
			continue
		}
		v := model.ProviderVerdict{
			Name: s.Name, OK: s.OK, Err: s.Err, MS: s.MS, Score: s.Score, ScoreName: s.ScoreName,
			Factors: s.Factors, Type: s.Type, ASN: s.ASN, Org: s.Org, ISP: s.ISP,
			Domain: s.Domain, Usage: s.Usage, Country: s.Country, Privates: s.Tags,
			Raw: truncRaw(s.Raw, opt.RawKeepBytes),
		}
		res.Providers = append(res.Providers, v)
		if s.OK {
			valid = append(valid, s)
		}
	}
	if len(valid) == 0 {
		res.Score = 55
		res.Level = model.LevelOfScore(res.Score)
		res.Reasons = append(res.Reasons, fmt.Sprintf("全部 %d 个来源都失败了，见各来源错误", len(sigs)))
		return res
	}

	// ---- 1. 因子投票 ----
	factorRiskFloor := 0
	fac := model.PurityFactors{}
	voteLog := map[string]string{}
	for _, spec := range factorSpecs {
		var yes, no float64
		for _, s := range valid {
			w := s.Weight
			if w <= 0 {
				w = Weight(s.Name)
			}
			v := boolOf(&s.Factors, spec.Key)
			if v == nil {
				continue
			}
			if *v {
				yes += w
			} else {
				no += w
			}
		}
		if yes == 0 && no == 0 {
			continue // 没人表态，保持 nil，别让汇总编造结论
		}
		// 一个专业源明确说是就算说是（见函数顶部注释第 1 条）。
		positive := yes >= 1.0 && yes > no*0.35
		out := positive
		spec.set(&fac, &out)
		if positive {
			voteLog[spec.Key] = yesNames(valid, spec.Key)
			if f := spec.riskFloor; f > factorRiskFloor {
				factorRiskFloor = f
			}
		}
	}

	// AbuseIPDB 的 abuseConfidenceScore 单独带出来，它不是布尔因子。
	for _, s := range valid {
		if s.Factors.AbuseScore != nil {
			cur := 0
			if fac.AbuseScore != nil {
				cur = *fac.AbuseScore
			}
			if *s.Factors.AbuseScore > cur {
				v := *s.Factors.AbuseScore
				fac.AbuseScore = &v
			}
		}
	}
	res.Factors = fac

	// ---- 2. 加权平均风险分 ----
	var wsum, acc float64
	for _, s := range valid {
		if s.Score == nil {
			continue
		}
		w := s.Weight
		if w <= 0 {
			w = Weight(s.Name)
		}
		acc += float64(*s.Score) * w
		wsum += w
	}
	var risk float64
	if wsum > 0 {
		risk = acc / wsum
		for _, s := range valid {
			if s.Score != nil {
				res.Reasons = append(res.Reasons, fmt.Sprintf("%s 给的风险分 %d（%s，权重 %.2f）",
					s.Name, *s.Score, firstNonEmpty(s.ScoreName, "score"), weightOf(s)))
			}
		}
	} else {
		// 谁都没给数值分：用投票结果换算一次。
		risk = float64(riskFromFactors(fac, true))
		if risk > 0 {
			res.Reasons = append(res.Reasons, "各来源都没给数值分，风险分由投票后的因子换算")
		}
	}

	// ---- 3. 因子下限 ----
	if factorRiskFloor > 0 && risk < float64(factorRiskFloor) {
		res.Reasons = append(res.Reasons, fmt.Sprintf("风险分下限被抬到 %d（%s）", factorRiskFloor, strings.Join(reasonList(voteLog), "、")))
		risk = float64(factorRiskFloor)
	}

	// ---- 4. 组织名关键词证据（机房名常常只出现在 org 里） ----
	var orgTexts []string
	for _, s := range valid {
		orgTexts = append(orgTexts, s.Org, s.ISP, s.Domain)
	}
	hostingHit, residentialHit := OrgKeywordSignals(orgTexts...)
	if hostingHit != "" && !orTrue(fac.Datacenter) {
		res.Reasons = append(res.Reasons, "内置规则：来源给出的运营商/组织名里含机房关键词「"+hostingHit+"」")
		t := true
		fac.Datacenter = &t
		res.Factors = fac
		if risk < 62 {
			risk = 62
		}
	}
	if residentialHit != "" && !orTrue(fac.Datacenter) && !orTrue(fac.VPN) && !orTrue(fac.Proxy) && !orTrue(fac.Tor) {
		res.Reasons = append(res.Reasons, "内置规则：运营商/组织名符合家宽或科研教育特征「"+residentialHit+"」，风险轻微下调")
		risk -= 8
	}
	if fac.AbuseScore != nil && *fac.AbuseScore >= 50 && risk < 55 {
		risk = 55
		res.Reasons = append(res.Reasons, fmt.Sprintf("滥用置信分 %d 偏高，风险分下限抬到 55", *fac.AbuseScore))
	}

	// ---- 5. 类型判定（优先级从上到下） ----
	res.IPType, res.TypeSource = decideType(q, valid, fac, hostingHit)
	derivedWeak := false
	if res.IPType == model.TypeUnknown {
		// 来源都没给类型时才轮到推导：官方名单没有家宽标识、免费来源也不给类型，
		// 不推导就永远是「未知」，家宽占比会显示成 0%（那不是结论，是没数据）。
		// 推导只填类型、不动风险分，依据写进 TypeSource 让界面分开显示。
		if basis := deriveResidential(q, valid, fac); basis != "" {
			res.IPType = model.TypeResidential
			res.TypeSource = basis
			res.Reasons = append(res.Reasons, residentialBasisText(basis))
			derivedWeak = strings.HasPrefix(basis, "derived:isp:")
		}
	}
	res.TypeLabel = labelFor(res.IPType)
	if res.IPType == model.TypeVpngateOwn && risk < 82 {
		risk = 82
		res.Reasons = append(res.Reasons, "VPN Gate 自营机房：SoftEther 官方服务器出口，按机房处理")
	}

	// ---- 6. 置信度与最终分 ----
	var evidence float64
	for _, s := range valid {
		// builtin 的弃权票不增加证据量：它自己标了 no-internal-rule。
		if hasTag(s, "no-internal-rule") {
			continue
		}
		evidence += weightOf(s)
	}
	conf := int(100 * evidence / opt.TargetWeight)
	if conf > 100 {
		conf = 100
	}
	if len(valid) < opt.MinProviders {
		conf = conf * len(valid) / opt.MinProviders
	}
	if derivedWeak {
		// 只有运营商名线索（没有 ASN 命中）：政企专线和家宽用同一个品牌名，
		// 置信度扣一档，界面上也标成「推导」。
		if conf > 12 {
			conf -= 12
		}
		res.Reasons = append(res.Reasons, "类型是推导出来的（只有运营商名线索），置信度扣 12")
	}
	res.Confidence = conf

	if risk < 0 {
		risk = 0
	}
	if risk > 100 {
		risk = 100
	}
	score := 100 - int(risk+0.5)
	// 证据不足就往中性值 62 收。62 是「看着能用、又不至于被当成已经验证过」的位置。
	if conf < 100 {
		f := float64(conf) / 100
		score = int(float64(score)*f + 62*(1-f) + 0.5)
	}
	if conf < 100 {
		res.Reasons = append(res.Reasons, fmt.Sprintf("证据权重 %.2f/%.2f，分数向中性值 62 收敛（可信度 %d%%）", evidence, opt.TargetWeight, conf))
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	res.Score = score
	res.Level = model.LevelOfScore(score)

	// 汇总里最靠得住的元数据：ASN/组织取权重最高、给得最全的那一条。
	pickMetadata(res, valid)
	// 来源排序：成功的在前，同权重按名字，界面显示稳定。
	sort.SliceStable(res.Providers, func(i, j int) bool {
		if res.Providers[i].OK != res.Providers[j].OK {
			return res.Providers[i].OK
		}
		return res.Providers[i].Name < res.Providers[j].Name
	})
	return res
}

// factorSpec 描述一个因子的投票规则与风险下限。
type factorSpec struct {
	Key       string
	riskFloor int // 该因子成立时风险至少多少
	set       func(dst *model.PurityFactors, v *bool)
}

var factorSpecs = []factorSpec{
	{Key: "tor", riskFloor: 88, set: func(d *model.PurityFactors, v *bool) { d.Tor = v }},
	{Key: "datacenter", riskFloor: 72, set: func(d *model.PurityFactors, v *bool) { d.Datacenter = v }},
	{Key: "vpn", riskFloor: 66, set: func(d *model.PurityFactors, v *bool) { d.VPN = v }},
	{Key: "proxy", riskFloor: 62, set: func(d *model.PurityFactors, v *bool) { d.Proxy = v }},
	{Key: "abuser", riskFloor: 45, set: func(d *model.PurityFactors, v *bool) { d.Abuser = v }},
	{Key: "bot", riskFloor: 30, set: func(d *model.PurityFactors, v *bool) { d.Bot = v }},
	{Key: "mobile", riskFloor: 0, set: func(d *model.PurityFactors, v *bool) { d.Mobile = v }},
}

// decideType 决定最终 IP 类型。
//
// 优先级是有理由的：Tor > 匿名出口 > 机房 > 移动 > 科研教育/政府/企业 > 家宽。
// 一个 IP 可以同时被标成机房和 VPN（云上跑 VPN 出口就是这样），
// 这时对用户最有用的信息是「它是匿名出口」，因为那才是会被风控的原因。
// decideType 决定类型，第二个返回值是「谁给的结论」（写进 TypeSource 给界面看）：
// 来源名（ipinfo）、factor-vote（因子投票）、builtin:own / builtin:org-keyword，
// 未知则空。家宽推导不在这里做 —— 它只在返回 unknown 之后才允许，见 Merge。
func decideType(q Query, valid []*Signals, fac model.PurityFactors, hostingHit string) (string, string) {
	for _, s := range valid {
		if s.Type == model.TypeVpngateOwn {
			return model.TypeVpngateOwn, "builtin:own"
		}
	}
	switch {
	case orTrue(fac.Tor):
		return model.TypeTor, "factor-vote"
	case orTrue(fac.VPN), orTrue(fac.Proxy):
		return model.TypeVPNProxy, "factor-vote"
	case orTrue(fac.Datacenter):
		return model.TypeHosting, "factor-vote"
	}
	// 类型字段按权重投票，取权重最高的非空类型。
	type tv struct {
		w    float64
		t    string
		from string
	}
	var best *tv
	for _, s := range valid {
		if s.Type == "" || s.Type == model.TypeVpngateOwn {
			continue
		}
		w := weightOf(s)
		if best == nil || w > best.w {
			v := tv{w: w, t: s.Type, from: s.Name}
			best = &v
		}
	}
	if best != nil && best.t != model.TypeUnknown {
		return best.t, best.from
	}
	if orTrue(fac.Mobile) {
		return model.TypeMobile, "factor-vote"
	}
	if hostingHit != "" {
		return model.TypeHosting, "builtin:org-keyword"
	}
	if t := typeFromWords(joinForType(allUsage(valid))); t != "" {
		return t, "usage-text"
	}
	return model.TypeUnknown, ""
}

// joinForType 把多个候选类型/用途串拼成一条给关键词表扫。
func joinForType(xs []string) string { return strings.Join(xs, " | ") }

func allUsage(valid []*Signals) []string {
	var out []string
	for _, s := range valid {
		out = append(out, s.Usage, s.Type)
	}
	return out
}

// pickMetadata 从各来源里挑一份最可信的 ASN/组织/国家信息。
func pickMetadata(res *model.PurityResult, valid []*Signals) {
	type cand struct {
		w float64
		s *Signals
	}
	var best *cand
	for _, s := range valid {
		// 权重优先：专业风险源给的 ASN/组织比只反映举报历史的来源更可信，
		// 完整度只在权重接近时起作用（否则一个 0.85 权重但字段填得多的来源
		// 会盖掉 1.2 权重的来源，界面上显示出错的运营商名）。
		score := weightOf(s) * 3
		// 给得越全越可信：ASN + 组织 + 类型齐全的来源优先。
		if s.ASN != "" {
			score += 1
		}
		if s.Org != "" {
			score += 0.5
		}
		if s.Type != "" || s.Usage != "" {
			score += 0.3
		}
		if best == nil || score > best.w {
			best = &cand{w: score, s: s}
		}
	}
	if best == nil {
		return
	}
	s := best.s
	res.ASN, res.Org, res.ISP, res.Domain, res.Usage, res.Country = s.ASN, s.Org, s.ISP, s.Domain, s.Usage, s.Country
	if res.Org == "" && hostingOrgNameHint(res.IPType) != "" {
		res.Org = hostingOrgNameHint(res.IPType)
	}
}

func hostingOrgNameHint(typ string) string {
	switch typ {
	case model.TypeHosting:
		return "（来源未给出组织名）"
	case model.TypeVpngateOwn:
		return "VPN Gate / SoftEther"
	}
	return ""
}

// IsCleanResidential 判断是否算「志愿者家宽」。store 会把这个结论缓存到节点上。
func IsCleanResidential(r *model.PurityResult) bool {
	if r == nil {
		return false
	}
	if orTrue(r.Factors.Datacenter) || orTrue(r.Factors.VPN) || orTrue(r.Factors.Proxy) || orTrue(r.Factors.Tor) {
		return false
	}
	switch r.IPType {
	case model.TypeResidential, model.TypeMobile, model.TypeBusiness, model.TypeEducation, model.TypeGovernment:
		return true
	}
	return false
}

// orTrue 处理指针布尔。
func orTrue(p *bool) bool { return p != nil && *p }

func weightOf(s *Signals) float64 {
	if s.Weight > 0 {
		return s.Weight
	}
	return Weight(s.Name)
}

func hasTag(s *Signals, tag string) bool {
	for _, t := range s.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func labelFor(typ string) string {
	if l, ok := model.TypeLabels[typ]; ok {
		return l
	}
	return model.TypeLabels[model.TypeUnknown]
}

// yesNames 列出在该因子投了「是」的来源名，用来生成理由。
func yesNames(valid []*Signals, key string) string {
	var names []string
	for _, s := range valid {
		v := boolOf(&s.Factors, key)
		if v != nil && *v {
			names = append(names, s.Name)
		}
	}
	return strings.Join(names, ",")
}

func reasonList(voteLog map[string]string) []string {
	var out []string
	for _, spec := range factorSpecs {
		if who, ok := voteLog[spec.Key]; ok {
			out = append(out, factorLabel(spec.Key)+"（来源: "+who+"）")
		}
	}
	return out
}

func factorLabel(key string) string {
	for _, f := range factorLabels {
		if f.Key == key {
			return f.Label
		}
	}
	return key
}
