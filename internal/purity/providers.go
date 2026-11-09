package purity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// 本文件是各外部来源的实现。每个 provider 只做两件事：
// 把该家的 JSON 映射成 Signals，以及把该家自己的风险分量纲归一到 0-100。
// 汇总、投票、结论都在 score.go，不在这里。

// fetch 拉一个 URL 并按上限截断。API 请求要开压缩（跟抓 CSV 相反：
// 那些是文本大文件且镜像站对 gzip 有 bug，这里是小 JSON 且走 HTTPS CDN）。
func fetch(ctx context.Context, h *http.Client, url string, maxBytes int64) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpngate-agg/1.0 (+ip-purity)")
	req.Header.Set("Accept", "application/json")
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// 把响应体前 200 字节带进错误里：免费源的 403/429 通常在 body 里写原因，
		// 只给状态码的话排障全靠猜。
		preview := strings.TrimSpace(string(raw))
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, preview)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("空响应")
	}
	return raw, nil
}

// ---------- ipquery.io（免费、可不用 key） ----------

type ipqueryProvider struct{ key string }

func (p ipqueryProvider) Name() string   { return "ipquery" }
func (p ipqueryProvider) NeedsKey() bool { return false }

func (p ipqueryProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	url := "https://api.ipquery.io/" + q.IP
	if p.key != "" {
		url += "?authorization=" + p.key
	}
	raw, err := fetch(ctx, h, url, 64<<10)
	if err != nil {
		return nil, err
	}
	var doc struct {
		ISP struct {
			ASN string `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"isp"`
		Location struct {
			Country string `json:"country"`
			Code    string `json:"country_code"`
		} `json:"location"`
		Risk struct {
			IsMobile     *bool `json:"is_mobile"`
			IsVPN        *bool `json:"is_vpn"`
			IsTor        *bool `json:"is_tor"`
			IsProxy      *bool `json:"is_proxy"`
			IsDatacenter *bool `json:"is_datacenter"`
			RiskScore    *int  `json:"risk_score"`
			Assessment   struct {
				Level       string `json:"level"`
				ThreatScore *int   `json:"threat_score"`
				Anonymity   *int   `json:"anonymity_score"`
				Reasons     []struct {
					Code   string `json:"code"`
					Score  int    `json:"score"`
					Source string `json:"source"`
				} `json:"reasons"`
			} `json:"assessment"`
		} `json:"risk"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	s := &Signals{Name: p.Name(), OK: true, Weight: Weight(p.Name())}
	s.ASN, s.Org, s.ISP = doc.ISP.ASN, doc.ISP.Org, doc.ISP.ISP
	s.Country = doc.Location.Country
	mergeTrue(&s.Factors.Proxy, orFalse(doc.Risk.IsProxy))
	mergeTrue(&s.Factors.VPN, orFalse(doc.Risk.IsVPN))
	mergeTrue(&s.Factors.Tor, orFalse(doc.Risk.IsTor))
	mergeTrue(&s.Factors.Datacenter, orFalse(doc.Risk.IsDatacenter))
	mergeTrue(&s.Factors.Mobile, orFalse(doc.Risk.IsMobile))
	if doc.Risk.RiskScore != nil {
		v := clampInt(*doc.Risk.RiskScore)
		s.Score = &v
		s.ScoreName = "risk_score"
	}
	for _, r := range doc.Risk.Assessment.Reasons {
		if r.Code != "" {
			s.Tags = append(s.Tags, r.Code)
		}
	}
	if orFalse(doc.Risk.IsDatacenter) {
		s.Type = model.TypeHosting
	} else if orFalse(doc.Risk.IsTor) {
		s.Type = model.TypeTor
	} else if orFalse(doc.Risk.IsProxy) || orFalse(doc.Risk.IsVPN) {
		s.Type = model.TypeVPNProxy
	} else if orFalse(doc.Risk.IsMobile) {
		s.Type = model.TypeMobile
	}
	s.Raw = raw
	return s, nil
}

// ---------- ipinfo.io（免费 token） ----------

type ipinfoProvider struct{ token string }

func (p ipinfoProvider) Name() string   { return "ipinfo" }
func (p ipinfoProvider) NeedsKey() bool { return true }

func (p ipinfoProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	raw, err := fetch(ctx, h, "https://ipinfo.io/"+q.IP+"/json?token="+p.token, 32<<10)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Org     string `json:"org"`
		Country string `json:"country"`
		Domain  string `json:"domain"`
		Privacy *struct {
			VPS     *bool `json:"vps"`
			Hosting *bool `json:"hosting"`
			Proxy   *bool `json:"proxy"`
			VPN     *bool `json:"vpn"`
			Tor     *bool `json:"tor"`
			TorExit *bool `json:"tor_exit"`
			Mobile  *bool `json:"mobile"`
			Service *struct {
				Name  string `json:"name"`
				Title string `json:"title"`
			} `json:"service"`
		} `json:"privacy"`
		Anonym *struct {
			Type string `json:"type"` // hosting | vpn | tor | proxy
		} `json:"anonymizer"`
		Bogon *bool `json:"bogon"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	s := &Signals{Name: p.Name(), OK: true, Weight: Weight(p.Name())}
	s.Org, s.Country, s.Domain = doc.Org, doc.Country, doc.Domain
	if doc.Bogon != nil && *doc.Bogon {
		s.Tags = append(s.Tags, "bogon")
	}
	if doc.Privacy == nil && doc.Anonym == nil {
		// 免费 token 的 privacy 字段是有配额/权限的。没给就别当作「全都干净」，
		// 这是最容易骗自己的一种「干净」。
		s.Err = "响应里没有 privacy 字段（token 权限或配额不足），本次不算有效结论"
		s.OK = false
		s.Raw = truncRaw(raw, 400)
		return s, nil
	}
	if pv := doc.Privacy; pv != nil {
		mergeTrue(&s.Factors.Proxy, orFalse(pv.Proxy))
		mergeTrue(&s.Factors.VPN, orFalse(pv.VPN))
		mergeTrue(&s.Factors.Tor, orFalse(pv.Tor) || orFalse(pv.TorExit))
		mergeTrue(&s.Factors.Datacenter, orFalse(pv.Hosting) || orFalse(pv.VPS))
		mergeTrue(&s.Factors.Mobile, orFalse(pv.Mobile))
		for k, v := range map[string]*bool{"vps": pv.VPS, "hosting": pv.Hosting, "proxy": pv.Proxy, "vpn": pv.VPN, "tor": pv.Tor, "tor_exit": pv.TorExit, "mobile": pv.Mobile} {
			if orFalse(v) {
				s.Tags = append(s.Tags, k)
			}
		}
		if pv.Service != nil && pv.Service.Name != "" {
			s.Tags = append(s.Tags, "service:"+pv.Service.Name)
		}
	}
	if doc.Anonym != nil && strings.TrimSpace(doc.Anonym.Type) != "" {
		s.Tags = append(s.Tags, "anonymizer:"+doc.Anonym.Type)
		switch strings.ToLower(doc.Anonym.Type) {
		case "tor":
			mergeTrue(&s.Factors.Tor, true)
		case "vpn":
			mergeTrue(&s.Factors.VPN, true)
		case "proxy":
			mergeTrue(&s.Factors.Proxy, true)
		case "hosting":
			mergeTrue(&s.Factors.Datacenter, true)
		}
	}
	// ipinfo 不给数值分。这里按因子推一个「该家口径」的风险分，
	// 再乘权重进汇总；换算规则写在这里而不是散落到汇总里。
	s.Score = ptrInt(riskFromFactors(s.Factors, true))
	s.ScoreName = "privacy_flags"
	if orFalse(s.Factors.Datacenter) {
		s.Type = model.TypeHosting
	} else if orFalse(s.Factors.Tor) {
		s.Type = model.TypeTor
	} else if orFalse(s.Factors.VPN) || orFalse(s.Factors.Proxy) {
		s.Type = model.TypeVPNProxy
	}
	s.Raw = raw
	return s, nil
}

// ---------- scamalytics（免费 key，机房/滥用数据比较硬） ----------

type scamalyticsProvider struct{ key string }

func (p scamalyticsProvider) Name() string   { return "scamalytics" }
func (p scamalyticsProvider) NeedsKey() bool { return true }

func (p scamalyticsProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	url := "https://scamalytics.com/api/secure/v2/check?access_key=" + p.key + "&address=" + q.IP + "&language=en"
	raw, err := fetch(ctx, h, url, 32<<10)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Success *bool `json:"success"`
		Err     *struct {
			Code int    `json:"code"`
			Msg  string `json:"message"`
		} `json:"error"`
		FraudScore *int    `json:"fraud_score"`
		IPType     *string `json:"ip_type"`
		UsageType  *string `json:"ip_usage_type"`
		Company    *struct {
			Name     *string `json:"name"`
			Domain   *string `json:"domain"`
			Category *string `json:"category"`
		} `json:"company"`
		Connections *struct {
			ASN *struct {
				Number *int    `json:"number"`
				Org    *string `json:"org"`
			} `json:"asn"`
			Proxy *struct {
				Exists *bool `json:"exists"`
			} `json:"proxy"`
			Tor *struct {
				Exists *bool `json:"exists"`
			} `json:"tor"`
		} `json:"connections"`
		Datacenter *struct {
			Exists *bool `json:"exists"`
		} `json:"datacenter"`
		Abuser  *bool `json:"abuser"`
		Crawler *bool `json:"crawler"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if doc.Success != nil && !*doc.Success {
		msg := "接口返回 success=false"
		if doc.Err != nil {
			msg = fmt.Sprintf("接口错误 %d: %s", doc.Err.Code, doc.Err.Msg)
		}
		return nil, fmt.Errorf("%s", msg)
	}
	s := &Signals{Name: p.Name(), OK: true, Weight: Weight(p.Name())}
	if doc.FraudScore != nil {
		v := clampInt(*doc.FraudScore)
		s.Score = &v
		s.ScoreName = "fraud_score"
	}
	if doc.Datacenter != nil {
		mergeTrue(&s.Factors.Datacenter, orFalse(doc.Datacenter.Exists))
	}
	if doc.Connections != nil {
		if doc.Connections.Proxy != nil {
			mergeTrue(&s.Factors.Proxy, orFalse(doc.Connections.Proxy.Exists))
		}
		if doc.Connections.Tor != nil {
			mergeTrue(&s.Factors.Tor, orFalse(doc.Connections.Tor.Exists))
		}
		if doc.Connections.ASN != nil {
			if doc.Connections.ASN.Number != nil {
				s.ASN = "AS" + strconv.Itoa(*doc.Connections.ASN.Number)
			}
			s.Org = derefStr(doc.Connections.ASN.Org)
		}
	}
	mergeTrue(&s.Factors.Abuser, orFalse(doc.Abuser))
	mergeTrue(&s.Factors.Bot, orFalse(doc.Crawler))
	if doc.Company != nil {
		s.Domain = derefStr(doc.Company.Domain)
		s.Org = firstNonEmpty(s.Org, derefStr(doc.Company.Name))
	}
	s.Type = typeFromWords(derefStr(doc.IPType))
	s.Usage = derefStr(doc.UsageType)
	s.Raw = raw
	return s, nil
}

// ---------- ipregistry.co（免费 key，network.type 是类型判据里最干净的） ----------

type ipregistryProvider struct{ key string }

func (p ipregistryProvider) Name() string   { return "ipregistry" }
func (p ipregistryProvider) NeedsKey() bool { return true }

func (p ipregistryProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	raw, err := fetch(ctx, h, "https://cloud.ipregistry.co/"+q.IP+"?key="+p.key, 64<<10)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		Location *struct {
			Country *struct {
				Name string `json:"name"`
				Code string `json:"code"`
			} `json:"country"`
		} `json:"location"`
		Network *struct {
			ASN    *int    `json:"asn"`
			Type   *string `json:"type"` // business | education | government | hosting | isp | mobile
			Org    *string `json:"org"`
			Domain *string `json:"domain"`
			ISP    *string `json:"isp"`
		} `json:"network"`
		Security *struct {
			Proxy         *bool `json:"is_proxy"`
			WebProxy      *bool `json:"is_web_proxy"`
			VPN           *bool `json:"is_vpn"`
			Tor           *bool `json:"is_tor"`
			TorExit       *bool `json:"is_tor_exit"`
			Bot           *bool `json:"is_bot"`
			CloudProvider *bool `json:"is_cloud_provider"`
			Datacenter    *struct {
				Exists *bool   `json:"exists"`
				Type   *string `json:"type"`
				Name   *string `json:"name"`
			} `json:"datacenter"`
			Threat *struct {
				Exists *bool `json:"exists"`
			} `json:"threat"`
			Abuser *bool `json:"is_abuser"`
		} `json:"security"`
		Abuse *struct {
			Totals *struct {
				Reports *int `json:"reports"`
			} `json:"totals"`
		} `json:"abuse"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if doc.Error != nil {
		return nil, fmt.Errorf("ipregistry: %s %s", doc.Error.Code, doc.Error.Message)
	}
	s := &Signals{Name: p.Name(), OK: true, Weight: Weight(p.Name())}
	if doc.Location != nil && doc.Location.Country != nil {
		s.Country = firstNonEmpty(doc.Location.Country.Name, doc.Location.Country.Code)
	}
	if doc.Network != nil {
		if doc.Network.ASN != nil {
			s.ASN = "AS" + strconv.Itoa(*doc.Network.ASN)
		}
		s.Org = derefStr(doc.Network.Org)
		s.ISP = derefStr(doc.Network.ISP)
		s.Domain = derefStr(doc.Network.Domain)
		s.Type = typeFromWords(derefStr(doc.Network.Type))
		if doc.Network.Type != nil {
			s.Usage = *doc.Network.Type
			s.Tags = append(s.Tags, "network.type="+*doc.Network.Type)
		}
	}
	if sec := doc.Security; sec != nil {
		mergeTrue(&s.Factors.Proxy, orFalse(sec.Proxy) || orFalse(sec.WebProxy))
		mergeTrue(&s.Factors.VPN, orFalse(sec.VPN))
		mergeTrue(&s.Factors.Tor, orFalse(sec.Tor) || orFalse(sec.TorExit))
		mergeTrue(&s.Factors.Bot, orFalse(sec.Bot))
		mergeTrue(&s.Factors.Abuser, orFalse(sec.Abuser))
		dc := orFalse(sec.CloudProvider)
		if sec.Datacenter != nil {
			dc = dc || orFalse(sec.Datacenter.Exists)
			if sec.Datacenter.Type != nil {
				s.Tags = append(s.Tags, "dc.type="+*sec.Datacenter.Type)
			}
			if sec.Datacenter.Name != nil && *sec.Datacenter.Name != "" {
				s.Tags = append(s.Tags, "dc:"+*sec.Datacenter.Name)
			}
		}
		mergeTrue(&s.Factors.Datacenter, dc)
		if sec.Threat != nil && orFalse(sec.Threat.Exists) {
			s.Tags = append(s.Tags, "threat")
		}
	}
	if doc.Abuse != nil && doc.Abuse.Totals != nil && doc.Abuse.Totals.Reports != nil {
		s.Tags = append(s.Tags, "reports="+strconv.Itoa(*doc.Abuse.Totals.Reports))
	}
	// ipregistry 不给 0-100 的分，用因子推。cloud_provider/datacenter 是主因。
	s.Score = ptrInt(riskFromFactors(s.Factors, true))
	s.ScoreName = "security_flags"
	if doc.Network != nil && doc.Network.Type != nil && strings.EqualFold(*doc.Network.Type, "hosting") {
		s.Type = model.TypeHosting
	}
	s.Raw = raw
	return s, nil
}

// ---------- ipqualityscore（IPQS，商业源，分数量纲最标准） ----------

type ipqsProvider struct{ key string }

func (p ipqsProvider) Name() string   { return "ipqualityscore" }
func (p ipqsProvider) NeedsKey() bool { return true }

func (p ipqsProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	url := "https://ipqualityscore.com/api/json/ip/" + p.key + "/" + q.IP + "?strictness=high&allow_public_access_points=true"
	raw, err := fetch(ctx, h, url, 32<<10)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Success    *bool    `json:"success"`
		Message    string   `json:"message"`
		FraudScore *int     `json:"fraud_score"`
		Proxy      *bool    `json:"proxy"`
		VPN        *bool    `json:"vpn"`
		Tor        *bool    `json:"tor"`
		SecBot     *bool    `json:"sec_bot"`
		Datacenter *string  `json:"is_datacenter"`
		AbuseFlags []string `json:"abuse_flags"`
		Connection *struct {
			ASN       *int    `json:"asn"`
			Org       *string `json:"org"`
			ISP       *string `json:"isp"`
			Domain    *string `json:"domain"`
			UsageType *string `json:"usage_type"`
			Country   *string `json:"country"`
			Type      *string `json:"type"`
		} `json:"connection"`
		Security *struct {
			IsDatacenter *bool `json:"is_datacenter"`
		} `json:"security"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if doc.Success != nil && !*doc.Success {
		return nil, fmt.Errorf("IPQS: %s", firstNonEmpty(doc.Message, "success=false"))
	}
	s := &Signals{Name: p.Name(), OK: true, Weight: Weight(p.Name())}
	if doc.FraudScore != nil {
		v := clampInt(*doc.FraudScore)
		s.Score = &v
		s.ScoreName = "fraud_score"
	}
	mergeTrue(&s.Factors.Proxy, orFalse(doc.Proxy))
	mergeTrue(&s.Factors.VPN, orFalse(doc.VPN))
	mergeTrue(&s.Factors.Tor, orFalse(doc.Tor))
	mergeTrue(&s.Factors.Bot, orFalse(doc.SecBot))
	dc := strings.EqualFold(derefStr(doc.Datacenter), "true") || strings.EqualFold(derefStr(doc.Datacenter), "yes")
	if doc.Security != nil {
		dc = dc || orFalse(doc.Security.IsDatacenter)
	}
	mergeTrue(&s.Factors.Datacenter, dc)
	for _, f := range doc.AbuseFlags {
		if f != "" {
			s.Tags = append(s.Tags, "flag:"+f)
		}
	}
	if c := doc.Connection; c != nil {
		if c.ASN != nil {
			s.ASN = "AS" + strconv.Itoa(*c.ASN)
		}
		s.Org = derefStr(c.Org)
		s.ISP = derefStr(c.ISP)
		s.Domain = derefStr(c.Domain)
		s.Usage = derefStr(c.UsageType)
		s.Country = derefStr(c.Country)
		s.Type = typeFromWords(firstNonEmpty(derefStr(c.Type), derefStr(c.UsageType)))
	}
	s.Raw = raw
	return s, nil
}

// ---------- abuseipdb（举报历史；不是纯净度全貌，权重要压低） ----------

type abuseipdbProvider struct{ key string }

func (p abuseipdbProvider) Name() string   { return "abuseipdb" }
func (p abuseipdbProvider) NeedsKey() bool { return true }

// abuseSecurityClasses 是 AbuseIPDB 的 securityClasses 到因子的映射（官方定义）。
var abuseSecurityClasses = map[int]string{
	4: "vpn", 6: "bot", 7: "abuser", 8: "ddos", 9: "spam", 10: "other", 3: "scanner",
}

func (p abuseipdbProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	// v2 接口必须带 ipVersion 和 maxAgeInDays，否则直接 422。IPv6 要 ipVersion=6。
	version := "4"
	if strings.Contains(q.IP, ":") {
		version = "6"
	}
	url := "https://api.abuseipdb.com/api/v2/check?ipAddress=" + q.IP +
		"&maxAgeInDays=90&ipVersion=" + version + "&verbose=false"
	cctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", p.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vpngate-agg/1.0")
	resp, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		preview := strings.TrimSpace(string(raw))
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, preview)
	}
	var doc struct {
		Data *struct {
			UsageType              *string `json:"usageType"`
			CountryCode            *string `json:"countryCode"`
			AbuseConfidenceScore   *int    `json:"abuseConfidenceScore"`
			TotalReports           *int    `json:"totalReports"`
			IsWhitelisted          *bool   `json:"isWhitelisted"`
			IsCloudServiceProvider *bool   `json:"isCloudServiceProvider"`
			SecurityClasses        []int   `json:"securityClasses"`
			Domain                 *string `json:"domain"`
			ISP                    *string `json:"isp"`
		} `json:"data"`
		Errors []struct {
			Code   int    `json:"code"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if doc.Data == nil {
		if len(doc.Errors) > 0 {
			return nil, fmt.Errorf("AbuseIPDB %d: %s", doc.Errors[0].Code, doc.Errors[0].Detail)
		}
		return nil, fmt.Errorf("AbuseIPDB 响应里没有 data 字段")
	}
	d := doc.Data
	s := &Signals{Name: p.Name(), OK: true, Weight: Weight(p.Name())}
	s.Usage = derefStr(d.UsageType)
	s.Country = derefStr(d.CountryCode)
	s.Domain = derefStr(d.Domain)
	s.ISP = derefStr(d.ISP)
	if d.AbuseConfidenceScore != nil {
		v := clampInt(*d.AbuseConfidenceScore)
		s.Score = &v
		s.ScoreName = "abuseConfidenceScore"
		ab := clampInt(*d.AbuseConfidenceScore)
		s.Factors.AbuseScore = &ab
	}
	if d.TotalReports != nil && *d.TotalReports > 0 {
		mergeTrue(&s.Factors.Abuser, true)
		s.Tags = append(s.Tags, "reports="+strconv.Itoa(*d.TotalReports))
	} else {
		mergeTrue(&s.Factors.Abuser, false)
	}
	if orFalse(d.IsCloudServiceProvider) {
		mergeTrue(&s.Factors.Datacenter, true)
		s.Tags = append(s.Tags, "cloud_provider")
	}
	for _, cls := range d.SecurityClasses {
		if name, ok := abuseSecurityClasses[cls]; ok {
			s.Tags = append(s.Tags, "class:"+name)
			switch name {
			case "vpn":
				mergeTrue(&s.Factors.VPN, true)
			case "bot", "scanner", "ddos":
				mergeTrue(&s.Factors.Bot, true)
			case "abuser", "spam", "other":
				mergeTrue(&s.Factors.Abuser, true)
			}
		}
	}
	if orFalse(d.IsWhitelisted) {
		s.Tags = append(s.Tags, "whitelisted")
	}
	s.Type = typeFromUsage(s.Usage)
	s.Raw = raw
	return s, nil
}

// ---------- 公共小工具 ----------

func orFalse(b *bool) bool { return b != nil && *b }

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// riskFromFactors 在没有原生数值分时，按因子推一个风险分。
//
// strict=true 表示「这些因子来自专业风险源」（ipinfo/ipregistry），
// 权重按专业源给；false 表示来自启发式推断，减半。
func riskFromFactors(f model.PurityFactors, strict bool) int {
	var sum float64
	if orFalse(f.Tor) {
		sum += 85
	}
	if orFalse(f.Datacenter) {
		sum += 68
	}
	if orFalse(f.VPN) {
		sum += 55
	}
	if orFalse(f.Proxy) {
		sum += 52
	}
	if orFalse(f.Abuser) {
		sum += 30
	}
	if orFalse(f.Bot) {
		sum += 22
	}
	// 多个来源同时命中不能简单相加就爆到 300：封顶后按命中数轻微上浮。
	v := sum
	if v > 92 {
		v = 92
	}
	if v > 0 && !strict {
		v /= 2
	}
	if orFalse(f.Mobile) && v == 0 {
		// 移动网络出口是共享的，算不上干净但也绝不脏。
		v = 12
	}
	return clampInt(int(v))
}

// typeFromWords 把各来源五花八门的类型/用途字符串归一到内部类型码。
// 关键词表刻意写成「按优先级从上到下」，第一个命中就用，避免
// "Cloud Hosting ISP" 这种混合串两头都算。
func typeFromWords(s string) string {
	low := strings.ToLower(strings.TrimSpace(s))
	if low == "" {
		return ""
	}
	rules := []struct {
		words []string
		typ   string
	}{
		{[]string{"tor"}, model.TypeTor},
		{[]string{"search engine", "search_engine", "crawler", "spider"}, model.TypeSearchEngine},
		{[]string{"cdn"}, model.TypeCDN},
		{[]string{"data center", "datacenter", "hosting", "hoster", "cloud", "vps", "colocation", "web hosting", "transit"}, model.TypeHosting},
		{[]string{"vpn", "proxy", "anonym", "residential proxy"}, model.TypeVPNProxy},
		{[]string{"mobile", "cellular", "wireless"}, model.TypeMobile},
		{[]string{"education", "university", "school", "research", "academi"}, model.TypeEducation},
		{[]string{"government", "military"}, model.TypeGovernment},
		{[]string{"business", "corporate", "enterprise"}, model.TypeBusiness},
		{[]string{"residential", "isp", "fixed line", "fixed-line", "broadband", "dial-up"}, model.TypeResidential},
	}
	for _, r := range rules {
		for _, w := range r.words {
			if strings.Contains(low, w) {
				return r.typ
			}
		}
	}
	return ""
}

// typeFromUsage 处理 AbuseIPDB 那种 usageType（"Data Center/Web Hosting/Transit"）。
func typeFromUsage(s string) string {
	if t := typeFromWords(s); t != "" {
		return t
	}
	return ""
}
