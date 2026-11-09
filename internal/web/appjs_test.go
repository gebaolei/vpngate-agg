package web

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 前端就一个 app.js，没有打包器、没有 TypeScript，写错一个函数名（比如
// settingGroupLabel 少个 s）浏览器只在运行时抛 ReferenceError，而设置页的
// 加载逻辑正好会把这类错误吞进「加载失败: xxx is not defined」里 —— 页面看起来
// 是"打开了但空的"，很容易被当成样式问题。所以这里做一个纯静态检查：
// 每个被调用的自定义函数名，文件里必须真的定义过。
//
// 只查「前面不是点」的调用：`foo(...)` 才算，`obj.foo(...)` 是方法调用，
// 那些由浏览器提供或由对象自己带着，静态查不出来也不该查。
func TestAppJSNoUndefinedFunctionCalls(t *testing.T) {
	blob, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("读 app.js 失败: %v", err)
	}
	src := stripJSNoise(string(blob))

	defined := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(`).FindAllStringSubmatch(src, -1) {
		defined[m[1]] = true
	}
	// 顶层 const/let 也可能是函数（箭头函数），一样算定义。
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=`).FindAllStringSubmatch(src, -1) {
		defined[m[1]] = true
	}
	// 参数名和局部变量会大量出现，别误报：凡是在这些位置上出现过的名字都放过。
	for _, m := range regexp.MustCompile(`(?:function\s*[\w$]*\s*\(|\bcatch\s*\(|\(([^()]*)\)\s*=>)`).FindAllStringSubmatch(src, -1) {
		for _, part := range strings.Split(m[1], ",") {
			name := strings.TrimSpace(strings.SplitN(strings.TrimSpace(part), " ", 2)[0])
			name = strings.TrimSuffix(name, "=")
			if name != "" {
				defined[name] = true
			}
		}
	}
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:const|let|var)\s+(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)`).FindAllStringSubmatch(src, -1) {
		defined[strings.TrimSpace(m[1])] = true
	}

	// 语言关键字 + 浏览器/JS 内建，这些当然没有 function 定义。
	builtin := map[string]bool{}
	for _, n := range strings.Fields(`
		if for while switch catch return function typeof await new delete void async
		fetch setTimeout clearTimeout setInterval clearInterval requestAnimationFrame
		parseInt parseFloat isNaN isFinite Number String Boolean Array Object JSON Math Date
		RegExp Error Promise Map Set URL URLSearchParams encodeURIComponent decodeURIComponent
		atob btoa alert confirm prompt Intl FormData Blob FileReader Image Event EventSource
		CustomEvent localStorage sessionStorage navigator location history document window console
		structuredClone queueMicrotask matchMedia getComputedStyle`) {
		builtin[n] = true
	}

	callRe := regexp.MustCompile(`(^|[^.\w$])([A-Za-z_$][\w$]*)\s*\(`)
	var missing []string
	seen := map[string]bool{}
	for _, m := range callRe.FindAllStringSubmatch(src, -1) {
		name := m[2]
		if seen[name] || defined[name] || builtin[name] {
			continue
		}
		seen[name] = true
		missing = append(missing, name)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("app.js 里调用了没定义的函数（运行时会是 ReferenceError）: %s", strings.Join(missing, ", "))
	}
}

// 设置页的三块必须都在 app.js 里：少一块，界面上就少一组配置，
// 而这种缺失不会报错，只会安静地少显示。
func TestAppJSHasSettingsSections(t *testing.T) {
	blob, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("读 app.js 失败: %v", err)
	}
	src := string(blob)
	for _, want := range []string{
		"function settingsNodes(",
		"function settingsProbe(",
		"function settingsPurity(",
		"function settingsPassword(",
		"function settingsGroupLabel(",
		"function settingToggle(",
		"function settingNumber(",
		"function settingStatus(",
		"function loadSettings(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js 少了 %q", want)
		}
	}
	// 每个 POST 字段都要有人真的发出去，否则界面上点了没反应。
	for _, field := range []string{
		// 官方主站故意不在列表里：它是必开来源，界面不该给关掉它的入口。
		"mirrors_enabled", "cdn_enabled", "cdn_pool_enabled",
		"keep_vpngate_own", "keep_days", "purge_fail_rounds",
		"probe_enabled", "probe_interval_minutes", "probe_concurrency",
		"probe_tcp_timeout_seconds", "probe_udp_timeout_seconds", "probe_handshake",
		"purity_enabled", "purity_rpm",
	} {
		if !strings.Contains(src, "'"+field+"'") {
			t.Errorf("界面上没有任何控件提交 %q，后端加了字段但界面漏了", field)
		}
	}
}

// 已判定不可达的行在延迟列不给数字（EWMA 不清空也不按时间衰减，挂着个
// 旧数字会被读成「现在还能连，只是慢」），改为只写说明 + 把历史值放到 title
// 和详情面板里。这个规则全在前端，写错了不会报错，只会静默把作废的
// 延迟列的四种状态必须分清楚：待测试（还没测过）/ 实测 / 未测出延迟（测了
// 但没连上）/ 已判定不可达。同时 best 口径不能再兜底官方 Ping —— 延迟列显示
// 的数和 sort=ping / max_ping 用的数必须是同一个值。这些规则全在前端，写错了
// 不报错，只会静默把别人那张网的数顶到这一列上，所以钉住。
func TestAppJSHidePingForDownNodes(t *testing.T) {
	blob, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("读 app.js 失败: %v", err)
	}
	src := string(blob)
	for _, want := range []string{
		"note: '已判定不可达'",      // 已挂：不给延迟数
		"'待测试'",               // 从没测过
		"'未测出延迟'",             // 测了但一次都没连上
		"noteWhenUnmeasured(", // 上面两个是同一条函数分的
		"class: 'ping-off'",   // 延迟列里那句说明
		"历史 EWMA",             // 详情面板把那个历史值补回来
	} {
		if !strings.Contains(src, want) {
			t.Errorf("app.js 少了 %q —— 延迟列的显示规则被弄丢了", want)
		}
	}
	// 旧写法不该回来：把作废的延迟数和「已判定不可达」拼在同一行。
	if strings.Contains(src, "' · 已判定不可达'") {
		t.Error("延迟列不该再显示「数字 + · 已判定不可达」")
	}
	// best 口径里不能再出现「拿官方 Ping 兜底」：排序已经不认它了（query.localPing）。
	if strings.Contains(src, "if (n.upstream_ping_ms) return") {
		t.Error("pickPing 的 best 口径不该兜底官方 Ping，与 store/query.go 的 localPing 必须同口径")
	}
}

// stripJSNoise 去掉注释和字符串字面量：注释里写 setAttribute('style')、
// CSS 串里的 linear-gradient(...)、模板串里的 var(...) 都不是函数调用，
// 不先摘掉会一路误报。
func stripJSNoise(src string) string {
	// 块注释
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, " ")
	var b strings.Builder
	b.Grow(len(src))
	rs := []rune(src)
	inLine := false
	var quote rune
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		if inLine {
			if c == '\n' {
				inLine = false
				b.WriteRune(c)
			}
			continue
		}
		if quote != 0 {
			if c == '\\' {
				i++ // 跳过被转义的字符
				continue
			}
			if c == quote {
				quote = 0
				b.WriteRune(' ')
			}
			continue
		}
		switch {
		case c == '/' && i+1 < len(rs) && rs[i+1] == '/':
			inLine = true
			i++
		case c == '\'' || c == '"' || c == '`':
			quote = c
			b.WriteRune(' ')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// 地图的国家坐标表是手写的，手写就会有笔误（[102, 3.9) 少个括号、纬度写成 91）。
// 语法错能被 JS 引擎挡住，范围错不会 —— 只会让某个国家的气泡跑到图外，
// 或者整表被解析截断。这里把范围、条数、关键国家钉住。
func TestAppJSMapCoordinates(t *testing.T) {
	blob, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("读 app.js 失败: %v", err)
	}
	block := regexp.MustCompile(`(?s)const COUNTRY_LL = \{(.*?)\n\};`).FindStringSubmatch(string(blob))
	if block == nil {
		t.Fatal("找不到 COUNTRY_LL 坐标表，地图画不出国家")
	}
	entry := regexp.MustCompile(`([A-Z]{2}):\s*\[\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*\]`)
	all := entry.FindAllStringSubmatch(block[1], -1)
	if len(all) < 120 {
		t.Errorf("坐标表只有 %d 条，太少：VPN Gate 常出现的国家基本都在 150 个左右", len(all))
	}
	have := map[string]bool{}
	for _, m := range all {
		code, lon, lat := m[1], m[2], m[3]
		have[code] = true
		f := func(s string) float64 { v, _ := strconv.ParseFloat(s, 64); return v }
		if f(lon) < -180 || f(lon) > 180 || f(lat) < -90 || f(lat) > 90 {
			t.Errorf("%s 坐标越界: [%s, %s]（画到图外去了）", code, lon, lat)
		}
	}
	// 官方名单里长期占大头的那几个，缺一个地图就少一半信息。
	for _, code := range []string{"JP", "KR", "RU", "TH", "US", "VN", "AU", "IN", "CA", "BR", "DE", "GB", "ZA"} {
		if !have[code] {
			t.Errorf("坐标表缺 %s", code)
		}
	}
}

// 版面契约：卡片 → （左地图 | 右数据源）→ 节点列表页。顺序被人改动后，
// 「节点列表单独一页」会变成「表格又跑回首页」，而这不会报任何错。
func TestIndexPageLayout(t *testing.T) {
	blob, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("读 index.html 失败: %v", err)
	}
	src := string(blob)
	mark := func(s string) int { return strings.Index(src, s) }
	order := []struct {
		name string
		need string
	}{
		{"统计卡片", `<section class="cards"`},
		{"总览页容器", `id="view-overview"`},
		{"国家分布图", `id="map-panel"`},
		{"数据源与任务", `id="pipeline"`},
		{"节点列表页", `id="view-nodes"`},
		{"筛选区", `id="filters"`},
		{"节点表", `id="nodes-table"`},
		{"分页", `id="pager"`},
	}
	prev := -1
	for _, o := range order {
		i := mark(o.need)
		if i < 0 {
			t.Fatalf("%s 不见了（%q）", o.name, o.need)
		}
		if i < prev {
			t.Errorf("%s 的位置不对：应该在 %s 之后", o.name, order[len(order)-1].name)
		}
		prev = i
	}
	// 切页入口和地图指标切换都得在 HTML 里，缺了就是「点了没反应」。
	for _, want := range []string{
		`data-act="tab" data-tab="overview"`,
		`data-act="tab" data-tab="nodes"`,
		`data-act="map-metric" data-metric="nodes"`,
		`data-act="map-metric" data-metric="alive"`,
		`data-act="map-metric" data-metric="res"`,
		`data-act="map-metric" data-metric="ping"`,
		`id="map-legend"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("index.html 少了 %q", want)
		}
	}
	// 节点列表页默认必须是隐藏的：不隐藏就是两页同时显示。
	if !strings.Contains(src, `class="nodes-view" id="view-nodes" hidden`) {
		t.Error(`节点列表页没带 hidden，会和总览页同时显示`)
	}
}

// 地图指标切换的四个键必须在两边都对得上：HTML 里点了某个指标，
// app.js 的 MAP_METRICS 里没有就会静默什么都不换。
func TestAppJSMapMetricsMatchHTML(t *testing.T) {
	js, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("读 app.js 失败: %v", err)
	}
	html, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("读 index.html 失败: %v", err)
	}
	metrics := regexp.MustCompile(`data-metric="([a-z]+)"`).FindAllStringSubmatch(string(html), -1)
	if len(metrics) == 0 {
		t.Fatal("index.html 里没有地图指标切换按钮")
	}
	block := regexp.MustCompile(`(?s)const MAP_METRICS = \{(.*?)\n\};`).FindStringSubmatch(string(js))
	if block == nil {
		t.Fatal("app.js 里找不到 MAP_METRICS")
	}
	for _, m := range metrics {
		if !regexp.MustCompile(`(?m)^\s*` + m[1] + `:\s*\{`).MatchString(block[1]) {
			t.Errorf("界面上的指标 %q 在 MAP_METRICS 里没有，点了不会切换", m[1])
		}
	}
}

// 总览页「两块面板等高 + 占满一屏」是靠三条规则凑出来的，少任何一条都不会报错，
// 只会退化成「面板一高一矮、页面底部留白」或者「面板溢出容器又开始整页滚」。
// 这三条我都是踩了坑才补上的，所以钉住。
func TestCSSOverviewFillsViewport(t *testing.T) {
	blob, err := os.ReadFile("static/style.css")
	if err != nil {
		t.Fatalf("读 style.css 失败: %v", err)
	}
	src := string(blob)
	for _, want := range []string{
		// 主区：卡片按内容，第二行吃满剩余高度
		"min-height: calc(100dvh - var(--topbar-h));",
		"grid-template-rows: auto minmax(0, 1fr);",
		// 总览页钉死高度，第二行才是 definite 的 1fr
		".main:has(> #view-overview:not([hidden])) { height: calc(100dvh - var(--topbar-h)); }",
		// 两块面板等高
		".home-grid {", "align-items: stretch;", "grid-template-rows: minmax(0, 1fr);",
		// 右面板装得下就铺满，装不下就内部滚，别把页面顶出留白
		".panel.panel-pipeline .pipeline { min-height: 0; overflow-y: auto; }",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("style.css 少了 %q —— 总览页的等高/占满会退化", want)
		}
	}
	// 双 class 不是啰嗦：单类选择器按出现顺序决胜，.panel 在后面就会盖掉规则。
	if strings.Contains(src, "\n.panel-map {") || strings.Contains(src, "\n.panel-pipeline {") {
		t.Error("面板的三段式规则必须写成 .panel.panel-map / .panel.panel-pipeline，否则会被 .panel 覆盖")
	}
}

// 深色模式下点开筛选下拉，展开的那张列表是浏览器画的：只给 select 本身染深色
// 不够，必须把 color-scheme 声明到控件的祖先（根元素），否则弹层还是白底黑字。
// 这条规则很容易在重构主题时被删掉，而且删了不会报错、只是「下拉看不清」，所以钉住。
func TestCSSColorSchemeFollowsTheme(t *testing.T) {
	blob, err := os.ReadFile("static/style.css")
	if err != nil {
		t.Fatalf("读 style.css 失败: %v", err)
	}
	src := string(blob)

	// 两套主题各自声明自己的 scheme，缺一个就有一半的主题回到浏览器默认。
	for _, want := range []string{
		"html:has(> body.theme-dark) { color-scheme: dark; }",
		"html:has(> body.theme-light) { color-scheme: light; }",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("style.css 少了 %q —— 浏览器画的控件（下拉弹层、number 箭头、checkbox）会跟着系统偏好走，不跟界面主题走", want)
		}
	}
	for _, theme := range []string{"theme-dark", "theme-light"} {
		block := regexp.MustCompile(`(?s)body\.` + theme + ` \{(.*?)\n\}`).FindStringSubmatch(src)
		if block == nil {
			t.Fatalf("找不到 body.%s 变量块", theme)
		}
		want := "color-scheme: " + strings.TrimPrefix(theme, "theme-") + ";"
		if !strings.Contains(block[1], want) {
			t.Errorf("body.%s 里没有 %s —— 控件不会继承当前主题的配色方案", theme, want)
		}
	}

	// 能认 option 颜色的浏览器（Chrome/Edge）靠这两条把弹层面板接上主题。
	for _, want := range []string{
		".mini select option, .mini select optgroup {",
		".mini select option:checked {",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("style.css 少了 %q —— 展开的下拉列表面板不会跟着主题上色", want)
		}
	}

	// head 里那条 meta 是 CSS 加载前的兜底（首帧不闪白），别顺手删了。
	h, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("读 index.html 失败: %v", err)
	}
	if !strings.Contains(string(h), `<meta name="color-scheme"`) {
		t.Error("index.html 的 <meta name=\"color-scheme\"> 被删了 —— CSS 到位前首帧会按浏览器默认刷一下白")
	}
}

// 已选条件的 chip 是一排胶囊：只要有一个 chip 的内容特别长（国家全名之类），或者
// 文字命中了行高很大的回退字体（国旗 emoji、符号字体在 Windows 上尤其明显），
// 那个胶囊就会自己撑成两行高的椭圆，跟同一排里其他 chip 差一截。这里钉死「只有一行
// + 行高固定 + 超出省略」，顺手给下拉框也钉个上限（它的宽度由最宽的那一项决定）。
func TestCSSChipStaysOneLine(t *testing.T) {
	blob, err := os.ReadFile("static/style.css")
	if err != nil {
		t.Fatalf("读 style.css 失败: %v", err)
	}
	src := string(blob)

	block := regexp.MustCompile(`(?s)\.chip \{(.*?)\n\}`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("找不到 .chip 规则块")
	}
	for _, want := range []string{"white-space: nowrap;", "line-height: 1.35;", "height: 2em;", "max-width: 100%;"} {
		if !strings.Contains(block[1], want) {
			t.Errorf(".chip 里没有 %s —— 长内容或回退字体会把某个 chip 撑成两行高的椭圆", want)
		}
	}
	// flex 容器默认 align-items:normal(=stretch)，不关掉的话同排里偏高的那个 chip
	// 会把其他人一起拉长。
	line := regexp.MustCompile(`(?m)^\.chips \{.*\}$`).FindString(src)
	if line == "" || !strings.Contains(line, "align-items: center;") {
		t.Error(".chips 没有 align-items: center —— flex 默认 stretch 会把整排 chip 拉到同高")
	}
	// flex 子项不关掉 min-width:auto 就不会收缩，省略号永远不出现。
	if !strings.Contains(src, ".chip > .muted, .chip > b { min-width: 0; overflow: hidden; text-overflow: ellipsis; }") {
		t.Error("chip 的文字没有 min-width:0 + 省略号 —— 收缩不了，只会被动变宽")
	}
	sel := regexp.MustCompile(`(?s)\.mini select \{(.*?)\n\}`).FindStringSubmatch(src)
	if sel == nil || !strings.Contains(sel[1], "max-width: 240px;") {
		t.Error(".mini select 没有 max-width —— 某个国家名很长时整排筛选会被它顶宽")
	}
}

// 过滤卡片是 grid（gap 10px），grid 的 align-content 默认 normal(=stretch)：卡片比
// 内容高时，多出来的高度会被分给自动行。而 .main 第二行是 minmax(0,1fr) 且整页有
// min-height，所以「结果很少」或「每页条数很小」时 .nodes-view 会拿到一大块空白，
// 过滤卡片被拉成行间距很大的胖卡片（实测 .filter-row 76px→144px、.chips 23px→92px）。
// 两处都要 align-content: start：外层不给空白，内层也不接空白。
func TestCSSFilterCardNotStretched(t *testing.T) {
	blob, err := os.ReadFile("static/style.css")
	if err != nil {
		t.Fatalf("读 style.css 失败: %v", err)
	}
	src := string(blob)
	for _, sel := range []string{`\.nodes-view`, `\.filters`} {
		block := regexp.MustCompile(`(?s)` + sel + ` \{(.*?)\n\}`).FindStringSubmatch(src)
		if block == nil {
			t.Fatalf("找不到 %s 规则块", sel)
		}
		if !strings.Contains(block[1], "align-content: start;") {
			t.Errorf("%s 没有 align-content: start —— grid 默认 stretch 会把剩余高度分给自动行，过滤卡片会胀高", sel)
		}
	}
}
