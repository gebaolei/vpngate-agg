package web

import (
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// world-map.js 是生成文件（tools/gen_worldmap.py），前端靠它画大陆和国界轮廓。
//
// 这类文件出问题不会报错，只会「界面上看着不像地图」：漏了就是只有气泡，
// 生成脚本的投影跟前端不一致就是轮廓整体错位或被压扁 —— 后者我在开发时真的
// 踩过（y 少乘 2，南半球整块看不见）。所以这里把三件事钉住：
// 文件被内嵌且有路由、坐标全在 viewBox 内、关键地理位置上真的有点。
func TestWorldMapEmbeddedAndProjected(t *testing.T) {
	b, err := staticFS.ReadFile("static/world-map.js")
	if err != nil {
		t.Fatalf("world-map.js 没被内嵌（界面上就没有大陆轮廓）: %v", err)
	}
	body := string(b)
	if !strings.Contains(body, "window.VPA_WORLD") {
		t.Error("world-map.js 没往 window.VPA_WORLD 上挂数据，app.js 读不到")
	}

	for _, key := range []string{"land", "borders"} {
		pts := worldPoints(t, body, key)
		if len(pts) < 500 {
			t.Errorf("%s 只有 %d 个坐标点，轮廓肯定被截断了", key, len(pts))
			continue
		}
		maxY := 0.0
		for _, p := range pts {
			if p[0] < 0 || p[0] > 720 || p[1] < 0 || p[1] > 360 {
				t.Fatalf("%s 有坐标超出 viewBox 720x360: [%g, %g]", key, p[0], p[1])
			}
			if p[1] > maxY {
				maxY = p[1]
			}
		}
		// 压扁 bug 的特征就是所有 y 都落在上半部分：南半球必须有点。
		if maxY < 300 {
			t.Errorf("%s 最南只到 y=%g（南半球没了？投影应满足 y=(90-lat)/180*360）", key, maxY)
		}

		// 地标点按前端 mapPx/mapPy 手算，容差 15 单位（约 7.5°）
		for _, want := range []struct {
			name     string
			lon, lat float64
		}{
			{"日本", 139, 37},
			{"澳大利亚", 134, -25},
			{"智利南端", -73, -50},
			{"好望角", 18, -34},
			{"英国", -2, 53},
		} {
			x := (want.lon + 180) / 360 * 720
			y := (90 - want.lat) / 180 * 360
			n := 0
			for _, p := range pts {
				if abs(p[0]-x) < 15 && abs(p[1]-y) < 15 {
					n++
				}
			}
			if n == 0 {
				t.Errorf("%s 这个位置（投影后 [%g, %g]）附近没有 %s 的轮廓点，轮廓跟气泡会错位", key, x, y, want.name)
			}
		}
	}

	// HTML 得引它，app.js 得用它，两边的画布尺寸还得对得上生成脚本里的 720x360。
	idx, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("读 index.html 失败: %v", err)
	}
	if !strings.Contains(string(idx), `src="/world-map.js`) {
		t.Error(`index.html 没引 /world-map.js`)
	}
	js, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("读 app.js 失败: %v", err)
	}
	appJS := string(js)
	for _, want := range []string{"window.VPA_WORLD", "MAP_W = 720", "MAP_H = 360", "map-land", "map-border"} {
		if !strings.Contains(appJS, want) {
			t.Errorf("app.js 少了 %q，底图画不出来", want)
		}
	}
}

func TestWorldMapRouteServed(t *testing.T) {
	h := newHarness(t, "底图路由", nil)
	resp, _ := h.get("/world-map.js")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /world-map.js = %d（登录页之前就要能拿到，别挂到需要登录的路由上）", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("应长缓存: %q", cc)
	}
	// 内容指纹必须把它算进去，否则换版本时浏览器会一直用旧轮廓。
	sb, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("读 server.go 失败: %v", err)
	}
	if !strings.Contains(string(sb), `"world-map.js"`) {
		t.Error(`server.go 的 assetTag 名单里没有 world-map.js，改轮廓不会刷新缓存`)
	}
}

// worldPoints 解析 path 数据里的坐标对。注意 L 支持隐式重复坐标
// （生成脚本就是为了省字节才这么写的），不能按 "L x y" 三个 token 一组读。
func worldPoints(t *testing.T, body, key string) [][2]float64 {
	t.Helper()
	m := regexp.MustCompile(`(?m)^\s*` + key + `: '([^']*)'`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("world-map.js 里找不到 %s 的 path 数据", key)
	}
	var pts [][2]float64
	var buf []float64
	cur := ""
	flush := func() {
		for i := 0; i+1 < len(buf); i += 2 {
			pts = append(pts, [2]float64{buf[i], buf[i+1]})
		}
		buf = buf[:0]
	}
	for _, tk := range regexp.MustCompile(`[MLZ]|-?\d+(?:\.\d+)?`).FindAllString(m[1], -1) {
		switch tk {
		case "M", "L":
			flush()
			cur = tk
		case "Z":
			flush()
			cur = ""
		default:
			if cur == "" {
				t.Fatalf("%s 的 path 里有游离坐标 %s", key, tk)
			}
			v, err := strconv.ParseFloat(tk, 64)
			if err != nil {
				t.Fatalf("%s 的 path 坐标 %q 解析失败: %v", key, tk, err)
			}
			buf = append(buf, v)
		}
	}
	flush()
	return pts
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}
