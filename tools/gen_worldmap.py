#!/usr/bin/env python3
"""重新生成 internal/web/static/world-map.js（国家分布图的底图轮廓）。

数据源：Natural Earth 110m（公共领域，无许可负担）
  ne_110m_land.geojson               陆地多边形
  ne_110m_admin_0_countries.geojson  国界多边形（只用轮廓，不按国家填色）

  curl -sO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_land.geojson
  curl -sO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson
  python3 tools/gen_worldmap.py ne_110m_land.geojson ne_110m_admin_0_countries.geojson

为什么要自己转成 path：CSP 是 script-src 'self'，没有 CDN，也没有第三方地图库，
轮廓必须打进二进制。投影直接用等距柱状（x = lon+180，y = 90-lat），跟前端
mapPx / mapPy 完全一致，所以气泡能落在正确的国家上。

压缩手段（按贡献排序）：Douglas-Peucker（阈值 0.45 投影单位 ≈ 0.22°）、
丢掉小环（对角线 < 1.0 单位的岛礁）、坐标只保留 1 位小数、SVG 的 L 用隐式重复
坐标。陆地 + 国界一共约 90KB，带 ?v= 内容指纹可以 immutable 长缓存。
"""
import json
import math
import sys

W, H = 720.0, 360.0
EPS = 0.45        # Douglas-Peucker 阈值（投影单位；1 单位 = 0.5°）
MIN_DIAG = 1.0    # 小于这个跨度的环丢掉（小岛礁、岩石）


def project(lon, lat):
    # 必须跟 app.js 的 mapPx/mapPy 一致：x = (lon+180)/360*720，y = (90-lat)/180*360。
    # 这里曾经误写成 H/360，轮廓被纵向压掉一半，南半球整块看不见。
    return (lon + 180.0) * (W / 360.0), (90.0 - lat) * (H / 180.0)


def dperp(p, a, b):
    ax, ay = a
    bx, by = b
    px, py = p
    dx, dy = bx - ax, by - ay
    if dx == dy == 0:
        return math.hypot(px - ax, py - ay)
    t = ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def dp(pts, eps):
    if len(pts) < 3:
        return pts
    dmax, idx = 0.0, 0
    for i in range(1, len(pts) - 1):
        d = dperp(pts[i], pts[0], pts[-1])
        if d > dmax:
            dmax, idx = d, i
    if dmax > eps:
        left = dp(pts[:idx + 1], eps)
        right = dp(pts[idx:], eps)
        return left[:-1] + right
    return [pts[0], pts[-1]]


def rings_of(geom):
    t, c = geom["type"], geom["coordinates"]
    if t == "Polygon":
        for r in c:
            yield r
    elif t == "MultiPolygon":
        for poly in c:
            for r in poly:
                yield r


def build(path):
    src = json.load(open(path, encoding="utf-8"))
    parts, kept, dropped, pin, pout = [], 0, 0, 0, 0
    for f in src["features"]:
        geom = f.get("geometry")
        if not geom:
            continue
        for ring in rings_of(geom):
            pin += len(ring)
            lon = [p[0] for p in ring]
            lat = [p[1] for p in ring]
            if math.hypot(max(lon) - min(lon), max(lat) - min(lat)) < MIN_DIAG:
                dropped += 1
                continue
            simp = dp([project(p[0], p[1]) for p in ring], EPS)
            if simp[0] == simp[-1]:
                simp = simp[:-1]
            if len(simp) < 4:
                dropped += 1
                continue
            coords = [(round(x, 1), round(y, 1)) for x, y in simp]
            d = "M%g %g" % coords[0]
            d += "L" + " ".join("%g %g" % c for c in coords[1:]) + "Z"
            parts.append(d)
            kept += 1
            pout += len(simp)
    return " ".join(parts), kept, dropped, pin, pout


def js_quote(s):
    assert '"' not in s and "\\" not in s and "`" not in s, "path 里出现了需要转义的字符"
    return s


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    land, kept_l, drop_l, in_l, out_l = build(sys.argv[1])
    borders, kept_b, drop_b, in_b, out_b = build(sys.argv[2])
    out = "internal/web/static/world-map.js"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(
            "/* 生成文件，别手改：见 tools/gen_worldmap.py。\n"
            " * 底图轮廓（陆地 + 国界）。投影是等距柱状，viewBox 720x360，\n"
            " * 跟 app.js 里的 mapPx/mapPy 一致，所以国家气泡能落在自己的位置上。\n"
            " * 数据：Natural Earth 110m（公共领域）。\n"
            " */\n'use strict';\nwindow.VPA_WORLD = {\n  // 陆地：填充 + 海岸线\n  land: '")
        fh.write(js_quote(land))
        fh.write("',\n  // 国界：只画细线，不按国家填色（那需要 ISO 码对齐，代价大收益小）\n  borders: '")
        fh.write(js_quote(borders))
        fh.write("',\n};\n")
    print("land    环 %4d（丢 %3d）点 %5d -> %5d  %d 字节" % (kept_l, drop_l, in_l, out_l, len(land)))
    print("borders 环 %4d（丢 %3d）点 %5d -> %5d  %d 字节" % (kept_b, drop_b, in_b, out_b, len(borders)))


if __name__ == "__main__":
    main()
