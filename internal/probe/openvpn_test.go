package probe

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestBuildHardResetShapes(t *testing.T) {
	// 首字节 = opcode(7)<<3 | key_id —— 服务端认的就是这个。
	legacy := BuildHardReset(ShapeLegacy)
	if legacy[0] != 0x38 {
		t.Errorf("legacy 首字节 = 0x%02x，期望 0x38", legacy[0])
	}
	if len(legacy) != 1+4+4+128 {
		t.Errorf("legacy 长度 = %d，期望 %d", len(legacy), 1+4+4+128)
	}
	if isAllZero(legacy[1:5]) {
		t.Error("会话 ID 不能全零：OpenVPN 的 session_id_defined() 会直接丢弃")
	}

	modern := BuildHardReset(ShapeModern)
	if modern[0] != 0x38 {
		t.Errorf("modern 首字节 = 0x%02x", modern[0])
	}
	if len(modern) != 1+8+8+128 {
		t.Errorf("modern 长度 = %d，期望 %d（2.6+ 的会话 ID / replay id 是 8 字节）", len(modern), 1+8+8+128)
	}
	if isAllZero(modern[1:9]) {
		t.Error("modern 的会话 ID 不能全零")
	}

	// 包里没有 tls-auth 的 HMAC，两次构造几乎必然不同（会话 ID 是随机的）。
	if a, b := BuildHardReset(ShapeLegacy), BuildHardReset(ShapeLegacy); string(a[:5]) == string(b[:5]) {
		t.Error("连续两包的会话 ID 相同，可能是随机源没生效")
	}
}

func TestTCPFrameAndStrip(t *testing.T) {
	payload := BuildHardReset(ShapeLegacy)
	framed := TCPFrame(payload)
	if got := binary.BigEndian.Uint16(framed[:2]); int(got) != len(payload) {
		t.Errorf("长度前缀 = %d，期望 %d", got, len(payload))
	}
	if string(framed[2:]) != string(payload) {
		t.Error("前缀加错位置")
	}
	if got := stripTCPFrame(framed); string(got) != string(payload) {
		t.Error("剥前缀没能还原原文")
	}

	// SoftEther 回的是裸 HTTP，没有长度前缀：不能误剥头两字节。
	http := []byte("HTTP/1.1 400 Bad Request\r\n")
	if got := stripTCPFrame(http); string(got) != string(http) {
		t.Errorf("HTTP 回包被误剥: %q", got[:6])
	}
	if got := stripTCPFrame([]byte{0x00, 0x01}); len(got) != 2 {
		t.Error("短包不该处理")
	}
}

func TestDecodeOpcode(t *testing.T) {
	cases := []struct {
		name       string
		in         []byte
		wantOp     int
		wantKind   string
		wantDetail string
	}{
		{"服务器硬重置", []byte{0x40, 1, 2, 3, 4, 5, 6, 7, 8}, 8, "openvpn", "P_CONTROL_HARD_RESET_SERVER_V2"},
		{"服务器硬重置带 key_id", []byte{0x43, 0, 0, 0}, 8, "openvpn", "key_id=3"},
		{"P_CONTROL_V1", []byte{0x20, 9, 9, 9}, 4, "openvpn", "P_CONTROL_V1"},
		{"自己发的包", []byte{0x38, 1, 2, 3}, 7, "openvpn", "P_CONTROL_HARD_RESET_CLIENT_V2"},
		{"SoftEther 的 HTTP 回包", []byte("HTTP/1.1 400 Bad Request\r\nServer: SoftEther\r\n"), -1, "http", "HTTP/1.1 400 Bad Request"},
		{"首字节不是 opcode", []byte{0x00, 1, 2, 3}, -1, "raw", "不是 OpenVPN opcode"},
		{"空回包", nil, -1, "", "空回包"},
	}
	for _, c := range cases {
		op, kind, detail := DecodeOpcode(c.in)
		if op != c.wantOp || kind != c.wantKind {
			t.Errorf("%s: 解出 (%d,%q)，期望 (%d,%q)", c.name, op, kind, c.wantOp, c.wantKind)
		}
		if !strings.Contains(detail, c.wantDetail) {
			t.Errorf("%s: detail = %q，应含 %q", c.name, detail, c.wantDetail)
		}
	}
}

func TestIsServerHardReset(t *testing.T) {
	if !IsServerHardReset([]byte{0x40, 0, 0, 0}) {
		t.Error("opcode 8 应认定为服务器硬重置")
	}
	if !IsServerHardReset([]byte{0x47, 0, 0, 0}) {
		t.Error("key_id 不同也应认定（0x40~0x47 都是 opcode 8）")
	}
	for _, b := range [][]byte{nil, {0x38}, {0x20}, {0x00}, {0x48}} {
		if IsServerHardReset(b) {
			t.Errorf("%v 不该认定为硬重置回包", b)
		}
	}
}

// 服务器硬重置回包：opcode 8 + 8 字节会话 ID + 4 字节 packet ID。
func serverHardResetReply() []byte {
	b := make([]byte, 1+8+4)
	b[0] = 0x40
	b[1], b[2], b[3], b[4] = 0xaa, 0xbb, 0xcc, 0xdd
	return b
}
