// Package probe 测节点可达性与服务指纹。
//
// 判定分层是这个包的核心设计：
//   - TCP 三次握手成功 = 「这个端口在你的网络里可达」，这是唯一硬结论；
//   - OpenVPN 硬重置包的回包 = 「这个端口真的是 OpenVPN/SoftEther 服务」，
//     是加分项，不是可达性判据；
//   - UDP 收不到回包 = 未知，不是死亡。
//
// 第三点必须写死：实测 VPN Gate 的节点全是 SoftEther，对标准的
// P_CONTROL_HARD_RESET_CLIENT_V2 包，TCP 通道回的是 "HTTP/1.1 400 Bad Request"
// （SoftEther 的 OpenVPN-over-TCP 自己就是这么应答的），UDP 通道 4 个节点
// 全部静默无响应。如果把「无响应」当死亡，界面上会把整个 UDP 池子标成挂了。
package probe

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"
)

// OpenVPN opcode（取自 OpenVPN 源码 src/openvpn/ssl_pkt.h）。
// 首字节 = opcode<<3 | key_id，所以硬重置客户端包以 0x38 开头，
// 服务器的硬重置回包以 0x40~0x47 开头。
const (
	opcodeHardResetClientV2 = 7
	opcodeHardResetServerV2 = 8
	opcodeShift             = 3
	keyIDMask               = 0x07
)

// PacketShape 是硬重置包的构造方式。
//
// OpenVPN 2.4/2.5 与 2.6+ 的会话 ID / packet id 字段宽度不同（4/8 字节），
// 而 VPN Gate 上跑的是 SoftEther 自己的 OpenVPN 兼容实现，不保证严格按
// RFC 草案解析。所以 UDP 上两种形状各发一个：多花 200ms，换「至少有一种
// 能被认出来」的概率。
type PacketShape int

const (
	// ShapeLegacy 对应 2.4/2.5 风格：opcode|sid(4)|packet_id(4)|IV(128)。
	ShapeLegacy PacketShape = iota
	// ShapeModern 对应 wire-protocol 草案/2.6+：opcode|sid(8)|replay_id(8)|IV(128)。
	ShapeModern
)

// BuildHardReset 构造一个硬重置包。
//
// 会话 ID 必须非零：OpenVPN 服务端在校验未认证包时会检查
// session_id_defined()，全零直接丢弃。HMAC 字段因为没有 tls-auth 密钥，
// 只能填随机字节 —— 服务端算出来的 HMAC 对不上是预期的，我们要的是
// 「它有没有理这个包」，不是完整握手。
func BuildHardReset(shape PacketShape) []byte {
	iv := randomBytes(128)
	out := []byte{(opcodeHardResetClientV2 << opcodeShift) | 0}
	switch shape {
	case ShapeModern:
		sid := randomBytes(8)
		if isAllZero(sid) {
			sid[7] = 1
		}
		out = append(out, sid...)
		var pid [8]byte
		binary.BigEndian.PutUint32(pid[0:4], uint32(time.Now().Unix()))
		binary.BigEndian.PutUint32(pid[4:8], 0)
		out = append(out, pid[:]...)
	default:
		sid := randomBytes(4)
		if isAllZero(sid) {
			sid[3] = 1
		}
		out = append(out, sid...)
		var pid [4]byte
		binary.BigEndian.PutUint32(pid[:], uint32(time.Now().Unix()))
		out = append(out, pid[:]...)
	}
	return append(out, iv...)
}

// TCPFrame 给包加上 OpenVPN over TCP 的 2 字节大端长度前缀。
func TCPFrame(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:], payload)
	return out
}

// DecodeOpcode 从回包里认 opcode。
//
// 回包可能是裸包（前 2 字节长度前缀已经在读取时剥掉），也可能根本不是
// OpenVPN（SoftEther 回 HTTP、别的服务回 banner）。所以除了 opcode，
// 还要给调用方一个可解释的细节串。
func DecodeOpcode(b []byte) (opcode int, kind string, detail string) {
	if len(b) == 0 {
		return -1, "", "空回包"
	}
	// SoftEther 的 OpenVPN-over-TCP 对不认识的包回 HTTP 错误页。
	if len(b) >= 5 && strings.EqualFold(string(b[:5]), "HTTP/") {
		first := strings.SplitN(strings.ReplaceAll(string(b), "\r\n", " | "), " | ", 2)[0]
		if len(first) > 120 {
			first = first[:120]
		}
		return -1, "http", first
	}
	op := int(b[0]>>opcodeShift) & 0x1f
	if op < 1 || op > 11 {
		return -1, "raw", "首字节 0x" + hex.EncodeToString(b[:1]) + " 不是 OpenVPN opcode，共 " + itoa(len(b)) + " 字节"
	}
	names := map[int]string{
		1:  "P_CONTROL_HARD_RESET_CLIENT_V1",
		2:  "P_CONTROL_HARD_RESET_SERVER_V1",
		3:  "P_CONTROL_SOFT_RESET_V1",
		4:  "P_CONTROL_V1",
		5:  "P_ACK_V1",
		6:  "P_DATA_V1",
		7:  "P_CONTROL_HARD_RESET_CLIENT_V2",
		8:  "P_CONTROL_HARD_RESET_SERVER_V2",
		9:  "P_DATA_V2",
		10: "P_CONTROL_HARD_RESET_CLIENT_V3",
		11: "P_CONTROL_WKC_V1",
	}
	name, ok := names[op]
	if !ok {
		name = "opcode"
	}
	return op, "openvpn", name + "，共 " + itoa(len(b)) + " 字节，key_id=" + itoa(int(b[0])&keyIDMask)
}

// IsServerHardReset 判断是不是服务器的硬重置回包（opcode 8）。
// 这是「端口后面确实是个 OpenVPN 语义的服务」的最强证据。
func IsServerHardReset(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return int(b[0]>>opcodeShift)&0x1f == opcodeHardResetServerV2
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败是系统级问题，退化成固定值也比 panic 好：
		// 探测包内容本来就不参与校验。
		for i := range b {
			b[i] = byte(i * 7)
		}
	}
	return b
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
