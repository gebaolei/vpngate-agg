package source

import (
	"crypto/sha256"
	"encoding/hex"
)

// shaHex 求字节的 SHA-256 十六进制串。单独一个函数是因为 sha256.Sum256 返回
// 数组，直接对函数返回值取切片 Go 编译不过，而校验点有好几处，每处都写一遍
// `sum := ...; hex.EncodeToString(sum[:])` 太吵。
func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
