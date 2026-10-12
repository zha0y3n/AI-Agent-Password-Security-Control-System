// Package crypto 封装 Broker 使用的国密算法：SM3、SM4-GCM、SM2。
//
// 与 A（Python）互通的编码细节（SM2 签名编码、公钥编码、签名输入）
// 以 docs/crypto-protocol.md 为准，在阶段二对齐。
package crypto

import (
	"encoding/hex"

	"github.com/emmansun/gmsm/sm3"
)

// SM3Size 是 SM3 摘要长度（字节）。
const SM3Size = sm3.Size

// SM3 计算 data 的 SM3 摘要。
func SM3(data []byte) []byte {
	sum := sm3.Sum(data)
	return sum[:]
}

// SM3Concat 计算多个字节串直接拼接后的 SM3 摘要，不引入额外分隔符。
func SM3Concat(parts ...[]byte) []byte {
	h := sm3.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// SM3Hex 返回小写十六进制的 SM3 摘要。
func SM3Hex(data []byte) string {
	return hex.EncodeToString(SM3(data))
}
