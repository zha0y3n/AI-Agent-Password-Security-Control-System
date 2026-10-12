package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
)

// SM4KeySize 是 SM4 密钥长度（字节）。
const SM4KeySize = 16

// ErrDecrypt 表示认证解密失败（密文、Tag、Nonce 或 AAD 被篡改，或密钥错误）。
var ErrDecrypt = errors.New("sm4-gcm: authentication failed")

// SM4GCM 是基于 SM4 分组密码的 GCM 认证加密。
type SM4GCM struct {
	aead cipher.AEAD
}

// NewSM4GCM 用 16 字节密钥创建 SM4-GCM。
func NewSM4GCM(key []byte) (*SM4GCM, error) {
	if len(key) != SM4KeySize {
		return nil, fmt.Errorf("sm4-gcm: key must be %d bytes, got %d", SM4KeySize, len(key))
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SM4GCM{aead: aead}, nil
}

// NonceSize 返回 GCM Nonce 长度（12 字节）。
func (g *SM4GCM) NonceSize() int { return g.aead.NonceSize() }

// Seal 使用随机 Nonce 加密 plaintext，返回 nonce 与 ciphertext‖tag。
func (g *SM4GCM) Seal(plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, g.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open 认证并解密。任何篡改都返回 ErrDecrypt。
func (g *SM4GCM) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != g.aead.NonceSize() {
		return nil, ErrDecrypt
	}
	pt, err := g.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
