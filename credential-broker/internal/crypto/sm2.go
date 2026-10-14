package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// SM2UserID 是协议固定的 SM2 用户标识（docs/crypto-protocol.md §3.2），
// 签名与验签都显式传入，不依赖库默认值。
const SM2UserID = "1234567812345678"

// SM2Signer 持有 SM2 私钥，签名格式为 ASN.1 DER(r, s)，
// 签名过程包含 Z 值预处理（SM3(Z‖M)）。
type SM2Signer struct {
	priv *sm2.PrivateKey
}

// GenerateSM2Signer 生成新的 SM2 密钥对。
func GenerateSM2Signer() (*SM2Signer, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &SM2Signer{priv: priv}, nil
}

// SM2SignerFromHex 从 32 字节私钥的十六进制恢复签名者。
func SM2SignerFromHex(s string) (*SM2Signer, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("sm2: invalid private key hex: %w", err)
	}
	priv, err := sm2.NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("sm2: invalid private key: %w", err)
	}
	return &SM2Signer{priv: priv}, nil
}

// LoadOrCreateSM2Signer 从文件加载私钥；文件不存在时生成新密钥并以 0600 权限写入。
// created 表示本次是否新生成。
func LoadOrCreateSM2Signer(path string) (s *SM2Signer, created bool, err error) {
	data, err := os.ReadFile(path)
	if err == nil {
		s, err = SM2SignerFromHex(string(data))
		return s, false, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	if s, err = GenerateSM2Signer(); err != nil {
		return nil, false, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	if err = os.WriteFile(path, []byte(s.PrivateKeyHex()), 0o600); err != nil {
		return nil, false, err
	}
	return s, true, nil
}

// Sign 对消息 msg 做 SM2 签名（内部计算 SM3(Z‖msg)）。
func (s *SM2Signer) Sign(msg []byte) ([]byte, error) {
	return s.priv.SignWithSM2(rand.Reader, []byte(SM2UserID), msg)
}

// PublicKey 返回公钥。
func (s *SM2Signer) PublicKey() *ecdsa.PublicKey { return &s.priv.PublicKey }

// PublicKeyHex 返回未压缩公钥 04‖X‖Y 的十六进制。
func (s *SM2Signer) PublicKeyHex() string {
	return hex.EncodeToString(MarshalSM2PublicKey(&s.priv.PublicKey))
}

// PrivateKeyHex 返回 32 字节私钥的十六进制。仅用于密钥文件持久化，禁止写入日志。
func (s *SM2Signer) PrivateKeyHex() string {
	d := make([]byte, 32)
	s.priv.D.FillBytes(d)
	return hex.EncodeToString(d)
}

// MarshalSM2PublicKey 编码为未压缩点 04‖X‖Y（65 字节）。
func MarshalSM2PublicKey(pub *ecdsa.PublicKey) []byte {
	out := make([]byte, 65)
	out[0] = 0x04
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:65])
	return out
}

// ParseSM2PublicKey 解析未压缩点 04‖X‖Y。
func ParseSM2PublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	return sm2.NewPublicKey(raw)
}

// ParseSM2PublicKeyHex 解析十六进制的未压缩公钥。
func ParseSM2PublicKeyHex(s string) (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sm2: invalid public key hex: %w", err)
	}
	return ParseSM2PublicKey(raw)
}

// SM2Verify 用协议 UID 验证 DER 签名。
func SM2Verify(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	return sm2.VerifyASN1WithSM2(pub, []byte(SM2UserID), msg, sig)
}

// ParseSM2PublicKeyPEM 解析 PEM SubjectPublicKeyInfo 格式的 SM2 公钥（A 的密钥注册表格式）。
// 只接受恰好一个 PUBLIC KEY 块，且曲线必须是 SM2。
func ParseSM2PublicKeyPEM(data string) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(data))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, errors.New("sm2: expected a single PEM PUBLIC KEY block")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("sm2: unexpected data after PEM block")
	}
	parsed, err := smx509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sm2: invalid SubjectPublicKeyInfo: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != sm2.P256() {
		return nil, errors.New("sm2: public key is not on the SM2 curve")
	}
	return pub, nil
}

// MarshalSM2PublicKeyPEM 把 SM2 公钥编码为 PEM SubjectPublicKeyInfo。
func MarshalSM2PublicKeyPEM(pub *ecdsa.PublicKey) (string, error) {
	der, err := smx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}
