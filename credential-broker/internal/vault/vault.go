// Package vault 使用 SM4-GCM 加密保存长期业务 Credential。
//
// AAD 绑定 credential_id、provider、credential_epoch，
// 密文被挪到其他 Credential 或其他 Epoch 下都无法解密。
package vault

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
)

// AADDomain 是 AAD 的域分隔前缀。
const AADDomain = "ACG-VAULT-v1"

// Vault 持有主密钥 K_V。主密钥只来自配置，不入库、不入日志。
type Vault struct {
	aead  *crypto.SM4GCM
	opens atomic.Uint64
}

// New 用 16 字节主密钥创建 Vault。
func New(masterKey []byte) (*Vault, error) {
	aead, err := crypto.NewSM4GCM(masterKey)
	if err != nil {
		return nil, err
	}
	return &Vault{aead: aead}, nil
}

// AAD 构造：
// "ACG-VAULT-v1" ‖ u32be(len(id)) ‖ id ‖ u32be(len(provider)) ‖ provider ‖ u64be(epoch)。
// 长度前缀避免 "a"+"bc" 与 "ab"+"c" 产生相同字节。
func AAD(credentialID, provider string, epoch int64) []byte {
	var buf bytes.Buffer
	buf.WriteString(AADDomain)
	binary.Write(&buf, binary.BigEndian, uint32(len(credentialID)))
	buf.WriteString(credentialID)
	binary.Write(&buf, binary.BigEndian, uint32(len(provider)))
	buf.WriteString(provider)
	binary.Write(&buf, binary.BigEndian, uint64(epoch))
	return buf.Bytes()
}

// Seal 加密 Credential 明文。
func (v *Vault) Seal(credentialID, provider string, epoch int64, s secret.Secret) (nonce, ciphertext []byte, err error) {
	return v.aead.Seal(s.Bytes(), AAD(credentialID, provider, epoch))
}

// Open 解密 Credential。调用方用完后应调用 Wipe()。
func (v *Vault) Open(credentialID, provider string, epoch int64, nonce, ciphertext []byte) (secret.Secret, error) {
	v.opens.Add(1)
	pt, err := v.aead.Open(nonce, ciphertext, AAD(credentialID, provider, epoch))
	if err != nil {
		return nil, err
	}
	return secret.Secret(pt), nil
}

// Opens 返回累计解密次数，供测试和实验断言“拒绝路径未读取 Credential”。
func (v *Vault) Opens() uint64 { return v.opens.Load() }
