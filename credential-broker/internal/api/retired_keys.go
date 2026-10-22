package api

import (
	"crypto/ecdsa"
	"fmt"
	"os"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

// LoadRetiredKeys 读取 Broker 以前用过的 Receipt 签名公钥（A 的 KeyRegistryDocument 格式），
// 与当前公钥一起在 /v1/broker/key-registry 发布：
//
//	status=ACTIVE  已轮换下线，但在 [not_before, not_after) 内签发的旧回执仍可验证
//	status=REVOKED 已泄露，验证方拒绝该公钥签的所有回执
//
// 每条记录必须是本 Broker 的 RECEIPT_SIGNING 公钥，且 key_id 与公钥都不能与当前密钥相同；
// 任何一条不合格都拒绝启动（fail closed）。返回的记录原样发布。
func LoadRetiredKeys(path, brokerID, currentKeyID string, current *ecdsa.PublicKey) ([]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	reg, err := protocol.ParseKeyRegistry(data)
	if err != nil {
		return nil, err
	}
	for _, rec := range reg.Records() {
		switch {
		case rec.Purpose != protocol.KeyPurposeReceipt:
			return nil, fmt.Errorf("retired key %s: purpose must be %s", rec.KeyID, protocol.KeyPurposeReceipt)
		case rec.SubjectID != brokerID:
			return nil, fmt.Errorf("retired key %s: subject must be %s", rec.KeyID, brokerID)
		case rec.KeyID == currentKeyID:
			return nil, fmt.Errorf("retired key %s: key id is the current BROKER_KEY_ID", rec.KeyID)
		case rec.PublicKey.Equal(current):
			return nil, fmt.Errorf("retired key %s: public key is the current signing key", rec.KeyID)
		}
	}
	// ParseKeyRegistry 已严格校验；这里再取原始记录，以便原样发布（含 PEM 文本）。
	v, err := canonical.Parse(data)
	if err != nil {
		return nil, err
	}
	return v.(map[string]any)["keys"].([]any), nil
}
