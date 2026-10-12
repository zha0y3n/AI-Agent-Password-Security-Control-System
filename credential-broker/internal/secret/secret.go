// Package secret 提供不会被意外打印或序列化的敏感字节类型。
package secret

import (
	"encoding/json"
	"log/slog"
)

const redacted = "[REDACTED]"

// Secret 保存 Credential 明文。
// String / LogValue / MarshalJSON 均输出 [REDACTED]，
// 防止通过 fmt、slog 或 JSON 响应泄露；只能通过 Bytes() 显式取出。
type Secret []byte

// Bytes 显式取出明文。仅允许在 Vault 加密与上游调用处使用。
func (s Secret) Bytes() []byte { return s }

// Wipe 将明文缓冲区清零。
func (s Secret) Wipe() {
	for i := range s {
		s[i] = 0
	}
}

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// UnmarshalJSON 从 JSON 字符串读取明文（用于管理接口录入 Credential）。
func (s *Secret) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	*s = Secret(str)
	return nil
}
