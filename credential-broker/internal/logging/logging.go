// Package logging 提供默认脱敏的结构化日志。
//
// 第一道防线是 secret.Secret 类型自带 [REDACTED]；
// 这里是第二道：属性名命中敏感词时，无论值是什么类型都替换为 [REDACTED]。
package logging

import (
	"io"
	"log/slog"
	"strings"
)

var sensitive = []string{"secret", "password", "passwd", "token", "authorization", "private", "vault_key", "plaintext", "credential_value"}

// IsSensitive 判断属性名是否敏感。
func IsSensitive(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitive {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// New 创建 JSON 日志器。level 取 debug / info / warn / error。
func New(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: lv,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if IsSensitive(a.Key) {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	}))
}
