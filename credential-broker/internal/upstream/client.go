package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
)

// ErrUnsupported 表示 service / operation 组合不受支持。
var ErrUnsupported = errors.New("unsupported service operation")

// Call 描述一次上游业务调用。阶段二由 A 的 AgentRequest 映射而来。
type Call struct {
	Service     string            // git / db
	Operation   string            // read_file / write_file / query / update
	Resource    string            // repo 名或 db 名
	Args        map[string]string // path / content / key / value
	CapID       string            // 作为下游幂等键
	RequestHash string
}

// Response 是上游返回。
type Response struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Replay bool            `json:"replay"`
}

// Client 由 Broker 使用，携带 Credential 调用受保护服务。
type Client struct {
	base  string
	http  *http.Client
	calls atomic.Uint64
}

// NewClient 创建 Client。
func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{base: baseURL, http: &http.Client{Timeout: timeout}}
}

// Calls 返回累计调用次数，供测试断言“拒绝路径未调用上游”。
func (c *Client) Calls() uint64 { return c.calls.Load() }

// Do 携带 cred 执行调用。cred 只出现在 Authorization 头中，不会进入日志或返回值。
func (c *Client) Do(ctx context.Context, call Call, cred secret.Secret) (*Response, error) {
	method, path, body, err := route(call)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(cred.Bytes()))
	if call.CapID != "" {
		req.Header.Set(HeaderIdempotencyKey, call.CapID)
		req.Header.Set(HeaderRequestHash, call.RequestHash)
	}

	c.calls.Add(1)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	if !json.Valid(raw) {
		raw, _ = json.Marshal(string(raw))
	}
	return &Response{Status: resp.StatusCode, Body: raw, Replay: resp.Header.Get(HeaderReplay) == "true"}, nil
}

func route(c Call) (method, path string, body any, err error) {
	res := url.PathEscape(c.Resource)
	switch c.Service + "/" + c.Operation {
	case "git/read_file":
		return http.MethodGet, "/git/repos/" + res + "/files/" + escapePath(c.Args["path"]), nil, nil
	case "git/write_file":
		return http.MethodPut, "/git/repos/" + res + "/files/" + escapePath(c.Args["path"]),
			map[string]string{"content": c.Args["content"]}, nil
	case "db/query":
		return http.MethodPost, "/db/" + res + "/query", map[string]string{"key": c.Args["key"]}, nil
	case "db/update":
		return http.MethodPost, "/db/" + res + "/update",
			map[string]string{"key": c.Args["key"], "value": c.Args["value"]}, nil
	}
	return "", "", nil, fmt.Errorf("%w: %s/%s", ErrUnsupported, c.Service, c.Operation)
}

// escapePath 转义路径中的特殊字符，保留 "/" 分隔。
func escapePath(p string) string {
	u := url.URL{Path: p}
	return u.EscapedPath()
}
