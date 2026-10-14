package verifier

import (
	"fmt"
	"strings"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
)

// MapRequest 把已验证的 AgentRequest 精确映射为上游调用。
//
// Broker 只执行与签名请求逐字段一致的动作：method、path、resource、query、body
// 必须共同指向同一个对象，任何多余或含糊的部分都拒绝，而不是“尽量理解”。
//
//	git/read_file   GET  /repos/{repo}/files/{path}  resource=repo/{repo}  body=null
//	git/write_file  PUT  /repos/{repo}/files/{path}  resource=repo/{repo}  body={"content": str}
//	db/query        POST /db/{db}/query              resource=db/{db}      body={"key": str}
//	db/update       POST /db/{db}/update             resource=db/{db}      body={"key": str, "value": str}
func MapRequest(r *protocol.AgentRequest) (upstream.Call, error) {
	if len(r.Query) != 0 {
		return upstream.Call{}, fmt.Errorf("query parameters are not supported for %s/%s", r.Service, r.Operation)
	}
	call := upstream.Call{Service: r.Service, Operation: r.Operation}
	switch r.Service + "/" + r.Operation {
	case "git/read_file", "git/write_file":
		method, body := "GET", []string(nil)
		if r.Operation == "write_file" {
			method, body = "PUT", []string{"content"}
		}
		repo, err := resourceName(r.Resource, "repo/")
		if err != nil {
			return upstream.Call{}, err
		}
		file, ok := strings.CutPrefix(r.Path, "/repos/"+repo+"/files/")
		if !ok || !validFilePath(file) {
			return upstream.Call{}, fmt.Errorf("path must be /repos/%s/files/<file>", repo)
		}
		args, err := bodyArgs(r, method, body)
		if err != nil {
			return upstream.Call{}, err
		}
		args["path"] = file
		call.Resource, call.Args = repo, args
	case "db/query", "db/update":
		fields := []string{"key"}
		if r.Operation == "update" {
			fields = []string{"key", "value"}
		}
		db, err := resourceName(r.Resource, "db/")
		if err != nil {
			return upstream.Call{}, err
		}
		if r.Path != "/db/"+db+"/"+r.Operation {
			return upstream.Call{}, fmt.Errorf("path must be /db/%s/%s", db, r.Operation)
		}
		args, err := bodyArgs(r, "POST", fields)
		if err != nil {
			return upstream.Call{}, err
		}
		call.Resource, call.Args = db, args
	default:
		return upstream.Call{}, fmt.Errorf("unsupported service operation %s/%s", r.Service, r.Operation)
	}
	return call, nil
}

// resourceName 取出 "repo/<name>" / "db/<name>" 中的 name，name 不得再含 "/"。
func resourceName(resource, prefix string) (string, error) {
	name, ok := strings.CutPrefix(resource, prefix)
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("resource must be %s<name>", prefix)
	}
	return name, nil
}

// validFilePath 要求非空且没有空段（协议层已拒绝 "." / ".." 段与反斜杠）。
func validFilePath(p string) bool {
	if p == "" {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			return false
		}
	}
	return true
}

// bodyArgs 校验 method，并要求 body 恰好是由 fields 组成的字符串对象（fields 为空时 body 必须为 null）。
func bodyArgs(r *protocol.AgentRequest, method string, fields []string) (map[string]string, error) {
	if r.Method != method {
		return nil, fmt.Errorf("%s/%s requires method %s", r.Service, r.Operation, method)
	}
	args := map[string]string{}
	if len(fields) == 0 {
		if r.Body != nil {
			return nil, fmt.Errorf("%s/%s does not take a body", r.Service, r.Operation)
		}
		return args, nil
	}
	obj, ok := r.Body.(map[string]any)
	if !ok || len(obj) != len(fields) {
		return nil, fmt.Errorf("body must be an object with exactly %v", fields)
	}
	for _, f := range fields {
		s, ok := obj[f].(string)
		if !ok {
			return nil, fmt.Errorf("body.%s must be a string", f)
		}
		args[f] = s
	}
	return args, nil
}
