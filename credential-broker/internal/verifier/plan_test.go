package verifier_test

import (
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

func req(service, resource, op, method, path string, body any) *protocol.AgentRequest {
	return &protocol.AgentRequest{Service: service, Resource: resource, Operation: op,
		Method: method, Path: path, Query: map[string]any{}, Body: body}
}

func TestMapRequestSupported(t *testing.T) {
	for name, c := range map[string]struct {
		r        *protocol.AgentRequest
		resource string
		args     map[string]string
	}{
		"git_read": {req("git", "repo/course-project", "read_file", "GET", "/repos/course-project/files/docs/a.md", nil),
			"course-project", map[string]string{"path": "docs/a.md"}},
		"git_write": {req("git", "repo/repo-A", "write_file", "PUT", "/repos/repo-A/files/out.txt", map[string]any{"content": "x"}),
			"repo-A", map[string]string{"path": "out.txt", "content": "x"}},
		"db_query": {req("db", "db/app-db", "query", "POST", "/db/app-db/query", map[string]any{"key": "user:1"}),
			"app-db", map[string]string{"key": "user:1"}},
		"db_update": {req("db", "db/app-db", "update", "POST", "/db/app-db/update", map[string]any{"key": "k", "value": "v"}),
			"app-db", map[string]string{"key": "k", "value": "v"}},
	} {
		call, err := verifier.MapRequest(c.r)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if call.Resource != c.resource || len(call.Args) != len(c.args) {
			t.Errorf("%s: got %+v", name, call)
		}
		for k, v := range c.args {
			if call.Args[k] != v {
				t.Errorf("%s: arg %s = %q want %q", name, k, call.Args[k], v)
			}
		}
	}
}

func TestMapRequestRejects(t *testing.T) {
	withQuery := req("git", "repo/r1", "read_file", "GET", "/repos/r1/files/a", nil)
	withQuery.Query = map[string]any{"ref": "main"}
	for name, r := range map[string]*protocol.AgentRequest{
		"unknown_operation":     req("git", "repo/r1", "delete_file", "DELETE", "/repos/r1/files/a", nil),
		"unknown_service":       req("s3", "bucket/b", "read_file", "GET", "/repos/b/files/a", nil),
		"method_mismatch":       req("git", "repo/r1", "read_file", "POST", "/repos/r1/files/a", nil),
		"path_other_repo":       req("git", "repo/r1", "read_file", "GET", "/repos/r2/files/a", nil),
		"resource_prefix":       req("git", "db/r1", "read_file", "GET", "/repos/r1/files/a", nil),
		"resource_nested":       req("git", "repo/r1/x", "read_file", "GET", "/repos/r1/x/files/a", nil),
		"empty_file":            req("git", "repo/r1", "read_file", "GET", "/repos/r1/files/", nil),
		"empty_segment":         req("git", "repo/r1", "read_file", "GET", "/repos/r1/files/a//b", nil),
		"read_with_body":        req("git", "repo/r1", "read_file", "GET", "/repos/r1/files/a", map[string]any{"content": "x"}),
		"write_no_body":         req("git", "repo/r1", "write_file", "PUT", "/repos/r1/files/a", nil),
		"write_extra_field":     req("git", "repo/r1", "write_file", "PUT", "/repos/r1/files/a", map[string]any{"content": "x", "mode": "755"}),
		"write_non_string":      req("git", "repo/r1", "write_file", "PUT", "/repos/r1/files/a", map[string]any{"content": int64(1)}),
		"db_wrong_path":         req("db", "db/app-db", "query", "POST", "/db/other/query", map[string]any{"key": "k"}),
		"db_update_missing_val": req("db", "db/app-db", "update", "POST", "/db/app-db/update", map[string]any{"key": "k"}),
		"query_params":          withQuery,
	} {
		if _, err := verifier.MapRequest(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
