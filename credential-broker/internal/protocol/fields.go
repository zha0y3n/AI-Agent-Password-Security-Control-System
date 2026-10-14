package protocol

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// 与 agent_aa.models 中的约束类型一一对应。
var (
	reIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
	reHashHex    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reNonceHex   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reChallenge  = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	reQueryKey   = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
	reSigValue   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

const (
	maxTimestamp = 1<<63 - 1
	maxEpoch     = 1<<31 - 1
)

// object 逐字段读取一个已严格解析的 JSON 对象。
// 第一个错误会被保留，之后的读取全部变为空操作；done() 再检查未知字段。
type object struct {
	path string
	m    map[string]any
	seen map[string]bool
	err  *Error
}

func newObject(v any, path string) (*object, *Error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, Errorf(CodeSchema, "%s must be an object", path)
	}
	return &object{path: path, m: m, seen: map[string]bool{}}, nil
}

func (o *object) fail(name, format string, args ...any) {
	if o.err == nil {
		o.err = Errorf(CodeSchema, o.path+"."+name+": "+format, args...)
	}
}

// get 返回字段值；present=false 表示缺失。
func (o *object) get(name string) (v any, present bool) {
	o.seen[name] = true
	v, present = o.m[name]
	return v, present
}

func (o *object) required(name string) (any, bool) {
	v, ok := o.get(name)
	if !ok {
		o.fail(name, "field required")
	}
	return v, ok && o.err == nil
}

func (o *object) str(name string) string {
	v, ok := o.required(name)
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		o.fail(name, "must be a string")
	}
	return s
}

func (o *object) identifier(name string) string {
	s := o.str(name)
	if o.err == nil && !(len(s) >= 3 && len(s) <= 128 && reIdentifier.MatchString(s)) {
		o.fail(name, "invalid identifier")
	}
	return s
}

func (o *object) match(name string, re *regexp.Regexp) string {
	s := o.str(name)
	if o.err == nil && !re.MatchString(s) {
		o.fail(name, "does not match %s", re.String())
	}
	return s
}

// literal 对应 Pydantic 的 Literal[...] = default：缺失时取默认值，出现时必须相等。
func (o *object) literal(name, want string) string {
	v, ok := o.get(name)
	if !ok {
		return want
	}
	if s, isStr := v.(string); !isStr || s != want {
		o.fail(name, "must be %q", want)
	}
	return want
}

func (o *object) oneOf(name string, allowed ...string) string {
	s := o.str(name)
	if o.err != nil {
		return s
	}
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	o.fail(name, "must be one of %s", strings.Join(allowed, ", "))
	return s
}

func (o *object) integer(name string, min, max int64) int64 {
	v, ok := o.required(name)
	if !ok {
		return 0
	}
	n, isInt := v.(int64)
	if !isInt {
		o.fail(name, "must be an integer")
		return 0
	}
	if n < min || n > max {
		o.fail(name, "must be between %d and %d", min, max)
	}
	return n
}

// done 拒绝未读取过的字段（对应 extra="forbid"），返回第一个错误。
func (o *object) done() *Error {
	if o.err != nil {
		return o.err
	}
	var unknown []string
	for k := range o.m {
		if !o.seen[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return Errorf(CodeSchema, "%s: unknown fields %q", o.path, unknown)
	}
	return nil
}

// sub 读取嵌套对象并交给 decode 处理。
func sub[T any](o *object, name string, decode func(any, string) (T, *Error)) T {
	var zero T
	v, ok := o.required(name)
	if !ok {
		return zero
	}
	out, err := decode(v, o.path+"."+name)
	if err != nil && o.err == nil {
		o.err = err
	}
	return out
}

func validPath(p string) bool {
	n := utf8.RuneCountInString(p)
	if n < 1 || n > 1024 || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// decodeSignatureValue 与 Python base64.urlsafe_b64decode(value + padding) 行为一致：
// 不要求末尾填充位为零。
func decodeSignatureValue(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
