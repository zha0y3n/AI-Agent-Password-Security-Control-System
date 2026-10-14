// Package canonical 实现 ZTCANON-JSON-v1（见 docs/crypto-protocol.md §1），
// 与 A 的 agent_aa.canonical 字节级一致。
//
// 值模型只有六种：nil、bool、int64、string、[]any、map[string]any。
// Parse 严格解析外部输入；Marshal 把值树编码为唯一的规范字节。
// 不使用 encoding/json：它会接受重复 key、把非法 UTF-8 / 孤立代理替换成 U+FFFD、
// 转义 <>&、U+2028/2029，均与协议定义不符。
package canonical

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrCanonical 是所有规范化 / 严格解析错误的哨兵，便于调用方映射为 CANONICALIZATION_ERROR。
var ErrCanonical = errors.New("canonicalization error")

// MaxDepth 限制嵌套深度，防止恶意输入耗尽栈。协议对象本身很浅。
const MaxDepth = 64

func errorf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCanonical, fmt.Sprintf(format, args...))
}

// Parse 严格解析 JSON：UTF-8 无 BOM，拒绝重复 key、浮点、NaN/Infinity、
// 超出 int64 的整数、孤立 UTF-16 代理、字符串内控制字符和尾随数据。
func Parse(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errorf("input is not valid UTF-8")
	}
	p := &parser{s: string(data)}
	p.skipSpace()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.i != len(p.s) {
		return nil, errorf("extra data at offset %d", p.i)
	}
	return v, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) skipSpace() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, errorf("nesting deeper than %d", MaxDepth)
	}
	if p.i >= len(p.s) {
		return nil, errorf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.string()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	default:
		return nil, errorf("unexpected character at offset %d", p.i)
	}
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // '{'
	obj := map[string]any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, errorf("expected object key at offset %d", p.i)
		}
		k, err := p.string()
		if err != nil {
			return nil, err
		}
		key := k.(string)
		if _, dup := obj[key]; dup {
			return nil, errorf("duplicate JSON object key: %q", key)
		}
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, errorf("expected ':' at offset %d", p.i)
		}
		p.i++
		p.skipSpace()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		obj[key] = v
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, errorf("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return obj, nil
		default:
			return nil, errorf("expected ',' or '}' at offset %d", p.i)
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	p.i++ // '['
	arr := []any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		p.skipSpace()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, errorf("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, errorf("expected ',' or ']' at offset %d", p.i)
		}
	}
}

// number 只接受 JSON 整数语法 -?(0|[1-9][0-9]*)；出现小数或指数即视为浮点并拒绝。
func (p *parser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	switch {
	case p.i < len(p.s) && p.s[p.i] == '0':
		p.i++
	case p.i < len(p.s) && p.s[p.i] >= '1' && p.s[p.i] <= '9':
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
	default:
		return nil, errorf("invalid number at offset %d", start)
	}
	if p.i < len(p.s) {
		switch p.s[p.i] {
		case '.', 'e', 'E':
			return nil, errorf("floating-point JSON numbers are forbidden")
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return nil, errorf("invalid number at offset %d", start) // 前导零
		}
	}
	n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
	if err != nil {
		return nil, errorf("JSON integer is outside int64")
	}
	return n, nil
}

func (p *parser) string() (any, error) {
	p.i++ // '"'
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return nil, errorf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return nil, errorf("control character in string at offset %d", p.i)
		case c == '\\':
			r, err := p.escape()
			if err != nil {
				return nil, err
			}
			b.WriteRune(r)
		default:
			// 输入已整体校验为合法 UTF-8，可直接按字节复制。
			b.WriteByte(c)
			p.i++
		}
	}
}

func (p *parser) escape() (rune, error) {
	if p.i+1 >= len(p.s) {
		return 0, errorf("unterminated escape")
	}
	c := p.s[p.i+1]
	p.i += 2
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		r1, err := p.hex4()
		if err != nil {
			return 0, err
		}
		if !utf16.IsSurrogate(r1) {
			return r1, nil
		}
		// 必须是高代理 + 低代理的完整对，否则是非法 Unicode。
		if r1 < 0xDC00 && strings.HasPrefix(p.s[p.i:], `\u`) {
			p.i += 2
			r2, err := p.hex4()
			if err != nil {
				return 0, err
			}
			if r := utf16.DecodeRune(r1, r2); r != utf8.RuneError {
				return r, nil
			}
		}
		return 0, errorf("lone UTF-16 surrogate in string")
	default:
		return 0, errorf("invalid escape \\%c", c)
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, errorf("truncated \\u escape")
	}
	n, err := strconv.ParseUint(p.s[p.i:p.i+4], 16, 32)
	if err != nil {
		return 0, errorf("invalid \\u escape")
	}
	p.i += 4
	return rune(n), nil
}

// Marshal 返回值树的 ZTCANON-JSON-v1 字节：key 按 code point 升序、无空白、
// 只转义 `"`、`\` 和 U+0000–U+001F（与 Python json.dumps(ensure_ascii=False) 相同）。
func Marshal(v any) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v, 0); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v any, depth int) error {
	if depth > MaxDepth {
		return errorf("nesting deeper than %d", MaxDepth)
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case string:
		return encodeString(b, x)
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, item, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeString(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// 合法 UTF-8 下字节序等价于 code point 序。
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := encode(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return errorf("unsupported value type %T", v)
	}
	return nil
}

const hexDigits = "0123456789abcdef"

func encodeString(b *strings.Builder, s string) error {
	if !utf8.ValidString(s) {
		return errorf("string is not valid UTF-8")
	}
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
