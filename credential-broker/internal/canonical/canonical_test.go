package canonical_test

import (
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
)

const vectorPath = "../../../shared/test-vectors/sm2-sm3-v1.json"

func loadVector(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.Parse(raw)
	if err != nil {
		t.Fatalf("parse vector file: %v", err)
	}
	return v.(map[string]any)
}

// 四段 canonical bytes 必须与 A（Python）生成的向量逐字节一致。
func TestSharedVectorCanonicalBytes(t *testing.T) {
	v := loadVector(t)
	hp := v["holder_proof_vector"].(map[string]any)
	rc := v["receipt_vector"].(map[string]any)
	cases := []struct {
		name string
		obj  any
		hex  any
	}{
		{"request", v["request"], v["request_canonical_hex"]},
		{"capability_body", v["capability_body"], v["capability_canonical_hex"]},
		{"holder_proof_body", hp["body"], hp["canonical_hex"]},
		{"receipt_body", rc["body"], rc["canonical_hex"]},
	}
	for _, c := range cases {
		got, err := canonical.Marshal(c.obj)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if hex.EncodeToString(got) != c.hex.(string) {
			t.Errorf("%s canonical bytes differ:\n got %s\nwant %s", c.name, hex.EncodeToString(got), c.hex)
		}
	}
}

// 期望值由 agent_aa.canonical.canonical_json 生成。
func TestMarshalMatchesPython(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{map[string]any{"b": int64(1), "a": []any{true, false, nil}, "é": "x", "Z": ""},
			`{"Z":"","a":[true,false,null],"b":1,"é":"x"}`},
		{"ctl:\x00\x01\x1f\x7f\b\f\n\r\t\"\\/<>&  😀",
			`"ctl:\u0000\u0001\u001f` + "\x7f" + `\b\f\n\r\t\"\\/<>&` + "  😀" + `"`},
		{int64(-9223372036854775808), `-9223372036854775808`},
		// code point 序：U+FFFF 排在 U+1F600 之前（不是 UTF-16 序）
		{map[string]any{"😀": int64(1), "￿": int64(2), "a": int64(3)}, `{"a":3,"` + "￿" + `":2,"😀":1}`},
	}
	for _, c := range cases {
		got, err := canonical.Marshal(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("Marshal(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
}

func TestParseAccepts(t *testing.T) {
	v, err := canonical.Parse([]byte(" {\"a\" : \"\\ud83d\\ude00\\u00e9\\/\", \"n\": -0}\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if m["a"] != "😀é/" || m["n"] != int64(0) {
		t.Fatalf("unexpected parse result: %#v", m)
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"a":2}`,
		`{"a":1,"a":2}`, // 转义后重复
		`1.0`, `1e2`, `1E2`, `-1.5`,
		`NaN`, `Infinity`, `-Infinity`,
		`9223372036854775808`, `-9223372036854775809`,
		`"\ud800"`, `"\udc00"`, `"\ud83dA"`,
		`01`, `-01`, `-`, `+1`,
		`[1,]`, `{"a":1,}`, `{a:1}`, `'a'`,
		"\"a\x01\"", "\"a\nb\"",
		`{} x`, `{}{}`, ``, `   `,
		"\xef\xbb\xbf{}", // BOM
		"\"\xff\"",       // 非法 UTF-8
		`"\x"`, `"\u12"`, `"\u12G4"`, `"abc`,
		`tru`, `nul`, `True`,
	} {
		if _, err := canonical.Parse([]byte(in)); !errors.Is(err, canonical.ErrCanonical) {
			t.Errorf("Parse(%q) = %v, want ErrCanonical", in, err)
		}
	}
}

func TestParseDepthLimit(t *testing.T) {
	deep := make([]byte, 0, 2*(canonical.MaxDepth+2))
	for i := 0; i < canonical.MaxDepth+2; i++ {
		deep = append(deep, '[')
	}
	for i := 0; i < canonical.MaxDepth+2; i++ {
		deep = append(deep, ']')
	}
	if _, err := canonical.Parse(deep); !errors.Is(err, canonical.ErrCanonical) {
		t.Fatalf("deep nesting accepted: %v", err)
	}
}

func TestMarshalRejects(t *testing.T) {
	for _, in := range []any{1.5, float32(1), "\xff", map[string]any{"\xff": int64(1)}, []any{struct{}{}}} {
		if _, err := canonical.Marshal(in); !errors.Is(err, canonical.ErrCanonical) {
			t.Errorf("Marshal(%#v) = %v, want ErrCanonical", in, err)
		}
	}
}

// 解析后再编码应是幂等的：规范字节再解析、再编码不变。
func TestRoundTrip(t *testing.T) {
	in := []byte(`{"z":[1,"é",{"b":null,"a":false}],"a":"\t"}`)
	v, err := canonical.Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := canonical.Marshal(v)
	v2, err := canonical.Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := canonical.Marshal(v2)
	if string(first) != string(second) || string(first) != `{"a":"\t","z":[1,"é",{"a":false,"b":null}]}` {
		t.Fatalf("round trip mismatch: %s / %s", first, second)
	}
}
