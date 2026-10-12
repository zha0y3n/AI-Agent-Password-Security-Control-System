package crypto

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm4"
)

func TestSM3StandardVectors(t *testing.T) {
	// GM/T 0004-2012 附录 A
	cases := []struct{ in, want string }{
		{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{strings.Repeat("abcd", 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	}
	for _, c := range cases {
		if got := SM3Hex([]byte(c.in)); got != c.want {
			t.Errorf("SM3(%q) = %s, want %s", c.in, got, c.want)
		}
	}
	if !bytes.Equal(SM3Concat([]byte("ab"), []byte("c")), SM3([]byte("abc"))) {
		t.Error("SM3Concat should equal SM3 of concatenation")
	}
}

func TestSM4StandardVector(t *testing.T) {
	// GM/T 0002-2012 附录 A 示例 1
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	want, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 16)
	block.Encrypt(got, key)
	if !bytes.Equal(got, want) {
		t.Fatalf("SM4 = %x, want %x", got, want)
	}
}

func TestSM4GCMRoundTripAndTamper(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, SM4KeySize)
	g, err := NewSM4GCM(key)
	if err != nil {
		t.Fatal(err)
	}
	pt, aad := []byte("ghp_long_term_token"), []byte("git-prod|github|17")
	nonce, ct, err := g.Seal(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Open(nonce, ct, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %v", err)
	}

	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 1
		return c
	}
	if _, err := g.Open(nonce, flip(ct, 0), aad); err != ErrDecrypt {
		t.Error("tampered ciphertext must fail")
	}
	if _, err := g.Open(nonce, flip(ct, len(ct)-1), aad); err != ErrDecrypt {
		t.Error("tampered tag must fail")
	}
	if _, err := g.Open(flip(nonce, 0), ct, aad); err != ErrDecrypt {
		t.Error("tampered nonce must fail")
	}
	if _, err := g.Open(nonce, ct, []byte("git-prod|github|18")); err != ErrDecrypt {
		t.Error("tampered AAD must fail")
	}
	other, _ := NewSM4GCM(bytes.Repeat([]byte{0x43}, SM4KeySize))
	if _, err := other.Open(nonce, ct, aad); err != ErrDecrypt {
		t.Error("wrong key must fail")
	}
	if _, err := NewSM4GCM([]byte("short")); err == nil {
		t.Error("short key must be rejected")
	}
}

func TestSM2SignVerify(t *testing.T) {
	s, err := GenerateSM2Signer()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("checkpoint")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !SM2Verify(s.PublicKey(), msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if SM2Verify(s.PublicKey(), []byte("checkpoinT"), sig) {
		t.Error("tampered message accepted")
	}
	bad := bytes.Clone(sig)
	bad[len(bad)-1] ^= 1
	if SM2Verify(s.PublicKey(), msg, bad) {
		t.Error("tampered signature accepted")
	}
	other, _ := GenerateSM2Signer()
	if SM2Verify(other.PublicKey(), msg, sig) {
		t.Error("wrong public key accepted")
	}

	pub, err := ParseSM2PublicKeyHex(s.PublicKeyHex())
	if err != nil {
		t.Fatal(err)
	}
	if !SM2Verify(pub, msg, sig) {
		t.Error("public key hex round trip failed")
	}
}

func TestLoadOrCreateSM2Signer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "broker.key")
	s1, created, err := LoadOrCreateSM2Signer(path)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	s2, created, err := LoadOrCreateSM2Signer(path)
	if err != nil || created {
		t.Fatalf("load: created=%v err=%v", created, err)
	}
	if s1.PublicKeyHex() != s2.PublicKeyHex() {
		t.Error("reloaded key differs")
	}
}
