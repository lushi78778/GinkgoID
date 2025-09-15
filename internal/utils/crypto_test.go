package utils

import "testing"

func TestATHashAndCHash(t *testing.T) {
	at := "access-token-example"
	ch := "code-example"
	h1 := ATHash(at)
	h2 := ATHash(at)
	if h1 != h2 {
		t.Fatalf("ATHash not deterministic")
	}
	if h1 == "" {
		t.Fatalf("ATHash empty")
	}
	c1 := CHash(ch)
	c2 := CHash(ch)
	if c1 != c2 {
		t.Fatalf("CHash not deterministic")
	}
	if len(h1) == 0 || len(c1) == 0 {
		t.Fatalf("hash length zero")
	}
}
