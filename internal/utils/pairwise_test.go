package utils

import "testing"

func TestPairwiseSub(t *testing.T) {
	s1 := PairwiseSub("example.com", 42, "salt")
	s2 := PairwiseSub("example.com", 42, "salt")
	if s1 != s2 {
		t.Fatalf("pairwise not deterministic")
	}
	s3 := PairwiseSub("another.com", 42, "salt")
	if s1 == s3 {
		t.Fatalf("pairwise should differ by sector")
	}
}
