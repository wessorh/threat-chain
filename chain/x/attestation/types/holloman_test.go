package types

import "testing"

func TestIsValidHollomanSignature(t *testing.T) {
	valid := []string{
		"00000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffff",
		"0123456789abcdef0123456789abcdef",
	}
	for _, s := range valid {
		if !IsValidHollomanSignature(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}

	invalid := []string{
		"",                                  // empty
		"0000000000000000000000000000000",   // 31 chars
		"000000000000000000000000000000000", // 33 chars
		"0000000000000000000000000000000g",  // non-hex
		"ABCDEF0123456789ABCDEF0123456789",  // uppercase
	}
	for _, s := range invalid {
		if IsValidHollomanSignature(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

func TestIsValidHammingMask(t *testing.T) {
	for _, d := range []int32{0, 1, 16, 128} {
		if !IsValidHammingMask(d) {
			t.Errorf("expected mask %d to be valid", d)
		}
	}
	for _, d := range []int32{-1, 129} {
		if IsValidHammingMask(d) {
			t.Errorf("expected mask %d to be invalid", d)
		}
	}
}

func TestHollomanHammingDistance(t *testing.T) {
	zero := "00000000000000000000000000000000"
	one := "00000000000000000000000000000001"
	allF := "ffffffffffffffffffffffffffffffff"

	if d, err := HollomanHammingDistance(zero, zero); err != nil || d != 0 {
		t.Errorf("identical: got (%d, %v), want (0, nil)", d, err)
	}
	if d, err := HollomanHammingDistance(zero, one); err != nil || d != 1 {
		t.Errorf("one bit: got (%d, %v), want (1, nil)", d, err)
	}
	if d, err := HollomanHammingDistance(zero, allF); err != nil || d != 128 {
		t.Errorf("all set: got (%d, %v), want (128, nil)", d, err)
	}
	if _, err := HollomanHammingDistance("bad", zero); err == nil {
		t.Errorf("expected error for invalid signature")
	}
}
