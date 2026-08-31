package types

import "testing"

func TestIsValidHollomanSignature(t *testing.T) {
	valid := []string{
		"h.002354560008424a0000030500000000",
		"k.003f8d51000a71760000060a00000000",
		"0.0123456789abcdef0123456789abcdef",
		"a.00000000000000000000000000000000",
	}
	for _, s := range valid {
		if !IsValidHollomanSignature(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}

	invalid := []string{
		"",                                     // empty
		"00000000000000000000000000000000",     // bare 32-hex, no order prefix
		"ffffffffffffffffffffffffffffffff",     // bare 32-hex, no order prefix
		"h.002354560008424a000003050000000",    // 31 hex after order
		"h.002354560008424a0000030500000000g",  // non-hex after order
		"H.002354560008424a0000030500000000",   // uppercase order
		"hh.002354560008424a0000030500000000",  // 2-char order
		"h.ABCDEF0123456789abcdef0123456789",   // uppercase hex after order
		"h002354560008424a0000030500000000",    // missing dot
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
	zero := "h.00000000000000000000000000000000"
	one := "h.00000000000000000000000000000001"
	allF := "h.ffffffffffffffffffffffffffffffff"

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

func TestHollomanHammingDistanceOrdered(t *testing.T) {
	a := "h.00000000000000000000000000000000"
	b := "h.00000000000000000000000000000001"
	other := "j.00000000000000000000000000000000"

	if d, err := HollomanHammingDistance(a, b); err != nil || d != 1 {
		t.Errorf("same order one bit: got (%d, %v), want (1, nil)", d, err)
	}
	if d, err := HollomanHammingDistance(a, a); err != nil || d != 0 {
		t.Errorf("same order identical: got (%d, %v), want (0, nil)", d, err)
	}
	// Different Hilbert orders are not comparable.
	if _, err := HollomanHammingDistance(a, other); err == nil {
		t.Errorf("expected order-mismatch error between %q and %q", a, other)
	}
}
