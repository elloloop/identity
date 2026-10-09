package emailaddr

import "testing"

func TestCanonicalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice@example.com", "alice@example.com"},
		{"  Alice@Example.COM ", "alice@example.com"},
		{"alice+news@example.com", "alice@example.com"},
		{"alice+a+b@example.com", "alice@example.com"},
		{"first.last@example.com", "first.last@example.com"},
		{"first.last@gmail.com", "firstlast@gmail.com"},
		{"First.Last+tag@GMail.com", "firstlast@gmail.com"},
		{"f.i.r.s.t@googlemail.com", "first@gmail.com"},
		{"first.last@gmail.com.", "firstlast@gmail.com"},
		{"user@bücher.example", "user@xn--bcher-kva.example"},
		{"no-at-sign", "no-at-sign"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Canonicalize(c.in); got != c.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", c.in, got, c.want)
		}
		if again := Canonicalize(Canonicalize(c.in)); again != c.want {
			t.Errorf("Canonicalize is not idempotent on %q: %q", c.in, again)
		}
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},
		{"googlemail.com", "gmail.com"},
		{"bücher.example", "xn--bcher-kva.example"},
	}
	for _, c := range cases {
		if got := CanonicalizeDomain(c.in); got != c.want {
			t.Errorf("CanonicalizeDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSameMailbox(t *testing.T) {
	if !SameMailbox("first.last@gmail.com", "firstlast+x@googlemail.com") {
		t.Error("two spellings of one Gmail inbox must be the same mailbox")
	}
	if SameMailbox("first.last@example.com", "firstlast@example.com") {
		t.Error("dots are significant outside Gmail")
	}
}
