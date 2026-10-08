package diff

import (
	"strings"
	"testing"
)

func apply(ls []Line) (a, b string) {
	var as, bs []string
	for _, l := range ls {
		if l.Op != Insert {
			as = append(as, l.Text)
		}
		if l.Op != Delete {
			bs = append(bs, l.Text)
		}
	}
	return strings.Join(as, "\n"), strings.Join(bs, "\n")
}

func TestLinesRoundTrip(t *testing.T) {
	cases := [][2]string{
		{"", ""},
		{"a", ""},
		{"", "b"},
		{"a\nb\nc", "a\nc"},
		{"a\nb\nc", "x\na\nb\ny\nc\nz"},
		{"1\n2\n3\n4\n5\n6\n7\n8\n9", "1\n2\nX\n4\n5\n6\n7\nY\n9"},
	}
	for _, c := range cases {
		ls := Lines(c[0], c[1])
		a, b := apply(ls)
		if a != strings.TrimSuffix(c[0], "\n") || b != strings.TrimSuffix(c[1], "\n") {
			t.Errorf("round trip failed for %q -> %q: got %q -> %q", c[0], c[1], a, b)
		}
	}
}

func TestMinimal(t *testing.T) {
	ins, del := Stats(Lines("a\nb\nc\nd", "a\nc\nd\ne"))
	if ins != 1 || del != 1 {
		t.Fatalf("expected 1/1, got %d/%d", ins, del)
	}
}

func TestUnified(t *testing.T) {
	a := "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\n"
	b := "l1\nl2\nl3\nCHANGED\nl5\nl6\nl7\nl8\nl9\nl10\n"
	u := Unified(a, b, "old", "new", 2)
	want := "--- old\n+++ new\n@@ -2,5 +2,5 @@\n l2\n l3\n-l4\n+CHANGED\n l5\n l6\n"
	if u != want {
		t.Fatalf("unexpected unified diff:\n%s\nwant:\n%s", u, want)
	}
	if Unified(a, a, "x", "y", 3) != "" {
		t.Fatal("identical inputs should produce empty diff")
	}
}
