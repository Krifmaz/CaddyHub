// Package caddyfile contains a Caddyfile writer (used by the generator) and a
// tolerant lexer/parser (used by the importer). The writer never edits text;
// it only emits fresh Caddyfiles from the structured model.
package caddyfile

import (
	"strings"
)

// Writer builds an indented Caddyfile.
type Writer struct {
	b     strings.Builder
	depth int
}

// Line writes one directive line. Arguments must already be quoted with Q
// where they come from user input.
func (w *Writer) Line(tokens ...string) {
	w.indent()
	w.b.WriteString(strings.Join(tokens, " "))
	w.b.WriteByte('\n')
}

// Open writes "tokens {" and increases depth.
func (w *Writer) Open(tokens ...string) {
	w.indent()
	if len(tokens) > 0 {
		w.b.WriteString(strings.Join(tokens, " "))
		w.b.WriteString(" ")
	}
	w.b.WriteString("{\n")
	w.depth++
}

// Close writes "}" and decreases depth.
func (w *Writer) Close() {
	if w.depth > 0 {
		w.depth--
	}
	w.indent()
	w.b.WriteString("}\n")
}

// Blank writes an empty line (never at depth > 0 twice in a row).
func (w *Writer) Blank() {
	s := w.b.String()
	if len(s) == 0 || strings.HasSuffix(s, "\n\n") || strings.HasSuffix(s, "{\n") {
		return
	}
	w.b.WriteByte('\n')
}

// Comment writes a comment line.
func (w *Writer) Comment(text string) {
	for _, l := range strings.Split(text, "\n") {
		w.indent()
		w.b.WriteString("# ")
		w.b.WriteString(strings.TrimRight(l, " \t"))
		w.b.WriteByte('\n')
	}
}

// Raw writes a verbatim multi-line block, re-indented to the current depth.
// Used for snippets, raw blocks and the per-site escape hatch.
func (w *Writer) Raw(text string) {
	text = strings.Trim(dedent(text), "\n")
	if strings.TrimSpace(text) == "" {
		return
	}
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" {
			w.b.WriteByte('\n')
			continue
		}
		w.indent()
		w.b.WriteString(strings.TrimRight(l, " \t\r"))
		w.b.WriteByte('\n')
	}
}

func (w *Writer) indent() {
	for i := 0; i < w.depth; i++ {
		w.b.WriteByte('\t')
	}
}

// String returns the document.
func (w *Writer) String() string { return w.b.String() }

// Q quotes a token if needed so it is lexed as a single token with the same
// value. Values containing both a backtick and a double quote use escaped
// double quotes.
func Q(s string) string {
	if s == "" {
		return `""`
	}
	if !needsQuote(s) {
		return s
	}
	if !strings.Contains(s, "`") && strings.Contains(s, `"`) {
		return "`" + s + "`"
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func needsQuote(s string) bool {
	if s == "{" || s == "}" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "<<") {
		return true
	}
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '`':
			return true
		}
	}
	return false
}

// dedent removes common leading whitespace.
func dedent(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	prefix := ""
	first := true
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		lead := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
		if first {
			prefix, first = lead, false
			continue
		}
		for !strings.HasPrefix(lead, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	if prefix == "" {
		return s
	}
	for i, l := range lines {
		lines[i] = strings.TrimPrefix(l, prefix)
	}
	return strings.Join(lines, "\n")
}
