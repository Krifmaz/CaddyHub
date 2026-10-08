package caddyfile

import (
	"fmt"
	"strings"
)

// Token is a lexed Caddyfile token.
type Token struct {
	Text   string
	Line   int
	Quoted bool
	Start  int // byte offset in source
	End    int
	// NewLineBefore is true when this token starts a new line (i.e. starts a
	// new directive within a block).
	NewLineBefore bool
}

// Lex tokenizes a Caddyfile. It understands comments, "quotes", `backticks`,
// heredocs (<<END ... END), escaped newlines and braces. It is tolerant:
// it never fails, it only produces tokens.
func Lex(src string) ([]Token, error) {
	var toks []Token
	line := 1
	i := 0
	newline := true
	n := len(src)
	for i < n {
		c := src[i]
		switch {
		case c == '\n':
			line++
			newline = true
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r':
			i++
			continue
		case c == '\\' && i+1 < n && (src[i+1] == '\n' || (src[i+1] == '\r' && i+2 < n && src[i+2] == '\n')):
			// line continuation
			if src[i+1] == '\r' {
				i++
			}
			i += 2
			line++
			continue
		case c == '#' && newlineOrSpaceBefore(src, i):
			for i < n && src[i] != '\n' {
				i++
			}
			continue
		}
		start := i
		startLine := line
		var sb strings.Builder
		quoted := false
		switch {
		case c == '"':
			quoted = true
			i++
			for i < n {
				if src[i] == '\\' && i+1 < n && src[i+1] == '"' {
					sb.WriteByte('"')
					i += 2
					continue
				}
				if src[i] == '"' {
					i++
					break
				}
				if src[i] == '\n' {
					line++
				}
				sb.WriteByte(src[i])
				i++
			}
		case c == '`':
			quoted = true
			i++
			for i < n && src[i] != '`' {
				if src[i] == '\n' {
					line++
				}
				sb.WriteByte(src[i])
				i++
			}
			if i < n {
				i++
			}
		case c == '<' && strings.HasPrefix(src[i:], "<<") && heredocMarker(src[i+2:]) != "":
			marker := heredocMarker(src[i+2:])
			i += 2 + len(marker)
			// skip to end of line
			for i < n && src[i] != '\n' {
				i++
			}
			if i < n {
				i++
				line++
			}
			bodyStart := i
			end := -1
			for j := i; j < n; {
				k := strings.IndexByte(src[j:], '\n')
				var l string
				if k < 0 {
					l = src[j:]
				} else {
					l = src[j : j+k]
				}
				// closing marker, optionally followed by more tokens on the
				// same line (e.g. `HTML 200`)
				tl := strings.TrimLeft(l, " \t")
				if strings.HasPrefix(tl, marker) && (len(tl) == len(marker) || tl[len(marker)] == ' ' || tl[len(marker)] == '\t' || tl[len(marker)] == '\r') {
					end = j
					i = j + (len(l) - len(tl)) + len(marker)
					break
				}
				if k < 0 {
					break
				}
				j += k + 1
			}
			if end < 0 {
				return toks, fmt.Errorf("line %d: unterminated heredoc %q", startLine, marker)
			}
			body := src[bodyStart:end]
			line += strings.Count(src[bodyStart:i], "\n")
			// strip indentation of closing marker line
			closing := src[end:i]
			ind := closing[:len(closing)-len(strings.TrimLeft(closing, " \t"))]
			var lines []string
			for _, l := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
				lines = append(lines, strings.TrimPrefix(l, ind))
			}
			sb.WriteString(strings.Join(lines, "\n"))
			quoted = true
		default:
			for i < n {
				ch := src[i]
				if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
					break
				}
				sb.WriteByte(ch)
				i++
			}
		}
		toks = append(toks, Token{Text: sb.String(), Line: startLine, Quoted: quoted, Start: start, End: i, NewLineBefore: newline})
		newline = false
	}
	return toks, nil
}

func newlineOrSpaceBefore(src string, i int) bool {
	return i == 0 || src[i-1] == ' ' || src[i-1] == '\t' || src[i-1] == '\n' || src[i-1] == '\r'
}

func heredocMarker(s string) string {
	j := 0
	for j < len(s) && (s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9' || s[j] == '_') {
		j++
	}
	if j == 0 || (j < len(s) && s[j] != '\n' && s[j] != '\r') {
		return ""
	}
	return s[:j]
}

// Directive is a parsed line with an optional block.
type Directive struct {
	Args     []Token // Args[0] is the directive name
	Block    []*Directive
	HasBlock bool
	Start    int
	End      int
}

// Name returns the directive name.
func (d *Directive) Name() string {
	if len(d.Args) == 0 {
		return ""
	}
	return d.Args[0].Text
}

// ArgStrings returns argument texts after the name.
func (d *Directive) ArgStrings() []string {
	var out []string
	for _, t := range d.Args[1:] {
		out = append(out, t.Text)
	}
	return out
}

// TopBlock is a top-level block: global options (no keys), a snippet,
// a named route or a site block.
type TopBlock struct {
	Keys  []Token // addresses, "(name)" or "&(name)"; empty for global options
	Body  []*Directive
	Start int
	End   int
	Text  string // verbatim source of the whole block
}

// IsGlobal reports whether this is the global options block.
func (b *TopBlock) IsGlobal() bool { return len(b.Keys) == 0 }

// IsSnippet reports whether this block is a snippet definition.
func (b *TopBlock) IsSnippet() bool {
	return len(b.Keys) == 1 && strings.HasPrefix(b.Keys[0].Text, "(") && strings.HasSuffix(b.Keys[0].Text, ")")
}

// IsNamedRoute reports whether this is a named route "&(name)".
func (b *TopBlock) IsNamedRoute() bool {
	return len(b.Keys) == 1 && strings.HasPrefix(b.Keys[0].Text, "&(")
}

// KeyStrings returns keys as strings with trailing commas stripped.
func (b *TopBlock) KeyStrings() []string {
	var out []string
	for _, k := range b.Keys {
		for _, p := range strings.Split(k.Text, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// Parse splits a Caddyfile into top-level blocks.
func Parse(src string) ([]*TopBlock, error) {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	toks, err := Lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks, src: src}
	return p.top()
}

type parser struct {
	toks []Token
	pos  int
	src  string
}

func (p *parser) top() ([]*TopBlock, error) {
	var blocks []*TopBlock
	for p.pos < len(p.toks) {
		start := p.toks[p.pos].Start
		var keys []Token
		// global options block: a lone "{" as the very first token
		if len(blocks) == 0 && p.toks[p.pos].Text == "{" && !p.toks[p.pos].Quoted {
			p.pos++
			body, err := p.block()
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, p.mk(nil, body, start))
			continue
		}
		// collect keys until "{" or a new line that isn't a continuation
		for p.pos < len(p.toks) {
			t := p.toks[p.pos]
			if t.Text == "{" && !t.Quoted {
				break
			}
			if len(keys) > 0 && t.NewLineBefore && !strings.HasSuffix(keys[len(keys)-1].Text, ",") {
				break
			}
			keys = append(keys, t)
			p.pos++
		}
		if p.pos < len(p.toks) && p.toks[p.pos].Text == "{" {
			p.pos++
			body, err := p.block()
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, p.mk(keys, body, start))
			continue
		}
		// Site without braces: only valid as the single site in the file;
		// the rest of the file is its body.
		var body []*Directive
		for p.pos < len(p.toks) {
			d, err := p.directive()
			if err != nil {
				return nil, err
			}
			body = append(body, d)
		}
		blocks = append(blocks, p.mk(keys, body, start))
	}
	return blocks, nil
}

func (p *parser) mk(keys []Token, body []*Directive, start int) *TopBlock {
	end := len(p.src)
	if p.pos > 0 && p.pos <= len(p.toks) {
		end = p.toks[p.pos-1].End
	}
	return &TopBlock{Keys: keys, Body: body, Start: start, End: end, Text: p.src[start:end]}
}

// block parses directives until the matching "}".
func (p *parser) block() ([]*Directive, error) {
	var out []*Directive
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		if t.Text == "}" && !t.Quoted {
			p.pos++
			return out, nil
		}
		d, err := p.directive()
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return nil, fmt.Errorf("unexpected end of file: missing '}'")
}

func (p *parser) directive() (*Directive, error) {
	d := &Directive{Start: p.toks[p.pos].Start}
	first := true
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		if !first && t.NewLineBefore {
			break
		}
		if t.Text == "}" && !t.Quoted {
			if first {
				return nil, fmt.Errorf("line %d: unexpected '}'", t.Line)
			}
			break
		}
		if t.Text == "{" && !t.Quoted && !first {
			p.pos++
			body, err := p.block()
			if err != nil {
				return nil, err
			}
			d.Block, d.HasBlock = body, true
			break
		}
		d.Args = append(d.Args, t)
		p.pos++
		first = false
	}
	d.End = p.toks[p.pos-1].End
	return d, nil
}

// Source returns the verbatim text of a directive.
func (d *Directive) Source(src string) string { return src[d.Start:d.End] }
