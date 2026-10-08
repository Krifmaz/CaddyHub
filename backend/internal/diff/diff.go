// Package diff produces line-based unified diffs (Myers O(ND) algorithm).
package diff

import (
	"fmt"
	"strings"
)

// Op is a diff operation.
type Op byte

const (
	Equal  Op = ' '
	Insert Op = '+'
	Delete Op = '-'
)

// Line is one line of an edit script.
type Line struct {
	Op   Op     `json:"op"`
	Text string `json:"text"`
}

// Lines computes the edit script between a and b (split on \n).
func Lines(a, b string) []Line {
	return compute(split(a), split(b))
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func compute(a, b []string) []Line {
	n, m := len(a), len(b)
	max := n + m
	if max == 0 {
		return nil
	}
	off := max
	v := make([]int, 2*max+2)
	var trace [][]int
	for d := 0; d <= max; d++ {
		snap := make([]int, len(v))
		copy(snap, v)
		trace = append(trace, snap)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(trace, a, b, off, d)
			}
		}
	}
	return nil
}

func backtrack(trace [][]int, a, b []string, off, d int) []Line {
	x, y := len(a), len(b)
	var out []Line
	for ; d > 0; d-- {
		v := trace[d]
		k := x - y
		var pk int
		if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := v[off+pk]
		py := px - pk
		for x > px && y > py {
			out = append(out, Line{Equal, a[x-1]})
			x--
			y--
		}
		if x == px {
			out = append(out, Line{Insert, b[y-1]})
			y--
		} else {
			out = append(out, Line{Delete, a[x-1]})
			x--
		}
	}
	for x > 0 && y > 0 {
		out = append(out, Line{Equal, a[x-1]})
		x--
		y--
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Stats counts insertions and deletions.
func Stats(ls []Line) (ins, del int) {
	for _, l := range ls {
		switch l.Op {
		case Insert:
			ins++
		case Delete:
			del++
		}
	}
	return
}

// Unified renders a unified diff with the given context lines.
func Unified(a, b, nameA, nameB string, context int) string {
	ls := Lines(a, b)
	ins, del := Stats(ls)
	if ins == 0 && del == 0 {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", nameA, nameB)
	// line numbers
	type pos struct{ a, b int }
	positions := make([]pos, len(ls)+1)
	ai, bi := 1, 1
	for i, l := range ls {
		positions[i] = pos{ai, bi}
		switch l.Op {
		case Equal:
			ai++
			bi++
		case Delete:
			ai++
		case Insert:
			bi++
		}
	}
	i := 0
	for i < len(ls) {
		if ls[i].Op == Equal {
			i++
			continue
		}
		start := i - context
		if start < 0 {
			start = 0
		}
		end := i
		for end < len(ls) {
			if ls[end].Op != Equal {
				end++
				continue
			}
			// look ahead: next change within 2*context?
			j := end
			for j < len(ls) && ls[j].Op == Equal && j-end < 2*context {
				j++
			}
			if j < len(ls) && ls[j].Op != Equal {
				end = j
				continue
			}
			break
		}
		stop := end + context
		if stop > len(ls) {
			stop = len(ls)
		}
		var ca, cb int
		for _, l := range ls[start:stop] {
			if l.Op != Insert {
				ca++
			}
			if l.Op != Delete {
				cb++
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", positions[start].a, ca, positions[start].b, cb)
		for _, l := range ls[start:stop] {
			sb.WriteByte(byte(l.Op))
			sb.WriteString(l.Text)
			sb.WriteByte('\n')
		}
		i = stop
	}
	return sb.String()
}
