package registry

import (
	"strconv"
	"strings"
)

// Version is a parsed semantic version like v2.11.7 or v2.12.0-beta.1.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
	Valid               bool
}

// ParseVersion parses the first token of `caddy version` output
// ("v2.11.7 h1:...") or a bare tag. Unknown/dev builds return Valid=false.
func ParseVersion(s string) Version {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "v")
	var v Version
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		v.Pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return Version{}
	}
	nums := make([]int, 3)
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return Version{}
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	v.Valid = true
	return v
}

func (v Version) String() string {
	if !v.Valid {
		return "unknown"
	}
	s := "v" + strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare returns -1, 0, 1. Pre-releases sort before the release.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return comparePre(v.Pre, o.Pre)
}

func comparePre(a, b string) int {
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		an, aerr := strconv.Atoi(ap[i])
		bn, berr := strconv.Atoi(bp[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case ap[i] != bp[i]:
			if ap[i] < bp[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ap) < len(bp):
		return -1
	case len(ap) > len(bp):
		return 1
	}
	return 0
}

// AtLeast reports whether v >= min. An unknown version (custom/dev build)
// is assumed to be new enough, since refusing everything would be worse;
// `caddy validate` still guards the actual config.
func (v Version) AtLeast(min string) bool {
	if min == "" || !v.Valid {
		return true
	}
	return v.Compare(ParseVersion(min)) >= 0
}
