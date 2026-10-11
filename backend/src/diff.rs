//! Line-based unified diffs (Myers O(ND) algorithm).

use serde::Serialize;
use std::fmt::Write as _;

/// A diff operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Op {
    #[serde(rename = " ")]
    Equal,
    #[serde(rename = "+")]
    Insert,
    #[serde(rename = "-")]
    Delete,
}

impl Op {
    fn ch(self) -> char {
        match self {
            Op::Equal => ' ',
            Op::Insert => '+',
            Op::Delete => '-',
        }
    }
}

/// One line of an edit script.
#[derive(Debug, Clone, Serialize)]
pub struct Line {
    pub op: Op,
    pub text: String,
}

/// Computes the edit script between a and b (split on newlines).
pub fn lines(a: &str, b: &str) -> Vec<Line> {
    let a = a.replace("\r\n", "\n");
    let b = b.replace("\r\n", "\n");
    compute(&split(&a), &split(&b))
}

fn split(s: &str) -> Vec<&str> {
    if s.is_empty() {
        return Vec::new();
    }
    let s = s.strip_suffix('\n').unwrap_or(s);
    s.split('\n').collect()
}

fn compute(a: &[&str], b: &[&str]) -> Vec<Line> {
    let (n, m) = (a.len() as i64, b.len() as i64);
    let max = n + m;
    if max == 0 {
        return Vec::new();
    }
    let off = max;
    let mut v = vec![0i64; (2 * max + 2) as usize];
    let mut trace: Vec<Vec<i64>> = Vec::new();
    for d in 0..=max {
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let idx = |kk: i64| (off + kk) as usize;
            let mut x = if k == -d || (k != d && v[idx(k - 1)] < v[idx(k + 1)]) {
                v[idx(k + 1)]
            } else {
                v[idx(k - 1)] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx(k)] = x;
            if x >= n && y >= m {
                return backtrack(&trace, a, b, off, d);
            }
            k += 2;
        }
    }
    Vec::new()
}

fn backtrack(trace: &[Vec<i64>], a: &[&str], b: &[&str], off: i64, d: i64) -> Vec<Line> {
    let (mut x, mut y) = (a.len() as i64, b.len() as i64);
    let mut out = Vec::new();
    let mut d = d;
    while d > 0 {
        let v = &trace[d as usize];
        let k = x - y;
        let idx = |kk: i64| (off + kk) as usize;
        let pk = if k == -d || (k != d && v[idx(k - 1)] < v[idx(k + 1)]) {
            k + 1
        } else {
            k - 1
        };
        let px = v[idx(pk)];
        let py = px - pk;
        while x > px && y > py {
            out.push(Line {
                op: Op::Equal,
                text: a[(x - 1) as usize].to_string(),
            });
            x -= 1;
            y -= 1;
        }
        if x == px {
            out.push(Line {
                op: Op::Insert,
                text: b[(y - 1) as usize].to_string(),
            });
            y -= 1;
        } else {
            out.push(Line {
                op: Op::Delete,
                text: a[(x - 1) as usize].to_string(),
            });
            x -= 1;
        }
        d -= 1;
    }
    while x > 0 && y > 0 {
        out.push(Line {
            op: Op::Equal,
            text: a[(x - 1) as usize].to_string(),
        });
        x -= 1;
        y -= 1;
    }
    out.reverse();
    out
}

/// Counts insertions and deletions.
pub fn stats(ls: &[Line]) -> (usize, usize) {
    let ins = ls.iter().filter(|l| l.op == Op::Insert).count();
    let del = ls.iter().filter(|l| l.op == Op::Delete).count();
    (ins, del)
}

/// Renders a unified diff with the given context lines.
pub fn unified(a: &str, b: &str, name_a: &str, name_b: &str, context: usize) -> String {
    let ls = lines(a, b);
    let (ins, del) = stats(&ls);
    if ins == 0 && del == 0 {
        return String::new();
    }
    let mut sb = String::new();
    let _ = writeln!(sb, "--- {name_a}\n+++ {name_b}");
    let mut positions = Vec::with_capacity(ls.len() + 1);
    let (mut ai, mut bi) = (1usize, 1usize);
    for l in &ls {
        positions.push((ai, bi));
        match l.op {
            Op::Equal => {
                ai += 1;
                bi += 1;
            }
            Op::Delete => ai += 1,
            Op::Insert => bi += 1,
        }
    }
    positions.push((ai, bi));
    let mut i = 0;
    while i < ls.len() {
        if ls[i].op == Op::Equal {
            i += 1;
            continue;
        }
        let start = i.saturating_sub(context);
        let mut end = i;
        while end < ls.len() {
            if ls[end].op != Op::Equal {
                end += 1;
                continue;
            }
            let mut j = end;
            while j < ls.len() && ls[j].op == Op::Equal && j - end < 2 * context {
                j += 1;
            }
            if j < ls.len() && ls[j].op != Op::Equal {
                end = j;
                continue;
            }
            break;
        }
        let stop = (end + context).min(ls.len());
        let (mut ca, mut cb) = (0usize, 0usize);
        for l in &ls[start..stop] {
            if l.op != Op::Insert {
                ca += 1;
            }
            if l.op != Op::Delete {
                cb += 1;
            }
        }
        let _ = writeln!(
            sb,
            "@@ -{},{} +{},{} @@",
            positions[start].0, ca, positions[start].1, cb
        );
        for l in &ls[start..stop] {
            sb.push(l.op.ch());
            sb.push_str(&l.text);
            sb.push('\n');
        }
        i = stop;
    }
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(ls: &[Line]) -> (String, String) {
        let a: Vec<&str> = ls
            .iter()
            .filter(|l| l.op != Op::Insert)
            .map(|l| l.text.as_str())
            .collect();
        let b: Vec<&str> = ls
            .iter()
            .filter(|l| l.op != Op::Delete)
            .map(|l| l.text.as_str())
            .collect();
        (a.join("\n"), b.join("\n"))
    }

    #[test]
    fn round_trip() {
        let cases = [
            ("", ""),
            ("a", ""),
            ("", "b"),
            ("a\nb\nc", "a\nc"),
            ("a\nb\nc", "x\na\nb\ny\nc\nz"),
            ("1\n2\n3\n4\n5\n6\n7\n8\n9", "1\n2\nX\n4\n5\n6\n7\nY\n9"),
        ];
        for (x, y) in cases {
            let (a, b) = apply(&lines(x, y));
            assert_eq!(a, x.trim_end_matches('\n'), "{x:?} -> {y:?}");
            assert_eq!(b, y.trim_end_matches('\n'), "{x:?} -> {y:?}");
        }
    }

    #[test]
    fn minimal() {
        assert_eq!(stats(&lines("a\nb\nc\nd", "a\nc\nd\ne")), (1, 1));
    }

    #[test]
    fn unified_output() {
        let a = "l1\nl2\nl3\nl4\nl5\nl6\nl7\nl8\nl9\nl10\n";
        let b = "l1\nl2\nl3\nCHANGED\nl5\nl6\nl7\nl8\nl9\nl10\n";
        let u = unified(a, b, "old", "new", 2);
        assert_eq!(
            u,
            "--- old\n+++ new\n@@ -2,5 +2,5 @@\n l2\n l3\n-l4\n+CHANGED\n l5\n l6\n"
        );
        assert_eq!(unified(a, a, "x", "y", 3), "");
    }
}
