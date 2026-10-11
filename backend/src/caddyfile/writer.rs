/// Builds an indented Caddyfile.
#[derive(Default)]
pub struct Writer {
    b: String,
    depth: usize,
}

impl Writer {
    /// Writes one directive line. Arguments must already be quoted with
    /// `quote` where they come from user input.
    pub fn line<S: AsRef<str>>(&mut self, tokens: &[S]) {
        self.indent();
        self.b.push_str(&join(tokens));
        self.b.push('\n');
    }

    /// Writes "tokens {" and increases depth.
    pub fn open<S: AsRef<str>>(&mut self, tokens: &[S]) {
        self.indent();
        if !tokens.is_empty() {
            self.b.push_str(&join(tokens));
            self.b.push(' ');
        }
        self.b.push_str("{\n");
        self.depth += 1;
    }

    /// Writes "}" and decreases depth.
    pub fn close(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }
        self.indent();
        self.b.push_str("}\n");
    }

    /// Writes an empty line (never twice in a row, and never right after an
    /// opening brace).
    pub fn blank(&mut self) {
        if self.b.is_empty() || self.b.ends_with("\n\n") || self.b.ends_with("{\n") {
            return;
        }
        self.b.push('\n');
    }

    /// Writes a comment line.
    pub fn comment(&mut self, text: &str) {
        for l in text.split('\n') {
            self.indent();
            self.b.push_str("# ");
            self.b.push_str(l.trim_end_matches([' ', '\t']));
            self.b.push('\n');
        }
    }

    /// Writes a verbatim multi-line block, re-indented to the current depth.
    /// Used for snippets, raw blocks and the per-site escape hatch.
    pub fn raw(&mut self, text: &str) {
        let text = dedent(text);
        let text = text.trim_matches('\n');
        if text.trim().is_empty() {
            return;
        }
        for l in text.split('\n') {
            if l.trim().is_empty() {
                self.b.push('\n');
                continue;
            }
            self.indent();
            self.b.push_str(l.trim_end_matches([' ', '\t', '\r']));
            self.b.push('\n');
        }
    }

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.b.push('\t');
        }
    }

    /// Returns the document.
    pub fn into_string(self) -> String {
        self.b
    }
}

fn join<S: AsRef<str>>(tokens: &[S]) -> String {
    tokens
        .iter()
        .map(|t| t.as_ref())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quotes a token if needed so it is lexed as a single token with the same
/// value. Values containing both a backtick and a double quote use escaped
/// double quotes.
pub fn quote(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    if !needs_quote(s) {
        return s.to_string();
    }
    if !s.contains('`') && s.contains('"') {
        return format!("`{s}`");
    }
    format!("\"{}\"", s.replace('"', "\\\""))
}

fn needs_quote(s: &str) -> bool {
    if s == "{" || s == "}" || s.starts_with('#') || s.starts_with("<<") {
        return true;
    }
    s.chars()
        .any(|r| matches!(r, ' ' | '\t' | '\n' | '\r' | '"' | '`'))
}

/// Removes common leading whitespace.
pub fn dedent(s: &str) -> String {
    let s = s.replace("\r\n", "\n");
    let lines: Vec<&str> = s.split('\n').collect();
    let mut prefix: Option<String> = None;
    for l in &lines {
        if l.trim().is_empty() {
            continue;
        }
        let lead: String = l.chars().take_while(|c| *c == ' ' || *c == '\t').collect();
        match &mut prefix {
            None => prefix = Some(lead),
            Some(p) => {
                while !lead.starts_with(p.as_str()) {
                    p.pop();
                }
            }
        }
    }
    let prefix = prefix.unwrap_or_default();
    if prefix.is_empty() {
        return s;
    }
    lines
        .iter()
        .map(|l| l.strip_prefix(prefix.as_str()).unwrap_or(l))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a b"), "\"a b\"");
        assert_eq!(quote("{\"ok\":true}"), "`{\"ok\":true}`");
        assert_eq!(quote("x`y\"z"), "\"x`y\\\"z\"");
        assert_eq!(quote("#x"), "\"#x\"");
    }

    #[test]
    fn writer_blocks() {
        let mut w = Writer::default();
        w.open(&["a"]);
        w.blank();
        w.line(&["b", "c"]);
        w.raw("  x {\n    y\n  }\n");
        w.close();
        assert_eq!(w.into_string(), "a {\n\tb c\n\tx {\n\t  y\n\t}\n}\n");
    }
}
