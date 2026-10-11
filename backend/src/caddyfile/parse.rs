use anyhow::{Result, anyhow};

/// A lexed Caddyfile token.
#[derive(Debug, Clone)]
pub struct Token {
    pub text: String,
    pub line: usize,
    pub quoted: bool,
    /// byte offset in source
    pub start: usize,
    pub end: usize,
    /// True when this token starts a new line (i.e. starts a new directive
    /// within a block).
    pub newline_before: bool,
}

fn heredoc_marker(s: &[u8]) -> Option<&[u8]> {
    let mut j = 0;
    while j < s.len() && (s[j].is_ascii_alphanumeric() || s[j] == b'_') {
        j += 1;
    }
    if j == 0 || (j < s.len() && s[j] != b'\n' && s[j] != b'\r') {
        return None;
    }
    Some(&s[..j])
}

fn newline_or_space_before(src: &[u8], i: usize) -> bool {
    i == 0 || matches!(src[i - 1], b' ' | b'\t' | b'\n' | b'\r')
}

/// Tokenizes a Caddyfile. It understands comments, "quotes", `backticks`,
/// heredocs (<<END ... END), escaped newlines and braces. It is tolerant:
/// it only fails on an unterminated heredoc.
pub fn lex(src: &str) -> Result<Vec<Token>> {
    let s = src.as_bytes();
    let n = s.len();
    let mut toks = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    let mut newline = true;
    while i < n {
        let c = s[i];
        if c == b'\n' {
            line += 1;
            newline = true;
            i += 1;
            continue;
        }
        if c == b' ' || c == b'\t' || c == b'\r' {
            i += 1;
            continue;
        }
        if c == b'\\'
            && i + 1 < n
            && (s[i + 1] == b'\n' || (s[i + 1] == b'\r' && i + 2 < n && s[i + 2] == b'\n'))
        {
            if s[i + 1] == b'\r' {
                i += 1;
            }
            i += 2;
            line += 1;
            continue;
        }
        if c == b'#' && newline_or_space_before(s, i) {
            while i < n && s[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let start = i;
        let start_line = line;
        let mut sb: Vec<u8> = Vec::new();
        let mut quoted = false;
        if c == b'"' {
            quoted = true;
            i += 1;
            while i < n {
                if s[i] == b'\\' && i + 1 < n && s[i + 1] == b'"' {
                    sb.push(b'"');
                    i += 2;
                    continue;
                }
                if s[i] == b'"' {
                    i += 1;
                    break;
                }
                if s[i] == b'\n' {
                    line += 1;
                }
                sb.push(s[i]);
                i += 1;
            }
        } else if c == b'`' {
            quoted = true;
            i += 1;
            while i < n && s[i] != b'`' {
                if s[i] == b'\n' {
                    line += 1;
                }
                sb.push(s[i]);
                i += 1;
            }
            if i < n {
                i += 1;
            }
        } else if c == b'<' && s[i..].starts_with(b"<<") && heredoc_marker(&s[i + 2..]).is_some() {
            let marker = heredoc_marker(&s[i + 2..]).unwrap().to_vec();
            i += 2 + marker.len();
            while i < n && s[i] != b'\n' {
                i += 1;
            }
            if i < n {
                i += 1;
                line += 1;
            }
            let body_start = i;
            let mut end: Option<usize> = None;
            let mut j = i;
            loop {
                let k = s[j..].iter().position(|&b| b == b'\n');
                let l: &[u8] = match k {
                    Some(k) => &s[j..j + k],
                    None => &s[j..],
                };
                let lead = l.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
                let tl = &l[lead..];
                if tl.starts_with(&marker)
                    && (tl.len() == marker.len()
                        || matches!(tl[marker.len()], b' ' | b'\t' | b'\r'))
                {
                    end = Some(j);
                    i = j + lead + marker.len();
                    break;
                }
                match k {
                    None => break,
                    Some(k) => j += k + 1,
                }
            }
            let Some(end) = end else {
                return Err(anyhow!(
                    "line {start_line}: unterminated heredoc {:?}",
                    String::from_utf8_lossy(&marker)
                ));
            };
            let body = &s[body_start..end];
            line += s[body_start..i].iter().filter(|&&b| b == b'\n').count();
            let closing = &s[end..i];
            let ind_len = closing
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            let ind = &closing[..ind_len];
            let body = body.strip_suffix(b"\n").unwrap_or(body);
            let mut lines: Vec<&[u8]> = Vec::new();
            for l in body.split(|&b| b == b'\n') {
                lines.push(l.strip_prefix(ind).unwrap_or(l));
            }
            sb = lines.join(&b'\n');
            quoted = true;
        } else {
            while i < n {
                let ch = s[i];
                if matches!(ch, b' ' | b'\t' | b'\n' | b'\r') {
                    break;
                }
                sb.push(ch);
                i += 1;
            }
        }
        toks.push(Token {
            text: String::from_utf8_lossy(&sb).into_owned(),
            line: start_line,
            quoted,
            start,
            end: i,
            newline_before: newline,
        });
        newline = false;
    }
    Ok(toks)
}

/// A parsed line with an optional block.
#[derive(Debug, Clone, Default)]
pub struct Directive {
    /// args[0] is the directive name
    pub args: Vec<Token>,
    pub block: Vec<Directive>,
    pub has_block: bool,
    pub start: usize,
    pub end: usize,
}

impl Directive {
    /// The directive name.
    pub fn name(&self) -> &str {
        self.args.first().map(|t| t.text.as_str()).unwrap_or("")
    }

    /// Argument texts after the name.
    pub fn arg_strings(&self) -> Vec<&str> {
        self.args.iter().skip(1).map(|t| t.text.as_str()).collect()
    }

    /// The verbatim text of a directive.
    pub fn source<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.end]
    }
}

/// A top-level block: global options (no keys), a snippet, a named route
/// or a site block.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct TopBlock {
    /// addresses, "(name)" or "&(name)"; empty for global options
    pub keys: Vec<Token>,
    pub body: Vec<Directive>,
    pub start: usize,
    pub end: usize,
    /// verbatim source of the whole block
    pub text: String,
}

impl TopBlock {
    /// Reports whether this is the global options block.
    pub fn is_global(&self) -> bool {
        self.keys.is_empty()
    }

    /// Reports whether this block is a snippet definition.
    pub fn is_snippet(&self) -> bool {
        self.keys.len() == 1
            && self.keys[0].text.starts_with('(')
            && self.keys[0].text.ends_with(')')
    }

    /// Reports whether this is a named route "&(name)".
    pub fn is_named_route(&self) -> bool {
        self.keys.len() == 1 && self.keys[0].text.starts_with("&(")
    }

    /// Keys as strings with trailing commas stripped.
    pub fn key_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        for k in &self.keys {
            for p in k.text.split(',') {
                let p = p.trim();
                if !p.is_empty() {
                    out.push(p.to_string());
                }
            }
        }
        out
    }
}

/// Splits a Caddyfile into top-level blocks.
pub fn parse(src: &str) -> Result<Vec<TopBlock>> {
    let src = src.replace("\r\n", "\n");
    let toks = lex(&src)?;
    let mut p = Parser {
        toks,
        pos: 0,
        src: &src,
    };
    p.top()
}

struct Parser<'a> {
    toks: Vec<Token>,
    pos: usize,
    src: &'a str,
}

impl Parser<'_> {
    fn top(&mut self) -> Result<Vec<TopBlock>> {
        let mut blocks: Vec<TopBlock> = Vec::new();
        while self.pos < self.toks.len() {
            let start = self.toks[self.pos].start;
            // global options block: a lone "{" as the very first token
            if blocks.is_empty() && self.toks[self.pos].text == "{" && !self.toks[self.pos].quoted {
                self.pos += 1;
                let body = self.block()?;
                let b = self.mk(Vec::new(), body, start);
                blocks.push(b);
                continue;
            }
            // collect keys until "{" or a new line that isn't a continuation
            let mut keys: Vec<Token> = Vec::new();
            while self.pos < self.toks.len() {
                let t = &self.toks[self.pos];
                if t.text == "{" && !t.quoted {
                    break;
                }
                if !keys.is_empty() && t.newline_before && !keys.last().unwrap().text.ends_with(',')
                {
                    break;
                }
                keys.push(t.clone());
                self.pos += 1;
            }
            if self.pos < self.toks.len()
                && self.toks[self.pos].text == "{"
                && !self.toks[self.pos].quoted
            {
                self.pos += 1;
                let body = self.block()?;
                let b = self.mk(keys, body, start);
                blocks.push(b);
                continue;
            }
            // Site without braces: only valid as the single site in the
            // file; the rest of the file is its body.
            let mut body = Vec::new();
            while self.pos < self.toks.len() {
                body.push(self.directive()?);
            }
            let b = self.mk(keys, body, start);
            blocks.push(b);
        }
        Ok(blocks)
    }

    fn mk(&self, keys: Vec<Token>, body: Vec<Directive>, start: usize) -> TopBlock {
        let mut end = self.src.len();
        if self.pos > 0 && self.pos <= self.toks.len() {
            end = self.toks[self.pos - 1].end;
        }
        TopBlock {
            keys,
            body,
            start,
            end,
            text: self.src[start..end].to_string(),
        }
    }

    /// Parses directives until the matching "}".
    fn block(&mut self) -> Result<Vec<Directive>> {
        let mut out = Vec::new();
        while self.pos < self.toks.len() {
            let t = &self.toks[self.pos];
            if t.text == "}" && !t.quoted {
                self.pos += 1;
                return Ok(out);
            }
            out.push(self.directive()?);
        }
        Err(anyhow!("unexpected end of file: missing '}}'"))
    }

    fn directive(&mut self) -> Result<Directive> {
        let mut d = Directive {
            start: self.toks[self.pos].start,
            ..Default::default()
        };
        let mut first = true;
        while self.pos < self.toks.len() {
            let t = self.toks[self.pos].clone();
            if !first && t.newline_before {
                break;
            }
            if t.text == "}" && !t.quoted {
                if first {
                    return Err(anyhow!("line {}: unexpected '}}'", t.line));
                }
                break;
            }
            if t.text == "{" && !t.quoted && !first {
                self.pos += 1;
                d.block = self.block()?;
                d.has_block = true;
                break;
            }
            d.args.push(t);
            self.pos += 1;
            first = false;
        }
        d.end = self.toks[self.pos - 1].end;
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_blocks_and_heredocs() {
        let src = "{\n\temail a@b.c\n}\n\n(snip) {\n\theader X Y\n}\n\na.example.com, b.example.com {\n\trespond <<HTML\n\t\t<h1>Hi # not a comment</h1>\n\t\tHTML 200\n\t# real comment\n\treverse_proxy app:80 {\n\t\tlb_policy first\n\t}\n}\n";
        let blocks = parse(src).unwrap();
        assert_eq!(blocks.len(), 3);
        assert!(blocks[0].is_global());
        assert!(blocks[1].is_snippet());
        assert_eq!(
            blocks[2].key_strings(),
            vec!["a.example.com", "b.example.com"]
        );
        let site = &blocks[2];
        assert_eq!(site.body.len(), 2);
        let respond = &site.body[0];
        assert_eq!(respond.name(), "respond");
        assert_eq!(respond.args[1].text, "<h1>Hi # not a comment</h1>");
        assert_eq!(respond.args[2].text, "200");
        let rp = &site.body[1];
        assert!(rp.has_block);
        assert_eq!(rp.block[0].arg_strings(), vec!["first"]);
        assert_eq!(
            rp.source(src),
            "reverse_proxy app:80 {\n\t\tlb_policy first\n\t}"
        );
    }

    #[test]
    fn braceless_site() {
        let blocks = parse("example.com\n\nreverse_proxy app:80\n").unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].key_strings(), vec!["example.com"]);
        assert_eq!(blocks[0].body[0].name(), "reverse_proxy");
    }

    #[test]
    fn quotes_and_escapes() {
        let toks = lex("respond \"a \\\"b\\\" c\" `x\"y` 200").unwrap();
        assert_eq!(toks[1].text, "a \"b\" c");
        assert_eq!(toks[2].text, "x\"y");
        assert!(toks[1].quoted);
    }
}
