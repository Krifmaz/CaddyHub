use std::cmp::Ordering;

/// A parsed semantic version like v2.11.7 or v2.12.0-beta.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Version {
    pub major: i64,
    pub minor: i64,
    pub patch: i64,
    pub pre: String,
    pub valid: bool,
}

/// Parses the first token of `caddy version` output ("v2.11.7 h1:...") or a
/// bare tag. Unknown/dev builds return valid=false.
pub fn parse_version(s: &str) -> Version {
    let s = s.trim();
    let s = s.split([' ', '\t', '\n']).next().unwrap_or("");
    let mut s = s.strip_prefix('v').unwrap_or(s);
    if let Some(i) = s.find('+') {
        s = &s[..i];
    }
    let mut v = Version::default();
    if let Some(i) = s.find('-') {
        v.pre = s[i + 1..].to_string();
        s = &s[..i];
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() < 2 {
        return Version::default();
    }
    let mut nums = [0i64; 3];
    for (i, p) in parts.iter().take(3).enumerate() {
        match p.parse::<i64>() {
            Ok(n) => nums[i] = n,
            Err(_) => return Version::default(),
        }
    }
    v.major = nums[0];
    v.minor = nums[1];
    v.patch = nums[2];
    v.valid = true;
    v
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.valid {
            return write!(f, "unknown");
        }
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            write!(f, "-{}", self.pre)?;
        }
        Ok(())
    }
}

impl Version {
    /// Compares two versions. Pre-releases sort before the release.
    pub fn compare(&self, o: &Version) -> Ordering {
        for (a, b) in [
            (self.major, o.major),
            (self.minor, o.minor),
            (self.patch, o.patch),
        ] {
            if a != b {
                return a.cmp(&b);
            }
        }
        match (self.pre.as_str(), o.pre.as_str()) {
            (a, b) if a == b => Ordering::Equal,
            ("", _) => Ordering::Greater,
            (_, "") => Ordering::Less,
            (a, b) => compare_pre(a, b),
        }
    }

    /// Reports whether self >= min. An unknown version (custom/dev build) is
    /// assumed to be new enough, since refusing everything would be worse;
    /// `caddy validate` still guards the actual config.
    pub fn at_least(&self, min: &str) -> bool {
        if min.is_empty() || !self.valid {
            return true;
        }
        self.compare(&parse_version(min)) != Ordering::Less
    }
}

fn compare_pre(a: &str, b: &str) -> Ordering {
    let ap: Vec<&str> = a.split('.').collect();
    let bp: Vec<&str> = b.split('.').collect();
    for (x, y) in ap.iter().zip(bp.iter()) {
        match (x.parse::<i64>(), y.parse::<i64>()) {
            (Ok(an), Ok(bn)) => {
                if an != bn {
                    return an.cmp(&bn);
                }
            }
            (Ok(_), Err(_)) => return Ordering::Less,
            (Err(_), Ok(_)) => return Ordering::Greater,
            (Err(_), Err(_)) => {
                if x != y {
                    return x.cmp(y);
                }
            }
        }
    }
    ap.len().cmp(&bp.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_compare() {
        let v = parse_version("v2.11.7 h1:abc");
        assert_eq!((v.major, v.minor, v.patch), (2, 11, 7));
        assert!(v.at_least("v2.8.0"));
        assert!(!v.at_least("v2.12.0"));
        assert!(
            parse_version("v2.12.0-beta.1").compare(&parse_version("v2.12.0")) == Ordering::Less
        );
        assert!(!parse_version("devel").valid);
        assert!(parse_version("devel").at_least("v9.0.0"));
        assert_eq!(parse_version("2.11").to_string(), "v2.11.0");
    }
}
