//! The user profile: `$XDG_CONFIG_HOME/dasm/config.toml`.
//!
//! Only `[user] name = "..."` is read. The file is tiny and the workspace
//! has no TOML dependency, so this is a deliberately minimal reader: a
//! missing or unreadable file, or a missing key, simply means "not
//! configured" (the author then falls back to `$USER`).

use std::path::PathBuf;

/// Where the profile lives for this process.
#[derive(Clone, Debug, Default)]
pub struct Env {
    /// Full path of `config.toml`, if it can be determined.
    pub config_path: Option<PathBuf>,
}

impl Env {
    /// From `$XDG_CONFIG_HOME`, else `$HOME/.config`.
    #[must_use]
    pub fn from_process() -> Self {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|h| PathBuf::from(h).join(".config"))
            });
        Env {
            config_path: base.map(|b| b.join("dasm").join("config.toml")),
        }
    }

    /// The configured author name, if any.
    #[must_use]
    pub fn user_name(&self) -> Option<String> {
        let text = std::fs::read_to_string(self.config_path.as_deref()?).ok()?;
        parse_user_name(&text)
    }
}

/// Extracts `name` from the `[user]` table.
#[must_use]
pub fn parse_user_name(toml: &str) -> Option<String> {
    let mut in_user = false;
    for raw in toml.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            in_user = header.split(']').next().is_some_and(|h| h.trim() == "user");
            continue;
        }
        if !in_user {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        if key.trim() == "name" {
            return parse_string(value.trim());
        }
    }
    None
}

fn parse_string(v: &str) -> Option<String> {
    if let Some(rest) = v.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Some(out),
                '\\' => match chars.next()? {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    _ => return None,
                },
                c => out.push(c),
            }
        }
        None
    } else if let Some(rest) = v.strip_prefix('\'') {
        rest.split('\'').next().map(str::to_owned)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_user_name() {
        assert_eq!(
            parse_user_name("[user]\nname = \"Ada L.\"\n").as_deref(),
            Some("Ada L.")
        );
        assert_eq!(
            parse_user_name("# c\n[other]\nname = \"x\"\n[user]\n name = 'bob' # c\n").as_deref(),
            Some("bob")
        );
        assert_eq!(
            parse_user_name("[user]\nname = \"a \\\"q\\\"\"").as_deref(),
            Some("a \"q\"")
        );
    }

    #[test]
    fn missing_or_malformed_is_none() {
        assert_eq!(parse_user_name(""), None);
        assert_eq!(parse_user_name("name = \"top\""), None);
        assert_eq!(parse_user_name("[user]\nname = unquoted"), None);
        assert_eq!(parse_user_name("[user]\nname = \"open"), None);
        assert_eq!(parse_user_name("[user"), None);
    }

    #[test]
    fn env_reads_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[user]\nname = \"Zed\"\n").unwrap();
        let env = Env {
            config_path: Some(path),
        };
        assert_eq!(env.user_name().as_deref(), Some("Zed"));
        assert_eq!(Env::default().user_name(), None);
    }
}
