//! Text policy for strings that reach a terminal or the UI (ADR 0002).
//!
//! Text from a binary or a project is attacker-controlled: an ANSI escape
//! can rewrite a terminal, a bidi override can make a name read differently
//! from what is stored. User-entered text is validated by
//! [`crate::Operation::validate`]; text that cannot be rejected, such as
//! symbol names in an ELF file, is shown through [`sanitize_for_display`].

use std::borrow::Cow;
use std::fmt::Write;

/// True for characters that display as nothing or change how neighbouring
/// text displays: Unicode category Cf, the line and paragraph separators,
/// and the other default-ignorable code points (variation selectors, Hangul
/// fillers, combining grapheme joiner, the tag block).
#[must_use]
pub fn is_invisible_char(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// Invisible characters that ordinary text in many scripts needs:
/// joiners, directional marks, emoji variation selectors.
fn is_text_shaping_char(c: char) -> bool {
    matches!(c, '\u{61c}' | '\u{200c}'..='\u{200f}' | '\u{fe00}'..='\u{fe0f}')
}

/// True if `s` is safe as an identifier-like label on one line (names,
/// tags, types, authors): no control and no format characters.
pub(crate) fn is_clean_label(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || is_invisible_char(c))
}

/// True if `s` is safe as free text (comments, notes). Newlines, tabs and
/// text-shaping characters are allowed; other control and invisible
/// characters, which can reorder or hide text, are not.
pub(crate) fn is_clean_text(s: &str) -> bool {
    !s.chars().any(|c| {
        (c.is_control() && c != '\n' && c != '\t')
            || (is_invisible_char(c) && !is_text_shaping_char(c))
    })
}

/// `s` with control and invisible characters replaced by visible
/// `\\u{..}` escapes and backslashes doubled, on one line, so an escape
/// cannot be confused with the same text in the original. Use for any
/// untrusted text shown to a person. Returns the input unchanged (without
/// allocating) when it is clean.
#[must_use]
pub fn sanitize_for_display(s: &str) -> Cow<'_, str> {
    let unsafe_char = |c: char| c == '\\' || c.is_control() || is_invisible_char(c);
    if !s.chars().any(unsafe_char) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if unsafe_char(c) {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_strings_are_not_copied() {
        assert!(matches!(
            sanitize_for_display("std::vector<int>::size"),
            Cow::Borrowed(_)
        ));
        assert!(matches!(
            sanitize_for_display("функция_名前"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn escapes_terminal_and_bidi_tricks() {
        assert_eq!(
            sanitize_for_display("a\u{1b}[31mb"),
            "a\\u{1b}[31mb".to_owned()
        );
        assert_eq!(
            sanitize_for_display("gnp\u{202e}exe"),
            "gnp\\u{202e}exe".to_owned()
        );
        assert_eq!(sanitize_for_display("a\nb"), "a\\u{a}b".to_owned());
    }

    #[test]
    fn escapes_cannot_be_forged() {
        assert_ne!(
            sanitize_for_display("\\u{1b}"),
            sanitize_for_display("\u{1b}")
        );
    }

    #[test]
    fn hidden_characters_outside_the_common_ranges_are_caught() {
        for c in [
            '\u{110bd}',
            '\u{13430}',
            '\u{1bca0}',
            '\u{1d173}',
            '\u{34f}',
            '\u{3164}',
            '\u{e0100}',
            '\u{fe0f}',
        ] {
            let name = format!("ma{c}in");
            assert!(!is_clean_label(&name), "{c:?}");
            assert_ne!(sanitize_for_display(&name), name, "{c:?}");
        }
        for c in ['\u{e0041}', '\u{200b}', '\u{feff}', '\u{ad}'] {
            assert!(!is_clean_text(&format!("a{c}b")), "{c:?}");
        }
        assert!(is_clean_text("\u{2764}\u{fe0f}"), "emoji presentation");
    }

    #[test]
    fn label_and_text_policies_differ() {
        assert!(is_clean_label("int (*)(char *)"));
        assert!(!is_clean_label("a\u{200b}b"));
        assert!(!is_clean_label("a\tb"));
        assert!(is_clean_text("line one\n\tline two"));
        // Directional marks and joiners occur in ordinary RTL and Indic text.
        assert!(is_clean_text(
            "\u{5d0}\u{200f}, \u{915}\u{94d}\u{200d}\u{937}"
        ));
        assert!(!is_clean_text("a\u{1b}[2J"));
        assert!(!is_clean_text("a\u{202e}b"));
        assert!(!is_clean_text("a\rb"));
        assert!(!is_clean_text("a\u{2028}b"));
    }
}
