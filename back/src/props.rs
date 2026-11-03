//! Parsing and rendering of the text formats applications load configuration from:
//! Java `.properties` (the `java.util.Properties` grammar), dotenv files, and shell exports.
use std::collections::BTreeMap;

pub type Map = BTreeMap<String, String>;

/// Parses `.properties` text following `java.util.Properties#load`: `#`/`!` comments,
/// `=`/`:`/whitespace separators, backslash line continuations and escapes, `\uXXXX`.
pub fn parse_properties(text: &str) -> Map {
    let mut out = Map::new();
    let mut lines = text.lines();
    while let Some(first) = lines.next() {
        let trimmed = first.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        let mut logical = String::new();
        let mut current = trimmed.to_owned();
        loop {
            let trailing = current.chars().rev().take_while(|c| *c == '\\').count();
            if trailing % 2 == 1 {
                current.pop();
                logical.push_str(&current);
                match lines.next() {
                    Some(next) => current = next.trim_start().to_owned(),
                    None => break,
                }
            } else {
                logical.push_str(&current);
                break;
            }
        }
        let (key, value) = split_entry(&logical);
        out.insert(unescape(key), unescape(value));
    }
    out
}

fn split_entry(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'=' | b':' | b' ' | b'\t' | b'\x0c' => break,
            _ => i += 1,
        }
    }
    let i = i.min(bytes.len());
    let key = &line[..i];
    let mut rest = line[i..].trim_start_matches([' ', '\t', '\x0c']);
    if let Some(stripped) = rest.strip_prefix(['=', ':']) {
        rest = stripped.trim_start_matches([' ', '\t', '\x0c']);
    }
    (key, rest)
}

fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    let mut pending_high: Option<u32> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('f') => out.push('\x0c'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let Ok(unit) = u32::from_str_radix(&hex, 16) else {
                    out.push_str(&hex);
                    continue;
                };
                if (0xD800..0xDC00).contains(&unit) {
                    pending_high = Some(unit);
                    continue;
                }
                let code = match pending_high.take() {
                    Some(high) if (0xDC00..0xE000).contains(&unit) => {
                        0x10000 + ((high - 0xD800) << 10) + (unit - 0xDC00)
                    }
                    _ => unit,
                };
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

fn escape(text: &str, is_key: bool, out: &mut String) {
    for (index, c) in text.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\x0c' => out.push_str("\\f"),
            ' ' if is_key || index == 0 => out.push_str("\\ "),
            '=' | ':' | '#' | '!' if is_key || index == 0 => {
                out.push('\\');
                out.push(c);
            }
            // ISO-8859-1 safe: Spring Boot and Properties#load(InputStream) both read Latin-1.
            c if !c.is_ascii() || c.is_ascii_control() => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04X}"));
                }
            }
            c => out.push(c),
        }
    }
}

pub fn render_properties(map: &Map, header: &str) -> String {
    let mut out = format!("# {header}\n");
    for (key, value) in map {
        escape(key, true, &mut out);
        out.push('=');
        escape(value, false, &mut out);
        out.push('\n');
    }
    out
}

/// Parses dotenv text: `KEY=value`, optional `export`, single/double quotes, `#` comments.
pub fn parse_dotenv(text: &str) -> Map {
    let mut out = Map::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = if let Some(inner) = value.strip_prefix('"') {
            let mut parsed = String::new();
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => match chars.next() {
                        Some('n') => parsed.push('\n'),
                        Some('t') => parsed.push('\t'),
                        Some(other) => parsed.push(other),
                        None => {}
                    },
                    c => parsed.push(c),
                }
            }
            parsed
        } else if let Some(inner) = value.strip_prefix('\'') {
            inner.split('\'').next().unwrap_or("").to_owned()
        } else {
            value.split(" #").next().unwrap_or("").trim_end().to_owned()
        };
        out.insert(key.trim().to_owned(), value);
    }
    out
}

/// `spring.datasource.url` → `SPRING_DATASOURCE_URL`, matching Spring's relaxed binding.
pub fn env_name(key: &str) -> String {
    let mut name: String = key
        .chars()
        .filter(|c| *c != ']')
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name.insert(0, '_');
    }
    name
}

pub fn render_dotenv(map: &Map) -> String {
    let mut out = String::new();
    for (key, value) in map {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('$', "\\$");
        out.push_str(&format!("{}=\"{escaped}\"\n", env_name(key)));
    }
    out
}

pub fn render_shell(map: &Map) -> String {
    let mut out = String::new();
    for (key, value) in map {
        out.push_str(&format!(
            "export {}='{}'\n",
            env_name(key),
            value.replace('\'', "'\\''")
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_properties_grammar() {
        let map = parse_properties(
            "# comment\n! also comment\nspring.datasource.url = jdbc:postgresql://db/app\n\
             password:p\\=ss\\u00e9\nmulti=one \\\n    two\nspaced\\ key value\nempty=\n",
        );
        assert_eq!(map["spring.datasource.url"], "jdbc:postgresql://db/app");
        assert_eq!(map["password"], "p=ssé");
        assert_eq!(map["multi"], "one two");
        assert_eq!(map["spaced key"], "value");
        assert_eq!(map["empty"], "");
        assert_eq!(map.len(), 5);
    }

    #[test]
    fn properties_round_trip() {
        let mut map = Map::new();
        map.insert("a key=:".into(), " leading\nline\ttab é 🔑 \\".into());
        map.insert("plain".into(), "x=y#z".into());
        let rendered = render_properties(&map, "test");
        assert!(rendered.is_ascii());
        assert_eq!(parse_properties(&rendered), map);
    }

    #[test]
    fn env_formats() {
        let mut map = Map::new();
        map.insert("spring.datasource.password".into(), "it's \"$x\"".into());
        map.insert("app.hosts[0]".into(), "a".into());
        assert_eq!(
            render_shell(&map),
            "export APP_HOSTS_0='a'\nexport SPRING_DATASOURCE_PASSWORD='it'\\''s \"$x\"'\n"
        );
        let dotenv = render_dotenv(&map);
        let parsed = parse_dotenv(&dotenv);
        assert_eq!(parsed["SPRING_DATASOURCE_PASSWORD"], "it's \"$x\"");
        let parsed = parse_dotenv("export A='x # y'\nB=plain # comment\n# skip\nC=\"q\\nr\"");
        assert_eq!(parsed["A"], "x # y");
        assert_eq!(parsed["B"], "plain");
        assert_eq!(parsed["C"], "q\nr");
    }
}
