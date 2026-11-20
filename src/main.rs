use std::collections::BTreeSet;
use std::io::{self, Read, Write};

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny(String),
    ForceAsk(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    Single,
    Double,
}

#[allow(dead_code)]
enum Json {
    Object(Vec<(String, Json)>),
    Array(Vec<Json>),
    Str(String),
    Other,
}

impl Json {
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            Json::Array(_) | Json::Str(_) | Json::Other => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            Json::Object(_) | Json::Array(_) | Json::Other => None,
        }
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            match b {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn consume_bytes(&mut self, expected: &[u8]) -> bool {
        match self.bytes.get(self.pos..self.pos + expected.len()) {
            Some(slice) if slice == expected => {
                self.pos += expected.len();
                true
            }
            _ => false,
        }
    }

    fn parse_value(&mut self) -> Option<Json> {
        self.skip_ws();
        match self.peek()? {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string().map(Json::Str),
            b't' => self.consume_bytes(b"true").then_some(Json::Other),
            b'f' => self.consume_bytes(b"false").then_some(Json::Other),
            b'n' => self.consume_bytes(b"null").then_some(Json::Other),
            b'-' | b'0'..=b'9' => {
                self.skip_number();
                Some(Json::Other)
            }
            _ => None,
        }
    }

    fn skip_number(&mut self) {
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn parse_object(&mut self) -> Option<Json> {
        self.bump()?; // '{'
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Some(Json::Object(entries));
        }

        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            match self.bump()? {
                b':' => {}
                _ => return None,
            }
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b'}' => return Some(Json::Object(entries)),
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self) -> Option<Json> {
        self.bump()?; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Some(Json::Array(items));
        }

        loop {
            let val = self.parse_value()?;
            items.push(val);
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b']' => return Some(Json::Array(items)),
                _ => return None,
            }
        }
    }

    fn parse_hex4(&mut self) -> Option<u16> {
        let slice = self.bytes.get(self.pos..self.pos + 4)?;
        let text = std::str::from_utf8(slice).ok()?;
        let val = u16::from_str_radix(text, 16).ok()?;
        self.pos += 4;
        Some(val)
    }

    fn parse_unicode_escape(&mut self, out: &mut Vec<u8>) -> Option<()> {
        let first = self.parse_hex4()?;
        let ch = match (0xD800..=0xDBFF).contains(&first) {
            true => {
                if !self.consume_bytes(b"\\u") {
                    return None;
                }
                let second = self.parse_hex4()?;
                if !(0xDC00..=0xDFFF).contains(&second) {
                    return None;
                }
                let code = 0x10000 + (((first - 0xD800) as u32) << 10) + ((second - 0xDC00) as u32);
                char::from_u32(code)?
            }
            false => char::from_u32(first as u32)?,
        };
        let mut utf8_buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut utf8_buf).as_bytes());
        Some(())
    }

    fn parse_string(&mut self) -> Option<String> {
        match self.bump()? {
            b'"' => {}
            _ => return None,
        }
        let mut out = Vec::new();
        while let Some(b) = self.bump() {
            match b {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => match self.bump()? {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'u' => self.parse_unicode_escape(&mut out)?,
                    _ => return None,
                },
                other => out.push(other),
            }
        }
        None
    }
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn format_decision(decision: &Decision) -> String {
    match decision {
        Decision::Allow => r#"{"decision":"allow"}"#.to_string(),
        Decision::Deny(reason) => {
            format!(
                r#"{{"decision":"deny","reason":"{}"}}"#,
                escape_json(reason)
            )
        }
        Decision::ForceAsk(reason) => {
            format!(
                r#"{{"decision":"force_ask","reason":"{}"}}"#,
                escape_json(reason)
            )
        }
    }
}

fn split_statements(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote: Option<Quote> = None;
    let mut escaped = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && quote != Some(Quote::Single) {
            current.push(ch);
            escaped = true;
            continue;
        }

        match quote {
            Some(Quote::Single) => {
                current.push(ch);
                if ch == '\'' {
                    quote = None;
                }
            }
            Some(Quote::Double) => {
                current.push(ch);
                if ch == '"' {
                    quote = None;
                }
            }
            None => match ch {
                '\'' => {
                    quote = Some(Quote::Single);
                    current.push(ch);
                }
                '"' => {
                    quote = Some(Quote::Double);
                    current.push(ch);
                }
                '&' if chars.peek() == Some(&'&') => {
                    chars.next();
                    push_trimmed(&mut result, &mut current);
                }
                '|' if chars.peek() == Some(&'|') => {
                    chars.next();
                    push_trimmed(&mut result, &mut current);
                }
                ';' | '\n' => push_trimmed(&mut result, &mut current),
                other => current.push(other),
            },
        }
    }

    push_trimmed(&mut result, &mut current);
    result
}

fn split_pipes(stmt: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote: Option<Quote> = None;
    let mut escaped = false;

    for ch in stmt.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && quote != Some(Quote::Single) {
            current.push(ch);
            escaped = true;
            continue;
        }

        match quote {
            Some(Quote::Single) => {
                current.push(ch);
                if ch == '\'' {
                    quote = None;
                }
            }
            Some(Quote::Double) => {
                current.push(ch);
                if ch == '"' {
                    quote = None;
                }
            }
            None => match ch {
                '\'' => {
                    quote = Some(Quote::Single);
                    current.push(ch);
                }
                '"' => {
                    quote = Some(Quote::Double);
                    current.push(ch);
                }
                '|' => push_trimmed(&mut parts, &mut current),
                other => current.push(other),
            },
        }
    }

    push_trimmed(&mut parts, &mut current);
    parts
}

fn tokenize(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<Quote> = None;
    let mut escaped = false;

    for ch in segment.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' && quote != Some(Quote::Single) {
            escaped = true;
            continue;
        }

        match quote {
            Some(Quote::Single) => match ch {
                '\'' => quote = None,
                other => current.push(other),
            },
            Some(Quote::Double) => match ch {
                '"' => quote = None,
                other => current.push(other),
            },
            None => match ch {
                '\'' => quote = Some(Quote::Single),
                '"' => quote = Some(Quote::Double),
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                other => current.push(other),
            },
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn push_trimmed(target: &mut Vec<String>, current: &mut String) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        target.push(trimmed.to_string());
    }
    current.clear();
}

fn is_env_assignment(token: &str) -> bool {
    match token.split_once('=') {
        Some((key, _)) if !key.is_empty() => {
            let mut bytes = key.bytes();
            let first_ok = match bytes.next() {
                Some(b) => b.is_ascii_alphabetic() || b == b'_',
                None => false,
            };
            first_ok && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }
        _ => false,
    }
}

fn extract_command(segment: &str) -> Option<(String, Vec<String>)> {
    let cleaned = segment.trim().trim_start_matches('(').trim();
    let tokens = tokenize(cleaned);
    let start = tokens
        .iter()
        .position(|tok| tok != "env" && !is_env_assignment(tok))?;

    let raw_prog = tokens.get(start)?;
    let prog = raw_prog.rsplit('/').next().unwrap_or(raw_prog).to_string();
    let args = tokens.into_iter().skip(start + 1).collect();
    Some((prog, args))
}

fn is_dangerous_rm(args: &[String]) -> bool {
    let mut has_recursive = false;
    let mut targets_critical = false;
    let mut end_of_flags = false;

    for arg in args {
        if !end_of_flags && arg == "--" {
            end_of_flags = true;
            continue;
        }
        if !end_of_flags && arg.starts_with('-') {
            let short_r = !arg.starts_with("--") && (arg.contains('r') || arg.contains('R'));
            if arg == "--recursive" || short_r {
                has_recursive = true;
            }
            continue;
        }
        let critical = matches!(arg.as_str(), "/" | "/*" | "~" | "$HOME")
            || arg.starts_with("~/")
            || arg.starts_with("$HOME/")
            || arg.starts_with("/home/user");
        if critical {
            targets_critical = true;
        }
    }

    has_recursive && targets_critical
}

fn is_dangerous_git(args: &[String]) -> bool {
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "-C" | "-c" | "--git-dir" | "--work-tree" => idx += 2,
            flag if flag.starts_with('-') => idx += 1,
            _ => break,
        }
    }

    let subcmd = match args.get(idx) {
        Some(s) => s.as_str(),
        None => return false,
    };
    let rest = &args[idx + 1..];

    match subcmd {
        "push" => rest.iter().any(|a| matches!(a.as_str(), "-f" | "--force")),
        "reset" => rest.iter().any(|a| a == "--hard"),
        "clean" => rest.iter().any(|a| {
            a == "--force" || (a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
        }),
        _ => false,
    }
}

fn check_dangerous_command(prog: &str, args: &[String]) -> Option<String> {
    if prog.starts_with("mkfs")
        || matches!(
            prog,
            "wipefs"
                | "shred"
                | "fdisk"
                | "parted"
                | "reboot"
                | "shutdown"
                | "poweroff"
                | "su"
                | "doas"
        )
    {
        return Some("Заблокирована потенциально разрушительная системная команда.".to_string());
    }

    if prog == "dd" && args.iter().any(|a| a.starts_with("if=")) {
        return Some("Заблокирована команда dd.".to_string());
    }

    if prog == "rm" && is_dangerous_rm(args) {
        return Some(
            "Заблокировано рекурсивное удаление системных или домашних директорий.".to_string(),
        );
    }

    if prog == "git" && is_dangerous_git(args) {
        return Some("Заблокирована деструктивная Git-операция.".to_string());
    }

    None
}

fn check_cargo_jobs(args: &[String]) -> Option<String> {
    for (idx, arg) in args.iter().enumerate() {
        let parsed = match arg.as_str() {
            "-j" | "--jobs" => args.get(idx + 1).and_then(|v| v.parse::<u32>().ok()),
            _ => arg
                .strip_prefix("--jobs=")
                .or_else(|| arg.strip_prefix("-j"))
                .and_then(|v| v.parse::<u32>().ok()),
        };

        if let Some(jobs) = parsed {
            if jobs > 2 {
                return Some(format!(
                    "На 2-ядерном i3-6006U запрещено cargo -j {jobs}. Максимум -j 2 (уже задано глобально)."
                ));
            }
        }
    }
    None
}

fn forbidden_native_reason(prog: &str) -> Option<&'static str> {
    match prog {
        "ls" | "ll" | "la" | "dir" => {
            Some("Не используй `ls` в Bash. Используй нативный `list_dir` или `find_by_name`.")
        }
        "tree" => {
            Some("Не используй `tree` в Bash. Используй `list_dir`, `find_by_name` или `codebase-memory`.")
        }
        "cat" | "bat" => Some("Не используй `cat`/`bat` в Bash. Используй нативный `view_file`."),
        "head" | "tail" => {
            Some("Не используй `head`/`tail` в Bash. Используй `view_file` с диапазоном строк.")
        }
        "find" | "fd" | "locate" => {
            Some("Не используй `find`/`fd` в Bash. Используй `find_by_name` или `codebase-memory`.")
        }
        "grep" | "rg" | "ripgrep" | "ag" | "ack" => Some(
            "Не используй CLI `grep`/`rg` для поиска по коду. Используй `codebase-memory`, LSP или нативный `grep_search`.",
        ),
        "sed" => Some("Не используй `sed` для правок файлов. Используй нативный `replace_file_content`."),
        "awk" | "wc" | "stat" => {
            Some("Не используй `awk`/`wc`/`stat` в Bash. Используй нативные файловые инструменты.")
        }
        _ => None,
    }
}

fn is_allowed_cmd(prog: &str) -> bool {
    matches!(
        prog,
        "cargo"
            | "rustc"
            | "rustup"
            | "git"
            | "nix"
            | "nr-switch"
            | "prek"
            | "agy"
            | "bs"
            | "samply"
            | "ferric"
            | "profiler-cli"
            | "pq"
            | "dhat-to-flamegraph"
            | "jq"
            | "cd"
            | "pwd"
    )
}

fn is_allowed_pipe_filter(prog: &str) -> bool {
    matches!(
        prog,
        "grep" | "rg" | "head" | "tail" | "sort" | "uniq" | "wc" | "cut" | "tr" | "jq" | "tee"
    )
}

fn is_dangerous_pipe_target(prog: &str) -> bool {
    matches!(prog, "sh" | "bash" | "zsh" | "fish" | "xargs")
}

fn check_shell_inline(prog: &str, args: &[String], depth: u8) -> Option<Decision> {
    if !matches!(prog, "sh" | "bash" | "zsh" | "fish") || depth >= 4 {
        return None;
    }

    let c_pos = args.iter().position(|a| a == "-c")?;
    let inner = args.get(c_pos + 1)?;
    match evaluate_command(inner, depth + 1) {
        Decision::Deny(reason) => Some(Decision::Deny(reason)),
        Decision::Allow | Decision::ForceAsk(_) => None,
    }
}

fn evaluate_command(cmd: &str, depth: u8) -> Decision {
    if cmd.trim().is_empty() {
        return Decision::Allow;
    }

    let mut unknown = BTreeSet::new();

    for stmt in split_statements(cmd) {
        let pipe_parts = split_pipes(&stmt);
        let mut iter = pipe_parts.iter();

        if let Some(first) = iter.next() {
            if let Some((prog, args)) = extract_command(first) {
                if let Some(reason) = check_dangerous_command(&prog, &args) {
                    return Decision::Deny(reason);
                }

                if let Some(decision) = check_shell_inline(&prog, &args, depth) {
                    return decision;
                }

                let is_slow_nix = (prog == "nix"
                    && args.first().map(String::as_str) == Some("search"))
                    || (prog == "nix-env" && args.iter().any(|a| a.starts_with("-q")));
                if is_slow_nix {
                    return Decision::Deny(
                        "Запрещён медленный nix search / nix-env -qa. Используй MCP-сервер mcp-nixos."
                            .to_string(),
                    );
                }

                if prog == "cargo" {
                    if let Some(reason) = check_cargo_jobs(&args) {
                        return Decision::Deny(reason);
                    }
                }

                if let Some(reason) = forbidden_native_reason(&prog) {
                    return Decision::Deny(reason.to_string());
                }

                if !is_allowed_cmd(&prog) {
                    unknown.insert(prog);
                }
            }
        }

        for stage in iter {
            if let Some((prog, args)) = extract_command(stage) {
                if is_dangerous_pipe_target(&prog) {
                    return Decision::Deny(format!(
                        "Заблокирована передача вывода через пайп в `{prog}`."
                    ));
                }

                if let Some(reason) = check_dangerous_command(&prog, &args) {
                    return Decision::Deny(reason);
                }

                if !is_allowed_pipe_filter(&prog) && !is_allowed_cmd(&prog) {
                    unknown.insert(prog);
                }
            }
        }
    }

    match unknown.is_empty() {
        true => Decision::Allow,
        false => {
            let list: Vec<&str> = unknown.iter().map(String::as_str).collect();
            Decision::ForceAsk(format!(
                "Команда `{}` не входит в белый список Bash (без спроса: cargo, git, nix, prek, bs, agy, jq). Требуется подтверждение пользователя.",
                list.join(", ")
            ))
        }
    }
}

fn handle_stdin(raw: &str) -> Decision {
    if raw.trim().is_empty() {
        return Decision::Allow;
    }

    let root = match JsonParser::new(raw).parse_value() {
        Some(v) => v,
        None => return Decision::Allow,
    };

    let tool_call = match root.get("toolCall") {
        Some(tc) => tc,
        None => return Decision::Allow,
    };

    if tool_call.get("name").and_then(Json::as_str) != Some("run_command") {
        return Decision::Allow;
    }

    let cmd = match tool_call
        .get("args")
        .and_then(|a| a.get("CommandLine"))
        .and_then(Json::as_str)
    {
        Some(c) => c,
        None => return Decision::Allow,
    };

    evaluate_command(cmd, 0)
}

fn main() {
    let mut raw = String::new();
    let decision = match io::stdin().read_to_string(&mut raw) {
        Ok(_) => handle_stdin(&raw),
        Err(_) => Decision::Allow,
    };

    let out = format_decision(&decision);
    let _ = writeln!(io::stdout(), "{out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_ls_and_cat() {
        assert!(matches!(evaluate_command("ls -la", 0), Decision::Deny(_)));
        assert!(matches!(
            evaluate_command("cd /tmp && cat Cargo.toml", 0),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn allows_pipes_and_cargo_default() {
        assert_eq!(
            evaluate_command("git log -n 10 | grep feat", 0),
            Decision::Allow
        );
        assert_eq!(evaluate_command("cargo check", 0), Decision::Allow);
        assert_eq!(
            evaluate_command("RUST_LOG=debug cargo test", 0),
            Decision::Allow
        );
    }

    #[test]
    fn allows_multiline_cyrillic_git_commit() {
        let cmd = "git commit -S -m \"feat: добавлен модуль\" -m \"Детали:\n- пункт 1; пункт 2\n- пункт 3\"";
        assert_eq!(evaluate_command(cmd, 0), Decision::Allow);
    }

    #[test]
    fn denies_high_cargo_jobs_and_slow_nix() {
        assert!(matches!(
            evaluate_command("cargo test -j 4", 0),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("cargo build --jobs=8", 0),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("nix search nixpkgs rust", 0),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn denies_dangerous_pipes_and_shell_bypass() {
        assert!(matches!(
            evaluate_command("echo \"rm -rf /\" | sh", 0),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("bash -c \"rm -rf /home/user/test\"", 0),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("git push --force", 0),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn force_asks_unknown_and_true_masking() {
        assert!(matches!(
            evaluate_command("mutool info book.pdf", 0),
            Decision::ForceAsk(_)
        ));
        assert!(matches!(
            evaluate_command("cargo test || true", 0),
            Decision::ForceAsk(_)
        ));
        assert!(matches!(
            evaluate_command("python3 -c \"print(1)\"", 0),
            Decision::ForceAsk(_)
        ));
    }

    #[test]
    fn handles_full_json_payload_with_cyrillic_and_escapes() {
        let payload = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git commit -S -m \"feat: тест\" -m \"Строка 1\n- пункт; 2\""}}}"#;
        assert_eq!(handle_stdin(payload), Decision::Allow);
    }
}
