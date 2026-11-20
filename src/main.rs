use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

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

#[derive(Debug, Deserialize, Clone)]
struct Config {
    #[serde(default)]
    general: GeneralConfig,
    #[serde(default)]
    workspaces: WorkspacesConfig,
    #[serde(default)]
    commands: CommandsConfig,
    #[serde(default)]
    security: SecurityConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct GeneralConfig {
    #[serde(default = "default_max_cargo_jobs")]
    max_cargo_jobs: u32,
}

fn default_max_cargo_jobs() -> u32 {
    2
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            max_cargo_jobs: default_max_cargo_jobs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
struct WorkspacesConfig {
    #[serde(default)]
    trusted: Vec<String>,
    #[serde(default)]
    forbidden_bash: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct CommandsConfig {
    #[serde(default)]
    allow: BTreeSet<String>,
    #[serde(default)]
    allow_pipe_filters: BTreeSet<String>,
    #[serde(default)]
    forbidden_native: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct SecurityConfig {
    #[serde(default)]
    destructive_commands: BTreeSet<String>,
    #[serde(default)]
    deny_patterns: Vec<DenyPatternConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct DenyPatternConfig {
    pattern: String,
    reason: String,
}

impl Config {
    fn load() -> Self {
        // 1. Explicit env var override
        if let Ok(path) = std::env::var("AGY_INTERCEPT_CONFIG") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return cfg;
                }
            }
        }

        // 2. User home configs (e.g. mkOutOfStoreSymlink from NixOS / Home Manager)
        if let Ok(home) = std::env::var("HOME") {
            let user_configs = [
                format!("{home}/.config/antigravity/intercept-bash.toml"),
                format!("{home}/.gemini/antigravity-cli/intercept-bash.toml"),
            ];
            for path_str in &user_configs {
                let p = Path::new(path_str);
                if p.exists() {
                    if let Ok(content) = fs::read_to_string(p) {
                        if let Ok(cfg) = toml::from_str::<Config>(&content) {
                            return cfg;
                        }
                    }
                }
            }
        }

        // 3. System-wide /etc config
        const SYSTEM_CONFIG: &str = "/etc/antigravity/intercept-bash.toml";
        if Path::new(SYSTEM_CONFIG).exists() {
            if let Ok(content) = fs::read_to_string(SYSTEM_CONFIG) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return cfg;
                }
            }
        }

        // 4. Local repo fallback
        const LOCAL_CONFIG: &str = "./intercept-bash.toml";
        if Path::new(LOCAL_CONFIG).exists() {
            if let Ok(content) = fs::read_to_string(LOCAL_CONFIG) {
                if let Ok(cfg) = toml::from_str::<Config>(&content) {
                    return cfg;
                }
            }
        }

        Self::default_builtin()
    }

    fn default_builtin() -> Self {
        let mut allow = BTreeSet::new();
        for cmd in [
            "cargo",
            "rustc",
            "rustup",
            "git",
            "nix",
            "nixos-rebuild",
            "nix-build",
            "nix-shell",
            "nix-prefetch-url",
            "nvfetcher",
            "gh",
            "nr-switch",
            "prek",
            "agy",
            "bs",
            "samply",
            "ferric",
            "profiler-cli",
            "pq",
            "dhat-to-flamegraph",
            "jq",
            "cd",
            "pwd",
            "echo",
            "printf",
            "mkdir",
            "cp",
            "mv",
            "touch",
            "which",
            "whereis",
            "type",
            "curl",
            "wget",
            "tar",
            "gzip",
            "gunzip",
            "xz",
            "unzip",
            "zip",
            "python",
            "python3",
            "chmod",
            "test",
            "[",
            "true",
            "false",
            "env",
            "mcpls",
            "lspmux",
            "clear",
            "diff",
        ] {
            allow.insert(cmd.to_string());
        }

        let mut allow_pipe_filters = BTreeSet::new();
        for cmd in [
            "grep", "rg", "head", "tail", "wc", "sed", "awk", "cut", "tr", "sort", "uniq", "jq",
            "cat", "bat", "less", "more", "tee",
        ] {
            allow_pipe_filters.insert(cmd.to_string());
        }

        let mut destructive_commands = BTreeSet::new();
        for cmd in [
            "mkfs", "wipefs", "shred", "fdisk", "parted", "reboot", "shutdown", "poweroff", "su",
            "doas",
        ] {
            destructive_commands.insert(cmd.to_string());
        }

        let mut forbidden_native = BTreeMap::new();
        forbidden_native.insert(
            "tree".to_string(),
            "Не используй `tree` в Bash. Используй нативные средства исследования файлов."
                .to_string(),
        );

        let deny_patterns = vec![
            DenyPatternConfig {
                pattern: "rm\\s+.*-(r.*f|f.*r)".to_string(),
                reason: "Заблокировано опасное рекурсивное/принудительное удаление (rm -rf)."
                    .to_string(),
            },
            DenyPatternConfig {
                pattern: "dd\\s+if=".to_string(),
                reason: "Заблокирована команда прямого блочного чтения/записи dd.".to_string(),
            },
            DenyPatternConfig {
                pattern: "(curl|wget).*\\|.*(sh|bash|zsh|fish)".to_string(),
                reason: "Заблокировано выполнение внешних скриптов напрямую из сети.".to_string(),
            },
            DenyPatternConfig {
                pattern: "git\\s+(push\\s+(--force|-f)|reset\\s+--hard|clean\\s+-[a-zA-Z]*f)"
                    .to_string(),
                reason: "Заблокирована деструктивная Git-операция.".to_string(),
            },
        ];

        Self {
            general: GeneralConfig { max_cargo_jobs: 2 },
            workspaces: WorkspacesConfig {
                trusted: vec!["/home/user/nixos-config".to_string()],
                forbidden_bash: vec!["/home/user/projects/libera-reader".to_string()],
            },
            commands: CommandsConfig {
                allow,
                allow_pipe_filters,
                forbidden_native,
            },
            security: SecurityConfig {
                destructive_commands,
                deny_patterns,
            },
        }
    }
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
        while let Some(&b) = self.bytes.get(self.pos) {
            match b {
                b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn parse_object(&mut self) -> Option<Json> {
        if self.bump()? != b'{' {
            return None;
        }
        let mut entries = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.bump();
                return Some(Json::Object(entries));
            }

            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump()? != b':' {
                return None;
            }
            let value = self.parse_value()?;
            entries.push((key, value));

            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.bump();
                }
                b'}' => {
                    self.bump();
                    return Some(Json::Object(entries));
                }
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self) -> Option<Json> {
        if self.bump()? != b'[' {
            return None;
        }
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.bump();
                return Some(Json::Array(items));
            }

            let item = self.parse_value()?;
            items.push(item);

            self.skip_ws();
            match self.peek()? {
                b',' => {
                    self.bump();
                }
                b']' => {
                    self.bump();
                    return Some(Json::Array(items));
                }
                _ => return None,
            }
        }
    }

    fn parse_hex_digit(&mut self) -> Option<u32> {
        let b = self.bump()?;
        match b {
            b'0'..=b'9' => Some((b - b'0') as u32),
            b'a'..=b'f' => Some((b - b'a' + 10) as u32),
            b'A'..=b'F' => Some((b - b'A' + 10) as u32),
            _ => None,
        }
    }

    fn parse_unicode_escape(&mut self, out: &mut Vec<u8>) -> Option<()> {
        let d1 = self.parse_hex_digit()?;
        let d2 = self.parse_hex_digit()?;
        let d3 = self.parse_hex_digit()?;
        let d4 = self.parse_hex_digit()?;
        let mut code = (d1 << 12) | (d2 << 8) | (d3 << 4) | d4;

        if (0xD800..=0xDBFF).contains(&code) {
            if self.bump()? != b'\\' || self.bump()? != b'u' {
                return None;
            }
            let s1 = self.parse_hex_digit()?;
            let s2 = self.parse_hex_digit()?;
            let s3 = self.parse_hex_digit()?;
            let s4 = self.parse_hex_digit()?;
            let trail = (s1 << 12) | (s2 << 8) | (s3 << 4) | s4;
            if !(0xDC00..=0xDFFF).contains(&trail) {
                return None;
            }
            code = 0x10000 + (((code - 0xD800) << 10) | (trail - 0xDC00));
        }

        let ch = char::from_u32(code)?;
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        out.extend_from_slice(encoded.as_bytes());
        Some(())
    }

    fn parse_string(&mut self) -> Option<String> {
        if self.bump()? != b'"' {
            return None;
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
                ';' | '\n' => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        result.push(trimmed.to_string());
                    }
                    current.clear();
                }
                '&' if chars.peek() == Some(&'&') => {
                    chars.next();
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        result.push(trimmed.to_string());
                    }
                    current.clear();
                }
                '|' if chars.peek() == Some(&'|') => {
                    chars.next();
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        result.push(trimmed.to_string());
                    }
                    current.clear();
                }
                _ => current.push(ch),
            },
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        result.push(trimmed.to_string());
    }

    result
}

fn split_pipes(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote: Option<Quote> = None;
    let mut escaped = false;

    for ch in input.chars() {
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
                '|' => {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        result.push(trimmed.to_string());
                    }
                    current.clear();
                }
                _ => current.push(ch),
            },
        }
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        result.push(trimmed.to_string());
    }

    result
}

fn tokenize_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<Quote> = None;
    let mut escaped = false;

    for ch in input.chars() {
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
            Some(Quote::Single) => {
                if ch == '\'' {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            Some(Quote::Double) => {
                if ch == '"' {
                    quote = None;
                } else {
                    current.push(ch);
                }
            }
            None => match ch {
                '\'' => quote = Some(Quote::Single),
                '"' => quote = Some(Quote::Double),
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        words.push(current.clone());
                        current.clear();
                    }
                }
                _ => current.push(ch),
            },
        }
    }

    if !current.is_empty() {
        words.push(current);
    }

    words
}

fn extract_command(stage: &str) -> Option<(String, Vec<String>)> {
    let raw_tokens = tokenize_words(stage);
    let mut tokens = raw_tokens.into_iter();

    while let Some(tok) = tokens.next() {
        if tok.contains('=') && !tok.starts_with('-') {
            continue;
        }
        if tok == "env" || tok == "nohup" || tok == "nice" || tok == "time" {
            continue;
        }

        let prog_name = Path::new(&tok)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&tok)
            .to_string();

        let args: Vec<String> = tokens.collect();
        return Some((prog_name, args));
    }

    None
}

fn is_dangerous_rm(args: &[String]) -> bool {
    let mut is_recursive = false;
    let mut targets = Vec::new();

    for arg in args {
        if arg == "--" {
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") {
            if arg.contains('r') || arg.contains('R') {
                is_recursive = true;
            }
        } else if arg == "--recursive" {
            is_recursive = true;
        } else if !arg.starts_with('-') {
            targets.push(arg.as_str());
        }
    }

    if !is_recursive {
        return false;
    }

    for target in targets {
        let clean = target.trim_end_matches('/');
        if clean.is_empty()
            || clean == "/"
            || clean == "/*"
            || clean == "~"
            || clean == "$HOME"
            || clean == "${HOME}"
            || clean == "/home/user"
            || clean == "/etc"
            || clean == "/usr"
            || clean == "/var"
            || clean == "/boot"
            || clean == "/root"
            || target.starts_with("~/")
            || target.starts_with("$HOME/")
            || target.starts_with("${HOME}/")
            || target.starts_with("/home/user/")
            || target.starts_with("/home/user")
            || target.starts_with("/etc/")
            || target.starts_with("/usr/")
            || target.starts_with("/var/")
        {
            return true;
        }
    }

    false
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

fn check_dangerous_command(prog: &str, args: &[String], config: &Config) -> Option<String> {
    if prog.starts_with("mkfs") || config.security.destructive_commands.contains(prog) {
        return Some("Заблокирована опасная системная команда.".to_string());
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

fn check_cargo_jobs(args: &[String], max_jobs: u32) -> Option<String> {
    for (idx, arg) in args.iter().enumerate() {
        let parsed = match arg.as_str() {
            "-j" | "--jobs" => args.get(idx + 1).and_then(|v| v.parse::<u32>().ok()),
            _ => arg
                .strip_prefix("--jobs=")
                .or_else(|| arg.strip_prefix("-j"))
                .and_then(|v| v.parse::<u32>().ok()),
        };

        if let Some(jobs) = parsed {
            if jobs > max_jobs {
                return Some(format!(
                    "На 2-ядерном i3-6006U запрещено cargo -j {jobs}. Максимум -j {max_jobs} (уже задано глобально)."
                ));
            }
        }
    }
    None
}

fn is_dangerous_pipe_target(prog: &str) -> bool {
    matches!(prog, "sh" | "bash" | "zsh" | "fish" | "xargs")
}

fn check_shell_inline(prog: &str, args: &[String], depth: u8, config: &Config) -> Option<Decision> {
    if !matches!(prog, "sh" | "bash" | "zsh" | "fish") || depth >= 4 {
        return None;
    }

    let c_pos = args.iter().position(|a| a == "-c")?;
    let inner = args.get(c_pos + 1)?;
    match evaluate_command(inner, depth + 1, config) {
        Decision::Deny(reason) => Some(Decision::Deny(reason)),
        Decision::Allow | Decision::ForceAsk(_) => None,
    }
}

fn evaluate_command(cmd: &str, depth: u8, config: &Config) -> Decision {
    if cmd.trim().is_empty() {
        return Decision::Allow;
    }

    for dp in &config.security.deny_patterns {
        if cmd.contains(&dp.pattern) {
            return Decision::Deny(dp.reason.clone());
        }
    }

    let mut unknown = BTreeSet::new();

    for stmt in split_statements(cmd) {
        let pipe_parts = split_pipes(&stmt);
        let mut iter = pipe_parts.iter();

        if let Some(first) = iter.next() {
            if let Some((prog, args)) = extract_command(first) {
                if let Some(reason) = check_dangerous_command(&prog, &args, config) {
                    return Decision::Deny(reason);
                }

                if let Some(decision) = check_shell_inline(&prog, &args, depth, config) {
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
                    if let Some(reason) = check_cargo_jobs(&args, config.general.max_cargo_jobs) {
                        return Decision::Deny(reason);
                    }
                }

                if let Some(reason) = config.commands.forbidden_native.get(&prog) {
                    return Decision::Deny(reason.to_string());
                }

                if !config.commands.allow.contains(&prog) {
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

                if let Some(reason) = check_dangerous_command(&prog, &args, config) {
                    return Decision::Deny(reason);
                }

                if !config.commands.allow_pipe_filters.contains(&prog)
                    && !config.commands.allow.contains(&prog)
                {
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

fn handle_stdin(raw: &str, config: &Config) -> Decision {
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

    let cwd_opt = root.get("cwd").and_then(Json::as_str);
    let workspace_paths: Vec<&str> = root
        .get("workspacePaths")
        .map(|wp| match wp {
            Json::Array(arr) => arr.iter().filter_map(Json::as_str).collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default();

    let is_forbidden_workspace = cwd_opt
        .map(|cwd| {
            config
                .workspaces
                .forbidden_bash
                .iter()
                .any(|fb| cwd == fb || cwd.starts_with(&format!("{fb}/")))
        })
        .unwrap_or(false)
        || workspace_paths.iter().any(|w| {
            config
                .workspaces
                .forbidden_bash
                .iter()
                .any(|fb| *w == fb || w.starts_with(&format!("{fb}/")))
        });

    if is_forbidden_workspace {
        let target = cwd_opt.unwrap_or_else(|| workspace_paths.first().copied().unwrap_or(""));
        return Decision::Deny(format!(
            "В рабочей директории `{target}` запрещено выполнение Bash-команд. Используй нативные инструменты: чтение/редактирование файлов (read_file/edit_file), LSP (mcpls) и MCP-серверы."
        ));
    }

    let is_trusted_workspace = cwd_opt
        .map(|cwd| {
            config
                .workspaces
                .trusted
                .iter()
                .any(|t| cwd == t || cwd.starts_with(&format!("{t}/")))
        })
        .unwrap_or(false)
        || workspace_paths.iter().any(|w| {
            config
                .workspaces
                .trusted
                .iter()
                .any(|t| *w == t || w.starts_with(&format!("{t}/")))
        });

    let decision = evaluate_command(cmd, 0, config);
    if is_trusted_workspace {
        match decision {
            Decision::ForceAsk(_) => Decision::Allow,
            other => other,
        }
    } else {
        decision
    }
}

fn main() {
    let config = Config::load();
    let mut raw = String::new();
    let decision = match io::stdin().read_to_string(&mut raw) {
        Ok(_) => handle_stdin(&raw, &config),
        Err(_) => Decision::Allow,
    };

    let out = format_decision(&decision);
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(out.as_bytes());
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::default_builtin()
    }

    #[test]
    fn allows_pipes_and_cargo_default() {
        let cfg = test_config();
        assert_eq!(
            evaluate_command("git log -n 10 | grep feat", 0, &cfg),
            Decision::Allow
        );
        assert_eq!(evaluate_command("cargo check", 0, &cfg), Decision::Allow);
        assert_eq!(
            evaluate_command("RUST_LOG=debug cargo test", 0, &cfg),
            Decision::Allow
        );
    }

    #[test]
    fn allows_multiline_cyrillic_git_commit() {
        let cfg = test_config();
        let cmd = "git commit -S -m \"feat: добавлен модуль\" -m \"Детали:\n- пункт 1; пункт 2\n- пункт 3\"";
        assert_eq!(evaluate_command(cmd, 0, &cfg), Decision::Allow);
    }

    #[test]
    fn denies_high_cargo_jobs_and_slow_nix() {
        let cfg = test_config();
        assert!(matches!(
            evaluate_command("cargo test -j 4", 0, &cfg),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("cargo build --jobs=8", 0, &cfg),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("nix search nixpkgs rust", 0, &cfg),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn denies_dangerous_pipes_and_shell_bypass() {
        let cfg = test_config();
        assert!(matches!(
            evaluate_command("echo \"rm -rf /\" | sh", 0, &cfg),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("bash -c \"rm -rf /home/user/test\"", 0, &cfg),
            Decision::Deny(_)
        ));
        assert!(matches!(
            evaluate_command("git push --force", 0, &cfg),
            Decision::Deny(_)
        ));
    }

    #[test]
    fn force_asks_unknown_in_untrusted() {
        let cfg = test_config();
        assert!(matches!(
            evaluate_command("mutool info book.pdf", 0, &cfg),
            Decision::ForceAsk(_)
        ));
    }

    #[test]
    fn allows_all_safe_commands_in_nixos_config() {
        let cfg = test_config();
        let payload = r#"{"cwd":"/home/user/nixos-config","toolCall":{"name":"run_command","args":{"CommandLine":"mutool info book.pdf"}}}"#;
        assert_eq!(handle_stdin(payload, &cfg), Decision::Allow);
    }

    #[test]
    fn denies_bash_in_forbidden_workspaces() {
        let cfg = test_config();
        let payload = r#"{"cwd":"/home/user/projects/libera-reader","toolCall":{"name":"run_command","args":{"CommandLine":"cargo check"}}}"#;
        assert!(matches!(handle_stdin(payload, &cfg), Decision::Deny(_)));

        let payload_sub = r#"{"cwd":"/home/user/projects/libera-reader/src/ui","toolCall":{"name":"run_command","args":{"CommandLine":"git status"}}}"#;
        assert!(matches!(handle_stdin(payload_sub, &cfg), Decision::Deny(_)));
    }

    #[test]
    fn handles_full_json_payload_with_cyrillic_and_escapes() {
        let cfg = test_config();
        let payload = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git commit -S -m \"feat: тест\" -m \"Строка 1\n- пункт; 2\""}}}"#;
        assert_eq!(handle_stdin(payload, &cfg), Decision::Allow);
    }
}
