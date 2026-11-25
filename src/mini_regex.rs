#[derive(Clone, Debug)]
enum ClassItem {
    Single(char),
    Range(char, char),
    Whitespace,
    NotWhitespace,
    Digit,
    NotDigit,
    Word,
    NotWord,
}

impl ClassItem {
    fn matches(&self, ch: char) -> bool {
        match self {
            Self::Single(c) => ch == *c,
            Self::Range(a, b) => ch >= *a && ch <= *b,
            Self::Whitespace => ch.is_whitespace(),
            Self::NotWhitespace => !ch.is_whitespace(),
            Self::Digit => ch.is_ascii_digit(),
            Self::NotDigit => !ch.is_ascii_digit(),
            Self::Word => ch.is_alphanumeric() || ch == '_',
            Self::NotWord => !(ch.is_alphanumeric() || ch == '_'),
        }
    }
}

#[derive(Clone, Debug)]
enum CharMatcher {
    Any,
    Literal(char),
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
}

impl CharMatcher {
    fn matches(&self, ch: char) -> bool {
        match self {
            Self::Any => true,
            Self::Literal(c) => ch == *c,
            Self::Class { negated, items } => {
                let hit = items.iter().any(|item| item.matches(ch));
                match negated {
                    true => !hit,
                    false => hit,
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Assertion {
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
}

impl Assertion {
    fn holds(&self, chars: &[char], pos: usize) -> bool {
        let is_word = |idx: usize| -> bool {
            chars
                .get(idx)
                .map(|c| c.is_alphanumeric() || *c == '_')
                .unwrap_or(false)
        };
        match self {
            Self::Start => pos == 0,
            Self::End => pos == chars.len(),
            Self::WordBoundary => {
                let prev = pos.checked_sub(1).map(is_word).unwrap_or(false);
                let next = is_word(pos);
                prev != next
            }
            Self::NotWordBoundary => {
                let prev = pos.checked_sub(1).map(is_word).unwrap_or(false);
                let next = is_word(pos);
                prev == next
            }
        }
    }
}

#[derive(Clone, Debug)]
enum Ast {
    Empty,
    Char(CharMatcher),
    Assert(Assertion),
    Seq(Vec<Ast>),
    Alt(Vec<Ast>),
    Repeat {
        inner: Box<Ast>,
        min: usize,
        unbounded: bool,
    },
}

struct Parser<'a> {
    chars: &'a [char],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(chars: &'a [char]) -> Self {
        Self { chars, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    fn parse_alt(&mut self) -> Result<Ast, String> {
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some('|') {
            self.bump();
            branches.push(self.parse_seq()?);
        }
        match branches.len() {
            1 => Ok(branches.pop().unwrap_or(Ast::Empty)),
            _ => Ok(Ast::Alt(branches)),
        }
    }

    fn parse_seq(&mut self) -> Result<Ast, String> {
        let mut items = Vec::new();
        while let Some(ch) = self.peek() {
            if ch == ')' || ch == '|' {
                break;
            }
            items.push(self.parse_quant()?);
        }
        match items.len() {
            0 => Ok(Ast::Empty),
            1 => Ok(items.pop().unwrap_or(Ast::Empty)),
            _ => Ok(Ast::Seq(items)),
        }
    }

    fn parse_quant(&mut self) -> Result<Ast, String> {
        let atom = self.parse_primary()?;
        let Some(q) = self.peek() else {
            return Ok(atom);
        };
        let (min, unbounded) = match q {
            '*' => (0, true),
            '+' => (1, true),
            '?' => (0, false),
            _ => return Ok(atom),
        };
        self.bump();
        if self.peek() == Some('?') {
            self.bump();
        }
        Ok(Ast::Repeat {
            inner: Box::new(atom),
            min,
            unbounded,
        })
    }

    fn parse_primary(&mut self) -> Result<Ast, String> {
        let ch = self
            .bump()
            .ok_or_else(|| "unexpected end of pattern".to_string())?;
        match ch {
            '(' => {
                if self.chars.get(self.pos..self.pos + 2) == Some(&['?', ':']) {
                    self.pos += 2;
                }
                let inner = self.parse_alt()?;
                match self.bump() {
                    Some(')') => Ok(inner),
                    _ => Err("unclosed '(' in pattern".to_string()),
                }
            }
            '[' => self.parse_class(),
            '.' => Ok(Ast::Char(CharMatcher::Any)),
            '^' => Ok(Ast::Assert(Assertion::Start)),
            '$' => Ok(Ast::Assert(Assertion::End)),
            '\\' => self.parse_escape(),
            '*' | '+' | '?' => Err(format!("unexpected quantifier `{ch}`")),
            other => Ok(Ast::Char(CharMatcher::Literal(other))),
        }
    }

    fn parse_escape(&mut self) -> Result<Ast, String> {
        let esc = self
            .bump()
            .ok_or_else(|| "dangling backslash in pattern".to_string())?;
        match esc {
            's' => Ok(Ast::Char(CharMatcher::Class {
                negated: false,
                items: vec![ClassItem::Whitespace],
            })),
            'S' => Ok(Ast::Char(CharMatcher::Class {
                negated: true,
                items: vec![ClassItem::Whitespace],
            })),
            'd' => Ok(Ast::Char(CharMatcher::Class {
                negated: false,
                items: vec![ClassItem::Digit],
            })),
            'D' => Ok(Ast::Char(CharMatcher::Class {
                negated: true,
                items: vec![ClassItem::Digit],
            })),
            'w' => Ok(Ast::Char(CharMatcher::Class {
                negated: false,
                items: vec![ClassItem::Word],
            })),
            'W' => Ok(Ast::Char(CharMatcher::Class {
                negated: true,
                items: vec![ClassItem::Word],
            })),
            'b' => Ok(Ast::Assert(Assertion::WordBoundary)),
            'B' => Ok(Ast::Assert(Assertion::NotWordBoundary)),
            'n' => Ok(Ast::Char(CharMatcher::Literal('\n'))),
            'r' => Ok(Ast::Char(CharMatcher::Literal('\r'))),
            't' => Ok(Ast::Char(CharMatcher::Literal('\t'))),
            other => Ok(Ast::Char(CharMatcher::Literal(other))),
        }
    }

    fn parse_class(&mut self) -> Result<Ast, String> {
        let negated = match self.peek() {
            Some('^') => {
                self.bump();
                true
            }
            _ => false,
        };
        let mut items = Vec::new();
        let mut first = true;
        while let Some(ch) = self.peek() {
            if ch == ']' && !first {
                self.bump();
                return Ok(Ast::Char(CharMatcher::Class { negated, items }));
            }
            first = false;
            self.bump();
            if ch == '\\' {
                let esc = self
                    .bump()
                    .ok_or_else(|| "dangling backslash in character class".to_string())?;
                match esc {
                    's' => items.push(ClassItem::Whitespace),
                    'S' => items.push(ClassItem::NotWhitespace),
                    'd' => items.push(ClassItem::Digit),
                    'D' => items.push(ClassItem::NotDigit),
                    'w' => items.push(ClassItem::Word),
                    'W' => items.push(ClassItem::NotWord),
                    'n' => items.push(ClassItem::Single('\n')),
                    'r' => items.push(ClassItem::Single('\r')),
                    't' => items.push(ClassItem::Single('\t')),
                    other => items.push(ClassItem::Single(other)),
                }
                continue;
            }
            if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                self.bump();
                let end = self
                    .bump()
                    .ok_or_else(|| "unterminated range in character class".to_string())?;
                items.push(ClassItem::Range(ch, end));
            } else {
                items.push(ClassItem::Single(ch));
            }
        }
        Err("unclosed '[' in pattern".to_string())
    }
}

#[derive(Clone, Debug)]
enum Inst {
    Char(CharMatcher, usize),
    Assert(Assertion, usize),
    Split(usize, usize),
    Jump(usize),
    Match,
}

struct Compiler {
    insts: Vec<Inst>,
}

impl Compiler {
    fn new() -> Self {
        Self { insts: Vec::new() }
    }

    fn emit(&mut self, inst: Inst) -> usize {
        let idx = self.insts.len();
        self.insts.push(inst);
        idx
    }

    fn patch(&mut self, idx: usize, target: usize) {
        match &mut self.insts[idx] {
            Inst::Char(_, next) | Inst::Assert(_, next) | Inst::Jump(next) => *next = target,
            Inst::Split(a, _) => *a = target,
            Inst::Match => {}
        }
    }

    fn patch_second(&mut self, idx: usize, target: usize) {
        if let Inst::Split(_, b) = &mut self.insts[idx] {
            *b = target;
        }
    }

    fn compile_node(&mut self, node: &Ast) -> (usize, Vec<(usize, bool)>) {
        match node {
            Ast::Empty => {
                let j = self.emit(Inst::Jump(0));
                (j, vec![(j, false)])
            }
            Ast::Char(m) => {
                let c = self.emit(Inst::Char(m.clone(), 0));
                (c, vec![(c, false)])
            }
            Ast::Assert(a) => {
                let i = self.emit(Inst::Assert(*a, 0));
                (i, vec![(i, false)])
            }
            Ast::Seq(items) => {
                let mut iter = items.iter();
                let Some(first) = iter.next() else {
                    return self.compile_node(&Ast::Empty);
                };
                let (entry, mut exits) = self.compile_node(first);
                for item in iter {
                    let (next_entry, next_exits) = self.compile_node(item);
                    for (idx, second) in exits {
                        match second {
                            true => self.patch_second(idx, next_entry),
                            false => self.patch(idx, next_entry),
                        }
                    }
                    exits = next_exits;
                }
                (entry, exits)
            }
            Ast::Alt(branches) => {
                if branches.is_empty() {
                    return self.compile_node(&Ast::Empty);
                }
                let mut compiled = Vec::with_capacity(branches.len());
                for b in branches {
                    compiled.push(self.compile_node(b));
                }
                let mut iter = compiled.into_iter().rev();
                let Some((mut cur_entry, mut cur_exits)) = iter.next() else {
                    return self.compile_node(&Ast::Empty);
                };
                for (b_entry, mut b_exits) in iter {
                    let split = self.emit(Inst::Split(b_entry, cur_entry));
                    b_exits.append(&mut cur_exits);
                    cur_entry = split;
                    cur_exits = b_exits;
                }
                (cur_entry, cur_exits)
            }
            Ast::Repeat {
                inner,
                min: 0,
                unbounded: false,
            } => {
                let (b_entry, mut b_exits) = self.compile_node(inner);
                let split = self.emit(Inst::Split(b_entry, 0));
                b_exits.push((split, true));
                (split, b_exits)
            }
            Ast::Repeat {
                inner,
                min: 0,
                unbounded: true,
            } => {
                let (b_entry, b_exits) = self.compile_node(inner);
                let split = self.emit(Inst::Split(b_entry, 0));
                for (idx, second) in b_exits {
                    match second {
                        true => self.patch_second(idx, split),
                        false => self.patch(idx, split),
                    }
                }
                (split, vec![(split, true)])
            }
            Ast::Repeat {
                inner,
                min: 1,
                unbounded: true,
            } => {
                let (b_entry, b_exits) = self.compile_node(inner);
                let split = self.emit(Inst::Split(b_entry, 0));
                for (idx, second) in b_exits {
                    match second {
                        true => self.patch_second(idx, split),
                        false => self.patch(idx, split),
                    }
                }
                (b_entry, vec![(split, true)])
            }
            Ast::Repeat { .. } => self.compile_node(&Ast::Empty),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MiniRegex {
    insts: Vec<Inst>,
    start: usize,
}

impl MiniRegex {
    pub fn compile(pattern: &str) -> Result<Self, String> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut parser = Parser::new(&chars);
        let ast = parser.parse_alt()?;
        if parser.pos != chars.len() {
            return Err("unexpected trailing characters in pattern".to_string());
        }
        let mut compiler = Compiler::new();
        let (start, exits) = compiler.compile_node(&ast);
        let match_idx = compiler.emit(Inst::Match);
        for (idx, second) in exits {
            match second {
                true => compiler.patch_second(idx, match_idx),
                false => compiler.patch(idx, match_idx),
            }
        }
        Ok(Self {
            insts: compiler.insts,
            start,
        })
    }

    pub fn is_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let n = self.insts.len();
        let mut seen = vec![0u32; n];
        let mut gen = 1u32;

        for start_pos in 0..=chars.len() {
            let mut curr = Vec::new();
            gen = gen.wrapping_add(1);
            if gen == 0 {
                seen.fill(0);
                gen = 1;
            }
            self.add_state(&chars, start_pos, self.start, &mut curr, &mut seen, gen);

            for (idx, &ch) in chars.iter().enumerate().skip(start_pos) {
                if curr.is_empty() {
                    break;
                }
                let mut next = Vec::new();
                gen = gen.wrapping_add(1);
                if gen == 0 {
                    seen.fill(0);
                    gen = 1;
                }
                for &pc in &curr {
                    match &self.insts[pc] {
                        Inst::Match => return true,
                        Inst::Char(matcher, target) if matcher.matches(ch) => {
                            self.add_state(&chars, idx + 1, *target, &mut next, &mut seen, gen);
                        }
                        _ => {}
                    }
                }
                curr = next;
            }

            if curr.iter().any(|&pc| matches!(self.insts[pc], Inst::Match)) {
                return true;
            }
        }
        false
    }

    fn add_state(
        &self,
        chars: &[char],
        pos: usize,
        pc: usize,
        list: &mut Vec<usize>,
        seen: &mut [u32],
        gen: u32,
    ) {
        let mut stack = vec![pc];
        while let Some(cur) = stack.pop() {
            if seen[cur] == gen {
                continue;
            }
            seen[cur] = gen;
            match &self.insts[cur] {
                Inst::Jump(target) => stack.push(*target),
                Inst::Split(a, b) => {
                    stack.push(*b);
                    stack.push(*a);
                }
                Inst::Assert(assertion, target) => {
                    if assertion.holds(chars, pos) {
                        stack.push(*target);
                    }
                }
                Inst::Char(_, _) | Inst::Match => list.push(cur),
            }
        }
    }
}
