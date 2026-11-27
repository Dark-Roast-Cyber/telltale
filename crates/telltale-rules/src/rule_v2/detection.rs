//! Rule v2 `detection`, profile level 1: search identifiers, the condition and
//! value lowering into Rule v1 compiled matchers.
//!
//! A search identifier is a map with one `field|modifiers` key, or a list of
//! such maps (an OR). Identifiers named `filter` or `filter_*` are filters, and
//! each filter vetoes exactly one single-key selection on the same field, as a
//! Rule v1 exclusion vetoes only its own target. The condition is an OR of
//! `<selection>` and `<selection> and not <filter>` terms, or, without filters,
//! one `<selection>`, `1 of <pattern>` or `1 of them`. Every other shape is an
//! error naming it.
//!
//! Matchers follow selection order: list order within an identifier, then the
//! document order of identifiers, which is why `detection` is read as an
//! order-preserving YAML mapping. Each value lowers to one regex in the Rule v1
//! form: a canonical flag group `(?ims:P)` (only the flags in use, in that
//! order), so `i` alone is exactly Rule v1's `(?i:P)`.

use std::collections::BTreeMap;
use std::error::Error;

use serde_yaml::{Mapping, Value};

use crate::{
    CompiledMatcher, MAX_PATTERN_BYTES, MatchScope, RuleLoadNotice, SEGMENT_SCOPE_TARGETS,
    shared_regex,
};

/// Rule v2 fields and the Rule v1 target each compiles to.
pub const FIELD_TARGETS: &[(&str, &str)] = &[
    ("tool.command", "command"),
    ("tool.arguments", "arguments"),
    ("tool.written_path", "written_path"),
    ("tool.path", "file_path"),
    ("tool.name", "tool_name"),
    ("tool.kind", "tool_kind"),
    ("tool.url", "url"),
    ("tool.result", "tool_result"),
    ("message.assistant_text", "assistant_context"),
    ("message.user_text", "user_context"),
];

/// Value modifiers profile level 1 accepts: the match forms, `cased`, and `re`,
/// which must come first.
pub const VALUE_MODIFIERS: &[&str] = &["contains", "startswith", "endswith", "cased", "re"];

/// Regex flags, accepted only after `re`, in their canonical order.
pub const REGEX_FLAGS: &[&str] = &["i", "m", "s"];

/// Telltale extension modifiers that set a matcher's scope, at most one per
/// key, only on the fields that compile to a segment scope target.
pub const SCOPE_MODIFIERS: &[&str] = &["segment", "exclusion_segment", "recorded_exclusion"];

/// Condition forms profile level 1 accepts: (form, what it means).
pub const CONDITION_FORMS: &[(&str, &str)] = &[
    (
        "<selection>",
        "the only selection; only in a rule without filters",
    ),
    (
        "1 of <pattern>",
        "any selection whose name matches the pattern (`*` matches any run of characters); \
         only in a rule without filters",
    ),
    ("1 of them", "any selection; only in a rule without filters"),
    (
        "<selection> and not <filter>",
        "the selection, vetoed by a filter on the same field; the selection has one key",
    ),
    (
        "<term> or <term>",
        "any term, where each term is `<selection>` or `<selection> and not <filter>`, \
         optionally in parentheses",
    ),
];

/// Sigma modifiers that profile level 1 names and rejects.
pub const REJECTED_MODIFIERS: &[&str] = &[
    "all",
    "exists",
    "base64",
    "base64offset",
    "utf16le",
    "utf16be",
    "utf16",
    "wide",
    "windash",
    "cidr",
    "fieldref",
    "gt",
    "gte",
    "lt",
    "lte",
    "neq",
    "expand",
    "minute",
    "hour",
    "day",
    "week",
    "month",
    "year",
];

/// Deepest parenthesis nesting a condition may use.
pub const MAX_CONDITION_DEPTH: usize = 32;

/// The matchers a `detection` block compiles to, in order, and what it read.
pub(super) struct Lowered {
    pub(super) matchers: Vec<CompiledMatcher>,
    /// Whether any field is a `tool.*` field.
    pub(super) uses_tool: bool,
    /// Whether any field is a `message.*` field.
    pub(super) uses_message: bool,
    pub(super) notices: Vec<RuleLoadNotice>,
}

pub(super) fn lower(rule: &str, detection: &Mapping) -> Result<Lowered, Box<dyn Error>> {
    let mut condition = None;
    let mut selections = Vec::new();
    let mut filters = Vec::new();
    for (key, value) in detection {
        let Value::String(name) = key else {
            return Err("detection keys must be strings".into());
        };
        if name == "condition" {
            condition = Some(match value {
                Value::String(text) => text.as_str(),
                Value::Sequence(_) => {
                    return Err("a list of conditions is not supported; join them with `or`".into());
                }
                _ => return Err("detection condition must be a string".into()),
            });
            continue;
        }
        validate_identifier(name)?;
        if is_filter(name) && !value.is_mapping() {
            return Err(format!("filter `{name}` must be a map with exactly one key").into());
        }
        let items = read_identifier(name, value)?;
        if is_filter(name) {
            filters.push(Identifier {
                name: name.clone(),
                items,
            });
        } else {
            selections.push(Identifier {
                name: name.clone(),
                items,
            });
        }
    }
    let condition = condition.ok_or("detection needs a condition")?;
    if selections.is_empty() {
        return Err("detection needs at least one selection".into());
    }
    check_fields(&selections, "selection item")?;
    check_fields(&filters, "filter")?;

    let pairs = condition_pairs(condition, &selections, &filters)
        .map_err(|error| format!("condition `{condition}`: {error}"))?;
    let filter_of = pairs
        .into_iter()
        .filter_map(|(selection, filter)| filter.map(|filter| (selection, filter)))
        .collect::<BTreeMap<_, _>>();

    let mut matchers = Vec::new();
    let mut notices = Vec::new();
    for (index, selection) in selections.iter().enumerate() {
        let filter = filter_of.get(&index).map(|&filter| &filters[filter]);
        if let Some(filter) = filter {
            notices.extend(pair_notice(rule, selection, filter)?);
        }
        for item in &selection.items {
            let scope = item.modifiers.scope.unwrap_or_default();
            let exclusion_regex = filter
                .map(|filter| compile_item(rule, &filter.name, &filter.items[0]))
                .transpose()?;
            matchers.push(CompiledMatcher {
                target: item.target.to_owned(),
                regex: compile_item(rule, &selection.name, item)?,
                exclusion_regex,
                scope,
            });
        }
    }
    let all_items = || selections.iter().flat_map(|selection| &selection.items);
    Ok(Lowered {
        uses_tool: all_items().any(|item| item.field.starts_with("tool.")),
        uses_message: all_items().any(|item| item.field.starts_with("message.")),
        matchers,
        notices,
    })
}

struct Identifier {
    name: String,
    items: Vec<Item>,
}

struct Item {
    field: &'static str,
    target: &'static str,
    modifiers: Modifiers,
    values: Vec<String>,
}

#[derive(Default)]
struct Modifiers {
    form: Form,
    regex: bool,
    case_insensitive_flag: bool,
    multi_line: bool,
    dot_all: bool,
    cased: bool,
    scope: Option<MatchScope>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Form {
    #[default]
    Whole,
    Contains,
    StartsWith,
    EndsWith,
}

impl Modifiers {
    /// The canonical flag group letters, in the order `i`, `m`, `s`.
    fn flags(&self) -> String {
        let insensitive = if self.regex {
            self.case_insensitive_flag
        } else {
            !self.cased
        };
        [
            (insensitive, 'i'),
            (self.multi_line, 'm'),
            (self.dot_all, 's'),
        ]
        .into_iter()
        .filter_map(|(set, flag)| set.then_some(flag))
        .collect()
    }

    fn case_insensitive(&self) -> bool {
        self.flags().contains('i')
    }
}

fn is_filter(name: &str) -> bool {
    name == "filter" || name.starts_with("filter_")
}

fn validate_identifier(name: &str) -> Result<(), Box<dyn Error>> {
    if name.starts_with('_') {
        return Err(format!(
            "search identifier `{name}` starts with `_`, which Sigma leaves out of `them`; rename it"
        )
        .into());
    }
    if name.is_empty()
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(
            format!("search identifier `{name}` must use only A-Z, a-z, 0-9, '_' and '-'").into(),
        );
    }
    if matches!(name, "and" | "or" | "not" | "of" | "them") {
        return Err(format!("search identifier `{name}` is a condition keyword").into());
    }
    Ok(())
}

fn read_identifier(name: &str, value: &Value) -> Result<Vec<Item>, Box<dyn Error>> {
    let in_identifier = |error: Box<dyn Error>| format!("search identifier `{name}`: {error}");
    match value {
        Value::Mapping(map) => Ok(vec![read_map(map).map_err(in_identifier)?]),
        Value::Sequence(entries) => {
            if entries.is_empty() {
                return Err(format!("search identifier `{name}` is an empty list").into());
            }
            entries
                .iter()
                .map(|entry| match entry {
                    Value::Mapping(map) => read_map(map),
                    Value::String(_) => Err("keyword lists are not supported; name a field".into()),
                    _ => Err("a list identifier must hold maps with exactly one key".into()),
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| in_identifier(error).into())
        }
        Value::String(_) => Err(format!(
            "search identifier `{name}` is a keyword search, which is not supported"
        )
        .into()),
        _ => Err(format!(
            "search identifier `{name}` must be a map with one key or a list of such maps"
        )
        .into()),
    }
}

fn read_map(map: &Mapping) -> Result<Item, Box<dyn Error>> {
    let mut entries = map.iter();
    let (Some((key, value)), None) = (entries.next(), entries.next()) else {
        return Err(if map.is_empty() {
            "a map must have exactly one key".into()
        } else {
            "a map with several keys (an AND across fields) needs profile level 2; \
             use a list of single-key maps or separate selections"
                .into()
        });
    };
    let Value::String(key) = key else {
        return Err("field keys must be strings".into());
    };
    let (field, target, modifiers) = parse_key(key)?;
    let values = read_values(value).map_err(|error| format!("`{key}`: {error}"))?;
    Ok(Item {
        field,
        target,
        modifiers,
        values,
    })
}

fn parse_key(key: &str) -> Result<(&'static str, &'static str, Modifiers), Box<dyn Error>> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    if field.is_empty() {
        return Err(format!("`{key}` has no field; keyword searches are not supported").into());
    }
    let Some(&(field, target)) = FIELD_TARGETS.iter().find(|(name, _)| *name == field) else {
        return Err(format!(
            "unknown field `{field}`; supported fields: {}",
            FIELD_TARGETS
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join(", ")
        )
        .into());
    };
    let mut modifiers = Modifiers::default();
    for (position, modifier) in parts.enumerate() {
        let repeated = || format!("`{key}` repeats modifier `{modifier}`");
        match modifier {
            "re" => {
                if position != 0 {
                    return Err(format!("`{key}`: `re` must be the first modifier").into());
                }
                modifiers.regex = true;
            }
            "i" | "m" | "s" => {
                if !modifiers.regex {
                    return Err(format!(
                        "`{key}`: `{modifier}` is a regex flag and must follow `re`"
                    )
                    .into());
                }
                let flag = match modifier {
                    "i" => &mut modifiers.case_insensitive_flag,
                    "m" => &mut modifiers.multi_line,
                    _ => &mut modifiers.dot_all,
                };
                if *flag {
                    return Err(repeated().into());
                }
                *flag = true;
            }
            "contains" | "startswith" | "endswith" => {
                if modifiers.form != Form::Whole {
                    return Err(format!(
                        "`{key}` may use only one of contains, startswith and endswith"
                    )
                    .into());
                }
                modifiers.form = match modifier {
                    "contains" => Form::Contains,
                    "startswith" => Form::StartsWith,
                    _ => Form::EndsWith,
                };
            }
            "cased" => {
                if modifiers.cased {
                    return Err(repeated().into());
                }
                modifiers.cased = true;
            }
            "segment" | "exclusion_segment" | "recorded_exclusion" => {
                if modifiers.scope.is_some() {
                    return Err(format!("`{key}` may use only one scope modifier").into());
                }
                modifiers.scope = Some(match modifier {
                    "segment" => MatchScope::Segment,
                    "exclusion_segment" => MatchScope::ExclusionSegment,
                    _ => MatchScope::RecordedExclusion,
                });
                if !SEGMENT_SCOPE_TARGETS.contains(&target) {
                    return Err(format!(
                        "`{key}`: scope modifier `{modifier}` applies only to tool.command, \
                         tool.arguments and tool.url"
                    )
                    .into());
                }
            }
            _ if REJECTED_MODIFIERS.contains(&modifier) => {
                return Err(format!(
                    "`{key}`: modifier `{modifier}` is not supported at profile level 1"
                )
                .into());
            }
            _ => return Err(format!("`{key}`: unknown modifier `{modifier}`").into()),
        }
    }
    if modifiers.regex && (modifiers.form != Form::Whole || modifiers.cased) {
        return Err(format!(
            "`{key}`: `re` cannot be combined with contains, startswith, endswith or cased"
        )
        .into());
    }
    Ok((field, target, modifiers))
}

fn read_values(value: &Value) -> Result<Vec<String>, Box<dyn Error>> {
    let one = |value: &Value| -> Result<String, Box<dyn Error>> {
        match value {
            Value::String(text) if text.is_empty() => Err("empty values are not supported".into()),
            Value::String(text) => Ok(text.clone()),
            Value::Null => Err("`null` values are not supported at profile level 1".into()),
            Value::Sequence(_) => Err("nested lists are not supported".into()),
            _ => Err("values must be strings".into()),
        }
    };
    match value {
        Value::Sequence(values) if values.is_empty() => Err("an empty list matches nothing".into()),
        Value::Sequence(values) => values.iter().map(one).collect(),
        value => Ok(vec![one(value)?]),
    }
}

fn check_fields(identifiers: &[Identifier], kind: &str) -> Result<(), Box<dyn Error>> {
    let mut seen = BTreeMap::new();
    for identifier in identifiers {
        for item in &identifier.items {
            if let Some(first) = seen.insert(item.field, &identifier.name) {
                return Err(format!(
                    "field `{}` appears in more than one {kind} (`{first}` and `{}`)",
                    item.field, identifier.name
                )
                .into());
            }
        }
    }
    Ok(())
}

/// A filter must veto one single-key selection on its own field and take its
/// scope; a case mode that differs from the selection's is only a notice.
fn pair_notice(
    rule: &str,
    selection: &Identifier,
    filter: &Identifier,
) -> Result<Option<RuleLoadNotice>, Box<dyn Error>> {
    let [item] = selection.items.as_slice() else {
        return Err(format!(
            "filter `{}` needs a selection with exactly one key, but `{}` is a list",
            filter.name, selection.name
        )
        .into());
    };
    let veto = &filter.items[0];
    if veto.field != item.field {
        return Err(format!(
            "filter `{}` reads `{}` but its selection `{}` reads `{}`; a filter vetoes only its own field",
            filter.name, veto.field, selection.name, item.field
        )
        .into());
    }
    if veto
        .modifiers
        .scope
        .is_some_and(|scope| scope != item.modifiers.scope.unwrap_or_default())
    {
        return Err(format!(
            "filter `{}` and its selection `{}` use different scope modifiers; a filter takes its selection's scope",
            filter.name, selection.name
        )
        .into());
    }
    let case = |insensitive: bool| {
        if insensitive {
            "case-insensitive"
        } else {
            "case-sensitive"
        }
    };
    let (selected, vetoed) = (
        item.modifiers.case_insensitive(),
        veto.modifiers.case_insensitive(),
    );
    Ok((selected != vetoed).then(|| RuleLoadNotice {
        rule_id: rule.to_owned(),
        kind: RuleLoadNotice::FILTER_CASE_MISMATCH,
        message: format!(
            "filter `{}` is {} but its selection `{}` is {}",
            filter.name,
            case(vetoed),
            selection.name,
            case(selected)
        ),
    }))
}

/// Lower one item's values to its compiled regex.
fn compile_item(rule: &str, identifier: &str, item: &Item) -> Result<regex::Regex, Box<dyn Error>> {
    let modifiers = &item.modifiers;
    let flags = modifiers.flags();
    let flagged = |pattern: &str| {
        if flags.is_empty() {
            pattern.to_owned()
        } else {
            format!("(?{flags}:{pattern})")
        }
    };
    let invalid = |error: regex::Error| {
        format!("invalid regex for rule {rule} in search identifier `{identifier}`: {error}")
    };
    let patterns = item
        .values
        .iter()
        .map(|value| {
            if modifiers.regex {
                value.clone()
            } else {
                let value = wildcard_pattern(value);
                match modifiers.form {
                    Form::Whole => format!("^(?:{value})$"),
                    Form::Contains => format!("(?:{value})"),
                    Form::StartsWith => format!("^(?:{value})"),
                    Form::EndsWith => format!("(?:{value})$"),
                }
            }
        })
        .collect::<Vec<_>>();
    let pattern = match patterns.as_slice() {
        [single] => flagged(single),
        several => {
            // Each item is checked alone so one item's inline flags cannot
            // hide its own error behind the next item's text.
            for (index, item) in several.iter().enumerate() {
                regex::Regex::new(&flagged(item))
                    .map_err(|error| format!("{} (list item {})", invalid(error), index + 1))?;
            }
            let joined = several
                .iter()
                .map(|item| format!("(?:{item})"))
                .collect::<Vec<_>>()
                .join("|");
            flagged(&format!("(?:{joined})"))
        }
    };
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(format!(
            "rule {rule}: search identifier `{identifier}` compiles to a {} byte pattern; \
             the limit is {MAX_PATTERN_BYTES} bytes",
            pattern.len()
        )
        .into());
    }
    Ok(shared_regex(&pattern).map_err(invalid)?)
}

/// A Sigma string with `*` and `?` wildcards as a regex: `\*`, `\?` and `\\`
/// are the literal character, and any other backslash is literal. Wildcards
/// match newlines too.
fn wildcard_pattern(value: &str) -> String {
    let mut pattern = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    let mut buffer = [0; 4];
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                let literal = match characters.peek() {
                    Some(&next @ ('*' | '?' | '\\')) => {
                        characters.next();
                        next
                    }
                    _ => '\\',
                };
                pattern.push_str(&regex::escape(literal.encode_utf8(&mut buffer)));
            }
            // Sigma wildcards match any character; agent commands can span
            // lines, so the dot also matches a newline.
            '*' => pattern.push_str("(?s:.*)"),
            '?' => pattern.push_str("(?s:.)"),
            other => pattern.push_str(&regex::escape(other.encode_utf8(&mut buffer))),
        }
    }
    pattern
}

#[derive(Debug, PartialEq)]
enum Token {
    Open,
    Close,
    Word(String),
}

#[derive(Debug)]
enum Expr {
    Identifier(String),
    Of { quantifier: String, pattern: String },
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

fn tokenize(condition: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut characters = condition.chars().peekable();
    while let Some(&character) = characters.peek() {
        match character {
            _ if character.is_whitespace() => {
                characters.next();
            }
            '(' | ')' => {
                characters.next();
                tokens.push(if character == '(' {
                    Token::Open
                } else {
                    Token::Close
                });
            }
            '|' => return Err("aggregations (`|`) are not supported".into()),
            _ if is_word_character(character) => {
                let mut word = String::new();
                while let Some(&character) = characters.peek() {
                    if !is_word_character(character) {
                        break;
                    }
                    word.push(character);
                    characters.next();
                }
                tokens.push(Token::Word(word));
            }
            _ => return Err(format!("unexpected character `{character}`")),
        }
    }
    Ok(tokens)
}

fn is_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '*')
}

/// Sigma's precedence, loosest first: `or`, `and`, `not`, `x of`, parentheses.
struct Parser {
    tokens: Vec<Token>,
    position: usize,
    depth: usize,
}

impl Parser {
    fn parse(condition: &str) -> Result<Expr, String> {
        let mut parser = Self {
            tokens: tokenize(condition)?,
            position: 0,
            depth: 0,
        };
        if parser.tokens.is_empty() {
            return Err("the condition is empty".into());
        }
        let expr = parser.or()?;
        match parser.tokens.get(parser.position) {
            None => Ok(expr),
            Some(token) => Err(format!("unexpected {}", describe(token))),
        }
    }

    fn peek_word(&self, word: &str) -> bool {
        matches!(self.tokens.get(self.position), Some(Token::Word(found)) if found == word)
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut terms = vec![self.and()?];
        while self.peek_word("or") {
            self.position += 1;
            terms.push(self.and()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expr::Or(terms)
        })
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut terms = vec![self.not()?];
        while self.peek_word("and") {
            self.position += 1;
            terms.push(self.not()?);
        }
        Ok(if terms.len() == 1 {
            terms.remove(0)
        } else {
            Expr::And(terms)
        })
    }

    fn not(&mut self) -> Result<Expr, String> {
        if self.peek_word("not") {
            self.position += 1;
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, String> {
        let Some(token) = self.tokens.get(self.position) else {
            return Err("the condition ends early".into());
        };
        self.position += 1;
        match token {
            Token::Open => {
                self.depth += 1;
                if self.depth > MAX_CONDITION_DEPTH {
                    return Err("parentheses nest too deeply".into());
                }
                let expr = self.or()?;
                if self.tokens.get(self.position) != Some(&Token::Close) {
                    return Err("a `(` is not closed".into());
                }
                self.position += 1;
                self.depth -= 1;
                Ok(expr)
            }
            Token::Close => Err("unexpected `)`".into()),
            Token::Word(word) => {
                let word = word.clone();
                if matches!(word.as_str(), "1" | "all" | "any") && self.peek_word("of") {
                    self.position += 1;
                    let Some(Token::Word(pattern)) = self.tokens.get(self.position) else {
                        return Err(format!("`{word} of` needs an identifier pattern"));
                    };
                    let pattern = pattern.clone();
                    self.position += 1;
                    return Ok(Expr::Of {
                        quantifier: word,
                        pattern,
                    });
                }
                if matches!(word.as_str(), "and" | "or" | "not" | "of") {
                    return Err(format!("unexpected `{word}`"));
                }
                if word.contains('*') {
                    return Err(format!(
                        "a pattern such as `{word}` is allowed only after `1 of`"
                    ));
                }
                Ok(Expr::Identifier(word))
            }
        }
    }
}

fn describe(token: &Token) -> String {
    match token {
        Token::Open => "`(`".into(),
        Token::Close => "`)`".into(),
        Token::Word(word) => format!("`{word}`"),
    }
}

/// Normalise the condition to (selection, optional filter) pairs, by index,
/// and check that every identifier is used exactly once.
fn condition_pairs(
    condition: &str,
    selections: &[Identifier],
    filters: &[Identifier],
) -> Result<Vec<(usize, Option<usize>)>, String> {
    let find = |identifiers: &[Identifier], name: &str| {
        identifiers
            .iter()
            .position(|identifier| identifier.name == name)
    };
    let pairs = match Parser::parse(condition)? {
        Expr::Of {
            quantifier,
            pattern,
        } => {
            if quantifier != "1" {
                return Err(quantifier_error(&quantifier));
            }
            if !filters.is_empty() {
                return Err("`1 of …` cannot be used in a rule with filters; write \
                     `(selection_x and not filter_x) or …`"
                    .into());
            }
            let matched = selections
                .iter()
                .enumerate()
                .filter(|(_, selection)| pattern == "them" || glob_match(&pattern, &selection.name))
                .map(|(index, _)| (index, None))
                .collect::<Vec<_>>();
            if matched.is_empty() {
                return Err(format!("`1 of {pattern}` matches no search identifier"));
            }
            matched
        }
        expr => {
            let mut terms = Vec::new();
            flatten_or(expr, &mut terms);
            terms
                .into_iter()
                .map(|term| term_pair(term, selections, filters, &find))
                .collect::<Result<Vec<_>, _>>()?
        }
    };

    let mut selection_uses = vec![0usize; selections.len()];
    let mut filter_uses = vec![0usize; filters.len()];
    for (selection, filter) in &pairs {
        selection_uses[*selection] += 1;
        if let Some(filter) = filter {
            filter_uses[*filter] += 1;
        }
    }
    for (selection, uses) in selections.iter().zip(&selection_uses) {
        match uses {
            0 => {
                return Err(format!(
                    "search identifier `{}` is not used",
                    selection.name
                ));
            }
            1 => {}
            _ => {
                return Err(format!(
                    "search identifier `{}` is used more than once",
                    selection.name
                ));
            }
        }
    }
    for (filter, uses) in filters.iter().zip(&filter_uses) {
        match uses {
            0 => return Err(format!("filter `{}` is not used", filter.name)),
            1 => {}
            _ => {
                return Err(format!(
                    "filter `{}` applies to more than one selection; give each selection its own filter",
                    filter.name
                ));
            }
        }
    }
    Ok(pairs)
}

fn flatten_or(expr: Expr, terms: &mut Vec<Expr>) {
    match expr {
        Expr::Or(parts) => {
            for part in parts {
                flatten_or(part, terms);
            }
        }
        other => terms.push(other),
    }
}

fn quantifier_error(quantifier: &str) -> String {
    match quantifier {
        "all" => "`all of …` (an AND of selections) needs profile level 2".into(),
        _ => format!("`{quantifier} of …` is not supported; use `1 of …`"),
    }
}

fn term_pair(
    term: Expr,
    selections: &[Identifier],
    filters: &[Identifier],
    find: &impl Fn(&[Identifier], &str) -> Option<usize>,
) -> Result<(usize, Option<usize>), String> {
    let undefined = |name: &str| format!("`{name}` is not a search identifier of this rule");
    match term {
        Expr::Identifier(name) => {
            if let Some(selection) = find(selections, &name) {
                Ok((selection, None))
            } else if find(filters, &name).is_some() {
                Err(format!(
                    "filter `{name}` must be written as `<selection> and not {name}`"
                ))
            } else {
                Err(undefined(&name))
            }
        }
        Expr::And(parts) => match <[Expr; 2]>::try_from(parts) {
            Ok([Expr::Identifier(selection), Expr::Not(veto)]) => {
                let Some(selection_index) = find(selections, &selection) else {
                    return Err(if find(filters, &selection).is_some() {
                        format!("write the selection first: `<selection> and not {selection}`")
                    } else {
                        undefined(&selection)
                    });
                };
                match *veto {
                    Expr::Identifier(filter) => match find(filters, &filter) {
                        Some(filter_index) => Ok((selection_index, Some(filter_index))),
                        None if find(selections, &filter).is_some() => Err(format!(
                            "`not {filter}` negates a selection, which is not supported"
                        )),
                        None => Err(undefined(&filter)),
                    },
                    Expr::Of { .. } => Err(
                        "`and not 1 of …` applies filters to more than one selection; pair each \
                         filter with one selection"
                            .into(),
                    ),
                    _ => Err("only `<selection> and not <filter>` may use `and`".into()),
                }
            }
            Ok([Expr::Not(_), Expr::Identifier(_)]) => {
                Err("write the selection first: `<selection> and not <filter>`".into())
            }
            Ok([Expr::Identifier(left), Expr::Identifier(right)])
                if find(selections, &left).is_some() && find(selections, &right).is_some() =>
            {
                Err("`and` between selections needs profile level 2".into())
            }
            _ => Err("only `<selection> and not <filter>` may use `and`".into()),
        },
        Expr::Not(inner) => Err(match *inner {
            Expr::Identifier(name) if find(selections, &name).is_some() => {
                format!("`not {name}` negates a selection, which is not supported")
            }
            Expr::Identifier(name) if find(filters, &name).is_some() => {
                format!("`not {name}` must follow its selection: `<selection> and not {name}`")
            }
            _ => "`not` is supported only as `<selection> and not <filter>`".into(),
        }),
        Expr::Of { quantifier, .. } if quantifier == "1" => {
            Err("`1 of …` must be the whole condition".into())
        }
        Expr::Of { quantifier, .. } => Err(quantifier_error(&quantifier)),
        Expr::Or(_) => Err("unsupported condition shape".into()),
    }
}

/// Sigma identifier patterns: `*` matches any run of characters, and the
/// pattern must match the whole name.
fn glob_match(pattern: &str, name: &str) -> bool {
    let parts = pattern.split('*').collect::<Vec<_>>();
    let [first, middle @ .., last] = parts.as_slice() else {
        return pattern == name;
    };
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    for part in middle {
        let Some(found) = rest.find(part) else {
            return false;
        };
        rest = &rest[found + part.len()..];
    }
    rest.ends_with(last)
}

#[cfg(test)]
mod tests;
