//! Evaluable projection of a tool input that Telltale quarantined.
//!
//! Telltale excludes a native record whose values exceed its structured
//! bounds (strings over 4,096 bytes outside authored-text fields, depth over
//! 6, arrays over 64 items, objects over 32 members, keys over 64 bytes, more
//! than 16 KiB of encoded input in all). An agent controls those values, so
//! "not evaluated" must never become a silent allow (security review finding:
//! a padded `description` field hid a deny-level command). The projection
//! flattens the input and splits every long string into overlapping chunks,
//! so every byte is evaluated in at least one bounded variant.
//!
//! A variant Telltale refuses is a variant not evaluated, so variants are
//! packed to the bounds Telltale checks them against, sizes counted as
//! Telltale counts them (escaped JSON, after NFC normalization): values that
//! fit one call apart but not together are spread over variants. Telltale
//! also refuses a call holding a URL whose host has a control character; such
//! a URL is evaluated with `_` in place of each control character.
//!
//! Covering every byte is not enough: a rule can need two values of one call
//! together (a written path counts only beside the content written), or two
//! parts of one command. Each variant is evaluated as a call of its own, so
//! the projection also keeps together what Telltale reads together:
//!
//! - Telltale takes a call's command, path, URL and written content from its
//!   top-level members, by name. Short top-level values are *anchors*, and
//!   every anchor shares a variant with every other anchor and with every
//!   other value or chunk. A top-level member that holds a container keeps
//!   its name as an anchor too, because its presence alone is a fact (`edits`
//!   marks a write).
//! - A top-level array of scalars keeps its array form under its member's
//!   name (`paths`); an argv `command` is joined into one command.
//! - A continuation chunk of a command starts with the head of that command.
//! - Two chunks of one value never share a variant: the second would be
//!   renamed, and lose the name Telltale reads it by.
//! - Telltale reads every top-level command of a call as one command text, so
//!   a piece of one it cannot evaluate takes the others down with it. With
//!   more than one command, no two share a variant, and none is an anchor.
//!
//! What cannot be kept together (more than one command included), or had to
//! be rewritten, is reported as
//! [`Projection::separated`], and the runtime then floors the verdict at
//! `on_unevaluable`: findings keep their force, and "no finding" is not taken
//! as an allow.
//!
//! The work is bounded: at most [`MAX_VARIANTS`] variants, and no more values
//! or pieces of values than they hold. Past that budget a bounded set of
//! variants is still evaluated rather than none: a short command and the first
//! block of short top-level values go into every variant, every chunk of a
//! longer command comes ahead of other values (first chunks first, so one
//! command cannot crowd out another), and then the start of other values while
//! variants remain. A command comes first whatever the member names sort as.
//! History keeps a line of its own ([`Projection::history`]): the start of
//! every command together, then short top-level values. Otherwise the layout
//! follows key-sorted order (members arrive sorted by name, not in the order
//! the agent wrote them). Whatever is in no variant, a value cut short for
//! room included, is not evaluated, and is reported as separated, so it floors
//! the verdict like anything else kept apart.

use serde_json::{Map, Value};
use telltale_schema::activity_facts::host_from_url_token;
use telltale_schema::observation::{
    LOCAL_MAX_KEY_BYTES, LOCAL_MAX_OBJECT_MEMBERS, LOCAL_MAX_STRING_BYTES, LOCAL_MAX_VALUE_BYTES,
};
use unicode_normalization::UnicodeNormalization;

use crate::hooks::journal::cut_utf8;

/// Bytes per chunk; with [`HEAD_BYTES`] under Telltale's string bound.
pub const CHUNK_BYTES: usize = 3000;
/// Bytes shared by consecutive chunks, so short patterns are not split.
pub const OVERLAP_BYTES: usize = 512;
/// A piece of text may take this many times its byte budget escaped.
/// Ordinary text, quotes and line breaks included, stays within it; text
/// heavy with control characters is cut shorter.
const ESCAPE_ROOM: usize = 2;
/// Leaves per variant; under Telltale's object member and entry bounds.
pub const LEAVES_PER_VARIANT: usize = 16;
/// Encoded bytes of one variant, as Telltale counts a tool input: escaped
/// JSON, braces included. Authored-text members (a `Bash` command) have a
/// larger bound of their own; the projection does not rely on it.
pub const VARIANT_BYTES: usize = LOCAL_MAX_VALUE_BYTES;
/// More variants than this is treated as unevaluable.
pub const MAX_VARIANTS: usize = 128;
/// A top-level value up to this many bytes is an anchor. Paths, URLs and
/// ordinary commands fit.
pub const ANCHOR_BYTES: usize = 1024;
/// Bytes of a command's start repeated ahead of each of its later chunks, as
/// if the text between had been cut out.
pub const HEAD_BYTES: usize = 512;
/// Up to this many anchors, within [`BLOCK_BYTES`], go into every variant.
/// More are split into blocks, and every two blocks share a variant.
const ANCHOR_BLOCK: usize = LEAVES_PER_VARIANT / 2;
/// Encoded bytes of a block of anchors: two blocks fill a variant.
const BLOCK_BYTES: usize = (VARIANT_BYTES - 2) / 2;
/// Values, and pieces of values, that the variants can hold; more are not
/// projected.
const MAX_LEAVES: usize = MAX_VARIANTS * LEAVES_PER_VARIANT;
const MAX_KEY_BYTES: usize = 60;
/// What a member costs beyond its escaped key and value: colon, comma, the
/// brackets of a list, and a `~n` suffix if [`variant`] renames it.
const MEMBER_OVERHEAD: usize = 8;

// Every member fits a block, and a block and any other member fit a variant:
// an anchor escapes to at most six bytes a byte, a chunk with a head stays
// under the string bound.
const _: () = {
    assert!(2 * ANCHOR_BLOCK <= LEAVES_PER_VARIANT);
    assert!(LEAVES_PER_VARIANT <= LOCAL_MAX_OBJECT_MEMBERS);
    assert!(MAX_KEY_BYTES < LOCAL_MAX_KEY_BYTES);
    assert!(CHUNK_BYTES + HEAD_BYTES <= LOCAL_MAX_STRING_BYTES);
    assert!(OVERLAP_BYTES + 6 < CHUNK_BYTES);
    let key = 2 + 6 * MAX_KEY_BYTES + MEMBER_OVERHEAD;
    assert!(key + 2 + 6 * ANCHOR_BYTES <= BLOCK_BYTES);
    let chunk = ESCAPE_ROOM * (CHUNK_BYTES + HEAD_BYTES);
    assert!(key + 2 + chunk <= VARIANT_BYTES - 2 - BLOCK_BYTES);
};

/// Top-level members Telltale reads as command text
/// (`is_command_argument_key` in telltale-detect). A rule on a command can
/// need parts of it that are far apart, so a command that had to be split is
/// reported as separated. History keeps them first (`journal::bound_history`).
pub(crate) fn is_command_key(key: &str) -> bool {
    matches!(key, "command" | "cmd" | "commandLine" | "command_line")
}

/// What [`project`] made of an input.
#[derive(Debug, PartialEq)]
pub struct Projection {
    /// Bounded inputs whose union covers every byte of the original.
    pub variants: Vec<Value>,
    /// What history keeps of the call, within the bounds of a variant: the
    /// start of every command, then short top-level values, then the start
    /// of other values. Unlike the variants it holds the commands together,
    /// so a later call can link to what each of them did.
    pub history: Value,
    /// Values or parts of a command that a rule may need together are not
    /// together in any variant: more short top-level values than the variant
    /// budget can pair up, a command longer than one chunk, or more than one
    /// command, which Telltale reads as one. Also set when
    /// a URL Telltale refuses had to be rewritten to be evaluated, and when
    /// the input is past the budget and part of it is in no variant.
    pub separated: bool,
    /// Past the budget: a value, chunk or variant was left out. The variants
    /// together then hold more than Telltale takes in one scan, and are
    /// evaluated one by one, the command's first.
    pub past_budget: bool,
}

struct Leaf {
    key: String,
    text: String,
    /// A scalar member of the input object itself.
    top: bool,
    /// An item of a top-level array of scalars, which keeps its array form
    /// under the member's name: the index of the array's first leaf.
    list: Option<usize>,
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::Object(_) | Value::Array(_) => None,
        Value::String(text) => Some(text.clone()),
        other => Some(other.to_string()),
    }
}

struct Flat {
    leaves: Vec<Leaf>,
    /// Top-level members that hold a container with at least one scalar.
    containers: Vec<String>,
    /// Every value is a leaf: none was left out for the budget.
    complete: bool,
}

/// A non-empty array of scalars: Telltale reads it by its member's name.
fn scalar_items(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()
        .filter(|items| !items.is_empty())
        .and_then(|items| items.iter().map(scalar_text).collect())
}

/// Flatten to at most [`MAX_LEAVES`] leaves, in key-sorted order; past that,
/// a command first, then the other top-level values, then nested ones,
/// whatever their names sort as.
fn flatten(value: &Value) -> Flat {
    fn walk(prefix: &str, value: &Value, depth: usize, out: &mut Vec<Leaf>) -> bool {
        if out.len() >= MAX_LEAVES {
            return false;
        }
        let join = |key: &str| {
            if prefix.is_empty() {
                key.to_owned()
            } else {
                format!("{prefix}.{key}")
            }
        };
        let leaf = |text: String, out: &mut Vec<Leaf>| {
            out.push(Leaf {
                key: prefix.to_owned(),
                text,
                top: depth == 1,
                list: None,
            });
            true
        };
        match value {
            Value::Object(map) => map.iter().all(|(k, v)| walk(&join(k), v, depth + 1, out)),
            Value::Array(items) => items
                .iter()
                .enumerate()
                .all(|(i, v)| walk(&join(&i.to_string()), v, depth + 1, out)),
            Value::String(text) => leaf(text.clone(), out),
            other => leaf(other.to_string(), out),
        }
    }
    /// The members in this order, up to [`MAX_LEAVES`] leaves.
    fn members<'a>(members: impl Iterator<Item = (&'a String, &'a Value)>) -> Flat {
        let mut leaves = Vec::new();
        let mut containers = Vec::new();
        let mut complete = true;
        for (key, member) in members {
            if leaves.len() >= MAX_LEAVES {
                complete = false;
                break;
            }
            let before = leaves.len();
            // Telltale reads a top-level array of strings by its member's
            // name too (an argv `command`, `paths`), so it is not flattened
            // into members of other names. An argv is joined as Telltale
            // joins it, and is then one command like any other.
            if let Some(items) = scalar_items(member) {
                if is_command_key(key) {
                    leaves.push(Leaf {
                        key: key.clone(),
                        text: items.join(" "),
                        top: true,
                        list: None,
                    });
                } else {
                    let room = MAX_LEAVES - leaves.len();
                    complete &= items.len() <= room;
                    leaves.extend(items.into_iter().take(room).map(|text| Leaf {
                        key: key.clone(),
                        text,
                        top: false,
                        list: Some(before),
                    }));
                }
                continue;
            }
            complete &= walk(key, member, 1, &mut leaves);
            if leaves.len() > before && (member.is_object() || member.is_array()) {
                containers.push(key.clone());
            }
        }
        Flat {
            leaves,
            containers,
            complete,
        }
    }
    match value {
        Value::Object(map) => {
            let flat = members(map.iter());
            if flat.complete {
                return flat;
            }
            // Past the budget, what comes first is what is projected: a
            // command, then the other top-level values, then nested ones.
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by_cached_key(|(key, member)| {
                let nested = match member {
                    Value::Object(_) => true,
                    Value::Array(items) => {
                        items.is_empty() || items.iter().any(|v| v.is_object() || v.is_array())
                    }
                    _ => false,
                };
                (!is_command_key(key), nested)
            });
            members(sorted.into_iter())
        }
        // Not an object: no member has a name Telltale could route on.
        other => {
            let mut leaves = Vec::new();
            let complete = walk("input", other, 2, &mut leaves);
            Flat {
                leaves,
                containers: Vec::new(),
                complete,
            }
        }
    }
}

/// Keys within Telltale's bound (after its NFC normalization), kept unique.
fn bounded_key(key: &str, index: usize) -> String {
    let key: String = if key.is_empty() {
        "input".to_owned()
    } else {
        key.nfc().collect()
    };
    if key.len() <= MAX_KEY_BYTES {
        key
    } else {
        format!("{}~{index}", cut_utf8(&key, MAX_KEY_BYTES - 8))
    }
}

/// Bytes `c` takes in a JSON string as Telltale counts them
/// (`escaped_string_bytes` in telltale-schema).
fn escaped(c: char) -> usize {
    match c {
        '"' | '\\' | '\u{08}' | '\u{0c}' | '\n' | '\r' | '\t' => 2,
        '\0'..='\u{1f}' => 6,
        c => c.len_utf8(),
    }
}

/// Bytes `text` takes as a JSON string, quotes included.
fn escaped_len(text: &str) -> usize {
    2 + text.chars().map(escaped).sum::<usize>()
}

/// How many bytes of `chars` (in order) fit `bytes`, within [`ESCAPE_ROOM`]
/// times that escaped.
fn fitting(chars: impl Iterator<Item = char>, bytes: usize) -> usize {
    let (mut used, mut escaped_used) = (0, 0);
    for c in chars {
        escaped_used += escaped(c);
        if used + c.len_utf8() > bytes || escaped_used > ESCAPE_ROOM * bytes {
            break;
        }
        used += c.len_utf8();
    }
    used
}

/// The longest start of `text` within `bytes` (see [`fitting`]).
fn cut(text: &str, bytes: usize) -> &str {
    &text[..fitting(text.chars(), bytes)]
}

/// The longest end of `text` within `bytes` (see [`fitting`]).
fn tail(text: &str, bytes: usize) -> &str {
    &text[text.len() - fitting(text.chars().rev(), bytes)..]
}

/// Overlapping chunks covering the start of `text`, cut on char boundaries,
/// and whether they cover all of it: no more than [`MAX_VARIANTS`], since no
/// two share a variant.
fn chunks(text: &str) -> (Vec<&str>, bool) {
    let mut out = Vec::new();
    let mut start = 0;
    loop {
        let piece = cut(&text[start..], CHUNK_BYTES);
        out.push(piece);
        let end = start + piece.len();
        if end == text.len() {
            return (out, true);
        }
        if out.len() == MAX_VARIANTS {
            return (out, false);
        }
        // A piece cut short holds more than the overlap, so this advances.
        start = end - tail(piece, OVERLAP_BYTES).len();
    }
}

/// Telltale refuses a call holding a URL whose host has a control character
/// (`invalid_native_contribution`), so such a token is rewritten with `_`
/// in place of each control character. A token is what Telltale reads as
/// one: a run between whitespace. The rewrite never makes a text longer,
/// escaped. Returns whether anything was rewritten.
fn rewrite_refused_urls(text: &mut String) -> bool {
    let refused = |token: &str| {
        host_from_url_token(token.trim_matches(|c: char| c.is_ascii_control()))
            .is_some_and(|host| host.chars().any(char::is_control))
    };
    if !text.split_whitespace().any(refused) {
        return false;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find(|c: char| !c.is_whitespace()) {
        let end = rest[start..]
            .find(char::is_whitespace)
            .map_or(rest.len(), |n| start + n);
        out.push_str(&rest[..start]);
        let token = &rest[start..end];
        if refused(token) {
            out.extend(token.chars().map(|c| if c.is_control() { '_' } else { c }));
        } else {
            out.push_str(token);
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    *text = out;
    true
}

/// One member of a variant, or one item of a member that is a list.
struct Item {
    key: String,
    text: String,
    list: bool,
    /// The leaf this is (a piece of): two pieces of one leaf never share a
    /// variant.
    leaf: usize,
    /// A top-level command: two commands never share a variant either.
    command: bool,
    /// Encoded bytes this adds to a variant.
    bytes: usize,
}

impl Item {
    fn new(
        key: String,
        mut text: String,
        list: bool,
        leaf: usize,
        command: bool,
        rewritten: &mut bool,
    ) -> Self {
        *rewritten |= rewrite_refused_urls(&mut text);
        let bytes = escaped_len(&key) + escaped_len(&text) + MEMBER_OVERHEAD;
        Self {
            key,
            text,
            list,
            leaf,
            command,
            bytes,
        }
    }
}

fn bytes_of(items: &[Item]) -> usize {
    items.iter().map(|item| item.bytes).sum()
}

/// `items` in order, in runs of at most `count` items and `bytes` encoded
/// bytes, and with no two pieces of one leaf, nor two commands, in a run.
fn pack(items: &[Item], count: usize, bytes: usize) -> Vec<&[Item]> {
    let mut runs = Vec::new();
    let (mut start, mut used) = (0, 0);
    for (at, item) in items.iter().enumerate() {
        let run = &items[start..at];
        if !run.is_empty()
            && (run.len() == count
                || used + item.bytes > bytes
                || run
                    .iter()
                    .any(|other| other.leaf == item.leaf || (other.command && item.command)))
        {
            runs.push(run);
            (start, used) = (at, 0);
        }
        used += item.bytes;
    }
    if start < items.len() {
        runs.push(&items[start..]);
    }
    runs
}

/// A variant holding `items`. Flattening can give two values one key (`a.b`
/// beside `a: {b}`); the later one is renamed, so neither value is dropped.
fn variant<'a>(items: impl IntoIterator<Item = &'a Item>) -> Value {
    let mut object = Map::new();
    for item in items {
        let text = Value::String(item.text.clone());
        if item.list
            && let Some(Value::Array(items)) = object.get_mut(&item.key)
        {
            items.push(text);
            continue;
        }
        let mut name = item.key.clone();
        let mut n = 1;
        while object.contains_key(&name) {
            name = format!("{}~{n}", cut_utf8(&item.key, MAX_KEY_BYTES - 4));
            n += 1;
        }
        let value = if item.list {
            Value::Array(vec![text])
        } else {
            text
        };
        object.insert(name, value);
    }
    Value::Object(object)
}

/// What history keeps of a projected call, within a variant's bounds: the
/// first chunk of every command (in key order), then anchors, then the first
/// chunks of other values, while they fit. If not every command fits, the
/// call is already reported separated: it has more than one.
fn history(anchors: &[Item], rest: &[Item]) -> Value {
    let mut kept: Vec<&Item> = Vec::new();
    let mut bytes = 0;
    let commands = rest.iter().filter(|item| item.command);
    for item in commands.chain(anchors).chain(rest) {
        if kept.len() == LEAVES_PER_VARIANT {
            break;
        }
        if kept.iter().any(|other| other.leaf == item.leaf)
            || bytes + item.bytes > VARIANT_BYTES - 2
        {
            continue;
        }
        bytes += item.bytes;
        kept.push(item);
    }
    variant(kept)
}

/// Bounded variants whose union covers every byte of `input`, or past the
/// budget as much of it as they hold (reported as separated). `None` when the
/// input holds no value at all.
pub fn project(input: &Value) -> Option<Projection> {
    let Flat {
        leaves,
        containers,
        complete,
    } = flatten(input);
    // An input with no scalar value at all (nested empty containers) has
    // nothing to project: it is unevaluable, not an empty evaluation.
    if leaves.is_empty() {
        return None;
    }
    // Everything is in some variant; past the budget it is not.
    let mut whole = complete;
    let mut separated = false;
    let mut rewritten = false;
    let command_leaf = |index: usize| {
        leaves
            .get(index)
            .is_some_and(|leaf| leaf.top && is_command_key(&leaf.key))
    };
    // Telltale reads every command of a call as one command text, so a piece
    // of one that it cannot evaluate would take the others down with it. With
    // more than one, each is evaluated apart, and that is reported.
    let apart = (0..leaves.len())
        .filter(|&index| command_leaf(index))
        .count()
        > 1;
    separated |= apart;
    // Anchors, and the pieces of the other leaves: each leaf's chunks, a
    // later chunk of a command behind the head of that command. A command is
    // cut first, so that no other value takes the room of its pieces, and
    // each leaf keeps its place in key-sorted order.
    let mut anchors: Vec<Item> = Vec::new();
    let mut long: Vec<(usize, String)> = Vec::new();
    let item = |index: usize, text: String, rewritten: &mut bool| {
        let leaf = &leaves[index];
        let key = bounded_key(&leaf.key, leaf.list.unwrap_or(index));
        let command = command_leaf(index);
        Item::new(key, text, leaf.list.is_some(), index, command, rewritten)
    };
    for (index, leaf) in leaves.iter().enumerate() {
        // Telltale evaluates the normalized text, and bounds it.
        let text: String = leaf.text.nfc().collect();
        if leaf.top && text.len() <= ANCHOR_BYTES && !(apart && command_leaf(index)) {
            anchors.push(item(index, text, &mut rewritten));
        } else {
            long.push((index, text));
        }
    }
    long.sort_by_key(|(index, _)| !command_leaf(*index));
    let mut pieces: Vec<Vec<Item>> = leaves.iter().map(|_| Vec::new()).collect();
    let mut count = 0;
    for (index, text) in long {
        let command = command_leaf(index);
        // No more pieces than variants can hold: the rest is not cut, and is
        // in no variant.
        let (mut chunks, all) = chunks(&text);
        let room = MAX_LEAVES - count;
        whole &= all && chunks.len() <= room;
        chunks.truncate(room);
        if chunks.is_empty() {
            continue;
        }
        count += chunks.len();
        separated |= command && chunks.len() > 1;
        let head = cut(&text, HEAD_BYTES);
        let mut items = vec![item(index, chunks[0].to_owned(), &mut rewritten)];
        for chunk in &chunks[1..] {
            let text = if command {
                format!("{head}{chunk}")
            } else {
                (*chunk).to_owned()
            };
            items.push(item(index, text, &mut rewritten));
        }
        pieces[index] = items;
    }
    for (index, key) in containers.iter().enumerate() {
        let key = bounded_key(key, leaves.len() + index);
        anchors.push(Item::new(
            key,
            String::new(),
            false,
            usize::MAX - index,
            false,
            &mut rewritten,
        ));
    }
    separated |= rewritten || !whole;
    // A command comes ahead of every other value, whatever the member names
    // sort as: its anchor in the first block, which goes into every variant
    // past the budget, and its pieces in the first groups.
    anchors.sort_by_key(|item| !item.command);
    // The rest, first chunks first: the first chunks of all leaves side by
    // side, commands first, then the second ones, and so on. A long command
    // cannot crowd out the first chunk of another.
    let mut rest: Vec<Item> = Vec::with_capacity(count);
    let mut rounds: Vec<_> = pieces.into_iter().map(Vec::into_iter).collect();
    rounds.sort_by_key(|round| !round.as_slice().first().is_some_and(|item| item.command));
    while rest.len() < count {
        rest.extend(rounds.iter_mut().filter_map(Iterator::next));
    }
    let history = history(&anchors, &rest);

    // Few anchors go into every variant. More are split into blocks: every
    // two blocks share a variant, and so do every block and every group.
    let blocks: Vec<&[Item]> = if anchors.is_empty() {
        vec![&anchors[..]]
    } else {
        pack(&anchors, ANCHOR_BLOCK, BLOCK_BYTES)
    };
    let widest = blocks.iter().map(|block| block.len()).max().unwrap_or(0);
    let largest = blocks
        .iter()
        .map(|block| bytes_of(block))
        .max()
        .unwrap_or(0);
    let groups = pack(
        &rest,
        LEAVES_PER_VARIANT - widest,
        VARIANT_BYTES - 2 - largest,
    );
    let pairs = blocks.len() * (blocks.len() - 1) / 2;
    // Past the budget, a pair of blocks without a command is not worth a
    // variant: then every variant holds the first block.
    if (whole || blocks.len() == 1) && pairs + groups.len() * blocks.len() <= MAX_VARIANTS {
        let mut variants = Vec::new();
        for group in &groups {
            for block in &blocks {
                variants.push(variant(block.iter().chain(group.iter())));
            }
        }
        for (i, first) in blocks.iter().enumerate() {
            for second in &blocks[i + 1..] {
                variants.push(variant(first.iter().chain(second.iter())));
            }
        }
        if variants.is_empty() {
            variants.push(variant(blocks.iter().flat_map(|block| block.iter())));
        }
        return Some(Projection {
            variants,
            history,
            separated,
            past_budget: !whole,
        });
    }

    // Too many anchors to pair up within the budget: every byte is still
    // covered, and the caller is told that values which may belong together
    // are apart.
    let lead = blocks[0].len();
    let anchor_count = anchors.len();
    let mut all: Vec<Item> = anchors.into_iter().chain(rest).collect();
    if whole {
        let groups = pack(&all, LEAVES_PER_VARIANT, VARIANT_BYTES - 2);
        if groups.len() <= MAX_VARIANTS {
            return Some(Projection {
                variants: groups.into_iter().map(variant).collect(),
                history,
                separated: true,
                past_budget: false,
            });
        }
    }
    // Past the budget: the first block of anchors, a command first, goes into
    // every variant. Beside it go a command's pieces, each in a group of its
    // own, then the other anchors, then the other pieces, first chunks first,
    // as many groups as the budget holds.
    let mut others = all.split_off(lead);
    let pieces = others.split_off(anchor_count - lead);
    let (commands, pieces): (Vec<Item>, Vec<Item>) =
        pieces.into_iter().partition(|item| item.command);
    let rest: Vec<Item> = commands.into_iter().chain(others).chain(pieces).collect();
    let first = all;
    let groups = pack(
        &rest,
        LEAVES_PER_VARIANT - first.len(),
        VARIANT_BYTES - 2 - bytes_of(&first),
    );
    let variants = groups
        .iter()
        .take(MAX_VARIANTS)
        .map(|group| variant(first.iter().chain(group.iter())))
        .collect();
    Some(Projection {
        variants,
        history,
        separated: true,
        past_budget: true,
    })
}

#[cfg(test)]
mod tests;
