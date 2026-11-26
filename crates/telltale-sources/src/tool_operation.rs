//! Declared tool operations: what a source's own tool table says a call does.
//!
//! Each source module keeps one table of the built-in tools of its harness: a
//! tool name, its kind in the shared vocabulary (decision O7) and where the
//! operands sit in the arguments. Tool names and argument keys therefore live
//! with the source that knows them. This module holds only the neutral reading
//! those tables share: top-level argument members, argv arrays and the
//! `*** Begin Patch` patch format.
//!
//! A declaration adds operands to what detection reads from the arguments by
//! shape, and a row may also say how a named argument is read: as content the
//! call authors, or as replaced text. Only the keys a row names get a role.
//! A patch key, and the argument text of a patch tool whose call carries no
//! object, are authored content only when the text is a patch (`is_patch`);
//! otherwise the key keeps its structural reading, so a command in a patch
//! key is still a command. A tool missing from a table is left undeclared, and
//! so is a call whose arguments hold no operand. A name an MCP server gives
//! its tools is never declared, whatever a table lists.
//!
//! A row also declares which argument keys hold authored text (commands, file
//! bodies, patches, prompts, messages) and so keep the direct-text budget
//! instead of the structured string bound when the call is converted
//! ([`argument_text`]). A tool name's text declaration holds wherever that
//! exact name is read, as the one shared list it replaces did: a hook journal
//! reports some tools under another harness's spelling. It changes the bound
//! only; detection reads a key as content only through `authored()`.

use std::collections::BTreeMap;

use telltale_schema::clients::ClientId;
use telltale_schema::observation::{
    ArgumentText, BoundDimension, BoundedTarget, BoundedValue, CanonicalFieldCategory,
    CanonicalObservationV2, JsonValue, ObservationBody, ObservationError, ObservationStage,
    SEMANTIC_MAX_TOTAL_BYTES, ToolKind, ToolObservation, ToolOperation,
};

use crate::acquisition::ToolTableCounts;
use crate::sources::{claude, codex, copilot, openclaw, opencode, pi, qwen};

/// One built-in tool of one harness.
pub(crate) struct ToolSpec {
    name: &'static str,
    kind: ToolKind,
    /// Argument keys holding the command: a string, or an argv array.
    commands: &'static [&'static str],
    /// Argument keys naming one file the call writes.
    written: &'static [&'static str],
    /// Argument keys naming files or directories the call reads or searches.
    read: &'static [&'static str],
    /// Argument keys holding destination URLs.
    urls: &'static [&'static str],
    /// A patch tool: the argument keys that hold its patch text. The whole
    /// argument string is a patch as well when the call carries no object.
    patch: Option<&'static [&'static str]>,
    /// Argument keys whose text is content the call authors.
    authored: &'static [&'static str],
    /// Argument keys whose text is replaced text, never an action fact.
    replaced: &'static [&'static str],
    /// The call may legitimately name no operand, such as a search with no
    /// root: an empty operand is then no drift.
    optional: bool,
    /// Argument keys whose string value is authored text with the direct-text
    /// budget. This is a bound, not a reading: a command key stays a command.
    text: &'static [&'static str],
    /// The whole argument may be one authored string.
    whole_text: bool,
    /// A `text` key holding anything but a string makes the arguments invalid.
    strict_text: bool,
    /// A tool whose argument is a script that calls other tools: the source's
    /// own reading of the calls the script names. See [`ToolSpec::script`].
    script: Option<ScriptReader>,
}

/// Reads the calls a script tool's arguments name, or `None` to leave the
/// arguments to the row.
pub(crate) type ScriptReader = fn(Option<&JsonValue>) -> Option<ToolOperation>;

impl ToolSpec {
    pub(crate) const fn new(name: &'static str, kind: ToolKind) -> Self {
        Self {
            name,
            kind,
            commands: &[],
            written: &[],
            read: &[],
            urls: &[],
            patch: None,
            authored: &[],
            replaced: &[],
            optional: false,
            text: &[],
            whole_text: false,
            strict_text: false,
            script: None,
        }
    }

    /// The tool runs a script that calls other tools. `reader` returns the
    /// operation those calls make, which stands in place of the row's own
    /// reading and of the script as command text. It is an argument role: a
    /// call the row may not be the tool of is not read with it.
    pub(crate) const fn script(mut self, reader: ScriptReader) -> Self {
        self.script = Some(reader);
        self
    }

    pub(crate) const fn text(mut self, keys: &'static [&'static str]) -> Self {
        self.text = keys;
        self
    }

    pub(crate) const fn whole_text(mut self) -> Self {
        self.whole_text = true;
        self
    }

    pub(crate) const fn strict_text(mut self) -> Self {
        self.strict_text = true;
        self
    }

    /// The authored-text declaration of this row: keys, whole, strict.
    #[cfg(test)]
    pub(crate) fn text_declaration(&self) -> (&'static [&'static str], bool, bool) {
        (self.text, self.whole_text, self.strict_text)
    }

    pub(crate) const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    pub(crate) const fn commands(mut self, keys: &'static [&'static str]) -> Self {
        self.commands = keys;
        self
    }

    pub(crate) const fn written(mut self, keys: &'static [&'static str]) -> Self {
        self.written = keys;
        self
    }

    pub(crate) const fn read(mut self, keys: &'static [&'static str]) -> Self {
        self.read = keys;
        self
    }

    pub(crate) const fn urls(mut self, keys: &'static [&'static str]) -> Self {
        self.urls = keys;
        self
    }

    pub(crate) const fn patch(mut self, keys: &'static [&'static str]) -> Self {
        self.patch = Some(keys);
        self
    }

    pub(crate) const fn authored(mut self, keys: &'static [&'static str]) -> Self {
        self.authored = keys;
        self
    }

    pub(crate) const fn replaced(mut self, keys: &'static [&'static str]) -> Self {
        self.replaced = keys;
        self
    }

    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    pub(crate) fn kind(&self) -> ToolKind {
        self.kind
    }

    /// The operand keys this row reads, by category.
    pub(crate) fn operand_keys(&self) -> [(&'static str, &'static [&'static str]); 7] {
        [
            ("command", self.commands),
            ("written", self.written),
            ("read", self.read),
            ("url", self.urls),
            ("patch", self.patch.unwrap_or(&[])),
            ("authored", self.authored),
            ("replaced", self.replaced),
        ]
    }

    /// Whether the row names an operand the declared call does not carry.
    fn drifted(&self, operation: &ToolOperation) -> bool {
        !self.optional
            && (!self.commands.is_empty() && operation.commands().is_empty()
                || (!self.written.is_empty() || self.patch.is_some())
                    && operation.written_paths().is_empty()
                || !self.read.is_empty() && operation.read_paths().is_empty()
                || !self.urls.is_empty() && operation.urls().is_empty())
    }

    /// The row read against a call's arguments. `roles` is false for a call the
    /// row may not be the tool of: it keeps the kind and operands, which only add
    /// readings, and gets no argument role, which replaces one.
    fn operation(&self, arguments: Option<&JsonValue>, roles: bool) -> ToolOperation {
        if roles && let Some(operation) = self.script.and_then(|reader| reader(arguments)) {
            return operation;
        }
        let members = Members::of(arguments);
        let mut operation = ToolOperation::new(self.kind);
        for key in self.commands {
            if let Some(command) = members.command(key) {
                operation = operation.with_command(command);
            }
        }
        for key in self.written {
            for path in members.strings(key) {
                operation = operation.with_written_path(path);
            }
        }
        for key in self.read {
            for path in members.strings(key) {
                operation = operation.with_read_path(path);
            }
        }
        for key in self.urls {
            for url in members.strings(key) {
                operation = operation.with_url(url);
            }
        }
        if let Some(keys) = self.patch {
            let texts = keys
                .iter()
                .filter_map(|key| members.text(key))
                .chain(members.raw().map(str::to_owned));
            for text in texts {
                for path in patch_targets(&text) {
                    operation = operation.with_written_path(path);
                }
            }
            // A patch is authored content; text that is none keeps its reading.
            for key in keys.iter().filter(|_| roles) {
                if members.text(key).is_some_and(|text| is_patch(&text)) {
                    operation = operation.with_authored_key(*key);
                }
            }
            if roles && members.raw().is_some_and(is_patch) {
                operation = operation.with_authored_text();
            }
        }
        if !roles {
            return operation;
        }
        for key in self.authored.iter().filter(|key| members.has(key)) {
            operation = operation.with_authored_key(*key);
        }
        for key in self.replaced.iter().filter(|key| members.has(key)) {
            operation = operation.with_replaced_key(*key);
        }
        operation
    }
}

/// Declare the operation a source's table gives a tool call: the tool's row,
/// read against the arguments already on the body. A tool with no row stays
/// undeclared.
pub(crate) fn declare(table: &[ToolSpec], body: ToolObservation) -> ToolObservation {
    declare_in(table, body, None)
}

/// [`declare`] for a call whose record may name the namespace the tool belongs
/// to. A namespace an MCP server's tools carry is never declared, whatever the
/// tool is called. Under any other namespace the name may be a built-in tool or
/// another tool with its name, so the call gets the row's kind and operands and
/// no argument role.
pub(crate) fn declare_in(
    table: &[ToolSpec],
    body: ToolObservation,
    namespace: Option<&str>,
) -> ToolObservation {
    if namespace.is_some_and(mcp_shaped) {
        return body;
    }
    let operation = body
        .name()
        .filter(|name| !mcp_shaped(name))
        .and_then(|name| table.iter().find(|spec| spec.name == name))
        .map(|spec| spec.operation(body.arguments(), namespace.is_none()));
    match operation {
        Some(operation) => body.with_operation(operation),
        None => body,
    }
}

/// The authored text declared for a call named `name`: its row in `table`
/// together with every registered table's row of that exact name, so a name
/// keeps its declaration wherever it is read (a hook journal can report a tool
/// under another harness's spelling). A name no table lists, and a name MCP
/// servers give their tools, declare none: their arguments keep the structured
/// bounds.
pub(crate) fn argument_text(table: &[ToolSpec], name: Option<&str>) -> ArgumentText {
    let mut declared = ArgumentText::new();
    let Some(name) = name.filter(|name| !mcp_shaped(name)) else {
        return declared;
    };
    let registered = ClientId::ALL
        .iter()
        .filter_map(|client| self::table(*client));
    for spec in std::iter::once(table)
        .chain(registered)
        .flatten()
        .filter(|spec| spec.name == name)
    {
        for key in spec.text {
            declared = declared.with_key(*key);
        }
        if spec.whole_text {
            declared = declared.with_whole();
        }
        if spec.strict_text {
            declared = declared.with_strict();
        }
    }
    declared
}

/// What a tool call's values over a canonical bound do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ValueBounds {
    /// Replace each over-bound value by `null` and record it on the body, so
    /// the call's name and admitted values are still evaluated.
    #[default]
    Replace,
    /// [`ValueBounds::Replace`], and omit a derived searchable text over its
    /// bound, recording it ([`with_searchable_text`]), so the values are
    /// kept. Only [`build_fitted`] asks for it, after the call's observation
    /// failed a value bound; [`ValueBounds::Fit`] and [`ValueBounds::Whole`]
    /// omit such a text as well.
    OmitText,
    /// [`ValueBounds::OmitText`], then fit the arguments and result together
    /// into the room the rest of the observation leaves
    /// ([`ToolObservation::with_fitted_values`]).
    Fit,
    /// [`ValueBounds::OmitText`], then replace the arguments and the result
    /// whole ([`ToolObservation::with_replaced_values`]): [`build_fitted`]'s
    /// last attempt.
    Whole,
    /// Fail the call, so its unit is quarantined.
    Strict,
}

/// Build a tool call's observation with `build`, converting its values under
/// `bounds`. When that fails on a value bound and `bounds` replaces values,
/// build it again with a derived searchable text over its bound omitted
/// ([`ValueBounds::OmitText`]), so the values themselves are kept. Should that
/// fail on a bound too, build it with the values fitted ([`ValueBounds::Fit`]):
/// each value may be admitted on its own and still overflow the observation
/// together with the other value, the tool name or the facets. Should that
/// fail on a bound as well, a last attempt replaces both values whole
/// ([`ValueBounds::Whole`]). A call that builds takes exactly its first
/// attempt; one that no attempt builds keeps the first attempt's error.
/// `bound` names a value-bound failure in the adapter's error.
pub(crate) fn build_fitted<T, E>(
    bounds: ValueBounds,
    bound: impl Fn(&E) -> bool,
    mut build: impl FnMut(ValueBounds) -> Result<T, E>,
) -> Result<T, E> {
    let error = match build(bounds) {
        Err(error) if bounds == ValueBounds::Replace && bound(&error) => error,
        outcome => return outcome,
    };
    for retry in [ValueBounds::OmitText, ValueBounds::Fit] {
        match build(retry) {
            Err(failed) if bound(&failed) => {}
            outcome => return outcome.map_err(|_| error),
        }
    }
    build(ValueBounds::Whole).map_err(|_| error)
}

/// Set a call's derived searchable text (`target` is
/// [`BoundedTarget::SearchableArguments`] or
/// [`BoundedTarget::SearchableResult`]). Under [`ValueBounds::Replace`] and
/// [`ValueBounds::Strict`] the text is set as given, so one over its bound
/// fails the call's observation; under the retries of [`build_fitted`] it is
/// omitted and recorded instead. The caller adds the field's metadata only
/// when the text is set.
pub(crate) fn with_searchable_text(
    body: ToolObservation,
    target: BoundedTarget,
    text: &str,
    bounds: ValueBounds,
) -> Result<ToolObservation, ObservationError> {
    let omit = matches!(
        bounds,
        ValueBounds::OmitText | ValueBounds::Fit | ValueBounds::Whole
    );
    match (target, omit) {
        (BoundedTarget::SearchableArguments, false) => body.with_searchable_arguments(text),
        (BoundedTarget::SearchableArguments, true) => body.with_bounded_searchable_arguments(text),
        (BoundedTarget::SearchableResult, false) => body.with_searchable_result(text),
        (BoundedTarget::SearchableResult, true) => body.with_bounded_searchable_result(text),
        (BoundedTarget::Arguments | BoundedTarget::Result, _) => {
            unreachable!("a tool value is no searchable text")
        }
    }
}

/// The budget a tool result's direct text gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResultText {
    /// A string result is direct output text ([`JsonValue::try_from_source_tool_result`]).
    Direct,
    /// Every result keeps the structured bounds ([`JsonValue::try_from_source_value`]).
    Structured,
}

/// Convert a call's native arguments under the text `table` declares for
/// `name`, and keep the declaration on the body for validation.
pub(crate) fn with_source_arguments(
    table: &[ToolSpec],
    name: Option<&str>,
    body: ToolObservation,
    arguments: &serde_json::Value,
    bounds: ValueBounds,
) -> Result<ToolObservation, ObservationError> {
    with_declared_arguments(argument_text(table, name), body, arguments, bounds)
}

/// Convert a call's native arguments under `declared` (no declaration keeps
/// every argument on the structured bounds). See [`bounded_or_strict`].
pub(crate) fn with_declared_arguments(
    declared: ArgumentText,
    body: ToolObservation,
    arguments: &serde_json::Value,
    bounds: ValueBounds,
) -> Result<ToolObservation, ObservationError> {
    let (value, replaced) = bounded_or_strict(
        JsonValue::try_from_source_tool_arguments(&declared, arguments),
        bounds,
        || JsonValue::try_from_source_tool_arguments_bounded(&declared, arguments),
    )
    .map_err(|error| error.with_bound_category(CanonicalFieldCategory::ToolArguments))?;
    fitted(
        body.with_arguments(value)
            .with_argument_text(declared)
            .with_bounded_values(replaced),
        bounds,
    )
}

/// The body as converted, or with its values fitted under [`ValueBounds::Fit`].
fn fitted(body: ToolObservation, bounds: ValueBounds) -> Result<ToolObservation, ObservationError> {
    match bounds {
        ValueBounds::Fit => body.with_fitted_values(),
        ValueBounds::Whole => body.with_replaced_values(),
        ValueBounds::Replace | ValueBounds::OmitText | ValueBounds::Strict => Ok(body),
    }
}

/// Convert a call's native result. See [`bounded_or_strict`].
pub(crate) fn with_source_result(
    body: ToolObservation,
    result: &serde_json::Value,
    text: ResultText,
    bounds: ValueBounds,
) -> Result<ToolObservation, ObservationError> {
    let (value, replaced) = match text {
        ResultText::Direct => bounded_or_strict(
            JsonValue::try_from_source_tool_result(result),
            bounds,
            || JsonValue::try_from_source_tool_result_bounded(result),
        ),
        ResultText::Structured => {
            bounded_or_strict(JsonValue::try_from_source_value(result), bounds, || {
                JsonValue::try_from_source_value_bounded(BoundedTarget::Result, result)
            })
        }
    }
    .map_err(|error| error.with_bound_category(CanonicalFieldCategory::ToolResult))?;
    fitted(
        body.with_result(value).with_bounded_values(replaced),
        bounds,
    )
}

/// The strict conversion decides every value it admits, so an in-bound call
/// takes exactly today's path. Only a value it refuses on a bound, or whose
/// encoded size alone exceeds the observation aggregate (a call that could
/// never be built), takes the bounded conversion, which replaces the
/// over-bound parts by `null` and records them. Other errors still fail.
fn bounded_or_strict(
    strict: Result<JsonValue, ObservationError>,
    bounds: ValueBounds,
    bounded: impl FnOnce() -> Result<(JsonValue, Vec<BoundedValue>), ObservationError>,
) -> Result<(JsonValue, Vec<BoundedValue>), ObservationError> {
    match strict {
        Ok(value)
            if bounds == ValueBounds::Strict
                || value.encoded_byte_len()? <= SEMANTIC_MAX_TOTAL_BYTES =>
        {
            Ok((value, Vec::new()))
        }
        Err(error) if bounds == ValueBounds::Strict || error.bound_dimension().is_none() => {
            Err(error)
        }
        _ => bounded(),
    }
}

/// The argument keys among `keys` that a bounded conversion replaced, taken
/// before the body moves into its builder, so no facet is built from them.
pub(crate) fn replaced_arguments(
    body: &ToolObservation,
    keys: &[&'static str],
) -> Vec<&'static str> {
    keys.iter()
        .copied()
        .filter(|key| body.bounded_member(BoundedTarget::Arguments, key))
        .collect()
}

/// Where a native unit was admitted with replaced tool values, and which
/// field and bound: coordinates only, never content. Kept apart from
/// quarantined units, since the unit itself was projected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundedRecord {
    pub(crate) source_sequence: u64,
    pub(crate) target: BoundedTarget,
    pub(crate) dimension: BoundDimension,
}

/// The distinct (field, bound) pairs one unit's observations replaced.
pub(crate) fn bounded_records(
    source_sequence: u64,
    observations: &[CanonicalObservationV2],
) -> Vec<BoundedRecord> {
    let mut records: Vec<BoundedRecord> = Vec::new();
    for observation in observations {
        let ObservationBody::Tool(tool) = observation.body() else {
            continue;
        };
        for value in tool.bounded_values() {
            let record = BoundedRecord {
                source_sequence,
                target: value.target(),
                dimension: value.dimension(),
            };
            if !records.contains(&record) {
                records.push(record);
            }
        }
    }
    records
}

/// The table of one source's harness.
pub(crate) fn table(client: ClientId) -> Option<&'static [ToolSpec]> {
    Some(match client {
        ClientId::Claude => claude::tools::TOOLS,
        ClientId::Codex => codex::tools::TOOLS,
        ClientId::Copilot => copilot::tools::TOOLS,
        ClientId::OpenClaw => openclaw::tools::TOOLS,
        ClientId::OpenCode => opencode::tools::TOOLS,
        ClientId::Qwen => qwen::tools::TOOLS,
        ClientId::Pi => pi::tools::TOOLS,
        _ => return None,
    })
}

/// A name MCP servers give their tools, which no harness table lists.
fn mcp_shaped(name: &str) -> bool {
    let name = name.trim_start().to_ascii_lowercase();
    name.strip_prefix("mcp")
        .is_some_and(|rest| rest.starts_with(['_', '-', '.', ':']))
}

/// Count, over the tool requests a source read produced, the calls whose name
/// no table row lists (and that are not MCP-shaped) and the declared calls
/// whose row names an operand the call lacks. Counting reads the observations
/// only: it changes none of them and carries no name, argument or path.
pub(crate) fn count(client: ClientId, observations: &[CanonicalObservationV2]) -> ToolTableCounts {
    let mut counts = ToolTableCounts::default();
    let Some(table) = table(client) else {
        return counts;
    };
    for observation in observations {
        let ObservationBody::Tool(body) = observation.body() else {
            continue;
        };
        if observation.stage() != ObservationStage::ToolRequested {
            continue;
        }
        let Some(name) = body.name() else { continue };
        match table.iter().find(|spec| spec.name == name) {
            None if !mcp_shaped(name) => {
                counts.unclassified_tool_calls = counts.unclassified_tool_calls.saturating_add(1);
            }
            // An operand replaced for its size is not drift.
            Some(spec)
                if !body
                    .bounded_values()
                    .iter()
                    .any(|value| value.target() == BoundedTarget::Arguments)
                    && body.operation().is_some_and(|op| spec.drifted(op)) =>
            {
                counts.tool_operand_drift = counts.tool_operand_drift.saturating_add(1);
            }
            _ => {}
        }
    }
    counts
}

/// The top-level members of a call's arguments: an object, the JSON-encoded
/// object some native envelopes carry as a string, or plain text.
enum Members<'a> {
    None,
    Object(&'a BTreeMap<String, JsonValue>),
    /// An encoded object. Each member stays raw JSON until a table asks for it,
    /// so a member nested past the parser's depth limit hides no other member
    /// and its text is never read as an operand.
    Decoded(BTreeMap<String, Box<serde_json::value::RawValue>>),
    /// Text that is not a JSON object at all.
    Raw(&'a str),
}

impl<'a> Members<'a> {
    fn of(arguments: Option<&'a JsonValue>) -> Self {
        match arguments {
            Some(JsonValue::Object(members)) => Self::Object(members),
            Some(JsonValue::String(text)) => {
                let decoded = text
                    .trim_start()
                    .starts_with('{')
                    .then(|| serde_json::from_str(text).ok())
                    .flatten();
                decoded.map_or(Self::Raw(text), Self::Decoded)
            }
            _ => Self::None,
        }
    }

    /// The decoded value of an encoded member; one nested too deep has none.
    fn decoded(&self, key: &str) -> Option<serde_json::Value> {
        match self {
            Self::Decoded(members) => serde_json::from_str(members.get(key)?.get()).ok(),
            _ => None,
        }
    }

    /// The text of an argument that is one string.
    fn text(&self, key: &str) -> Option<String> {
        match self {
            Self::Object(members) => match members.get(key) {
                Some(JsonValue::String(text)) => Some(text.clone()),
                _ => None,
            },
            Self::Decoded(_) => match self.decoded(key) {
                Some(serde_json::Value::String(text)) => Some(text),
                _ => None,
            },
            Self::None | Self::Raw(_) => None,
        }
    }

    /// Whether the call's argument object has a member under `key`.
    fn has(&self, key: &str) -> bool {
        match self {
            Self::Object(members) => members.contains_key(key),
            Self::Decoded(members) => members.contains_key(key),
            Self::None | Self::Raw(_) => false,
        }
    }

    /// The whole argument text of a call that carries no object.
    fn raw(&self) -> Option<&str> {
        match self {
            Self::Raw(text) => Some(text),
            _ => None,
        }
    }

    /// The strings of an argument that is a string or an array of them.
    fn strings(&self, key: &str) -> Vec<String> {
        match self {
            Self::Object(members) => match members.get(key) {
                Some(JsonValue::String(text)) => vec![text.clone()],
                Some(JsonValue::Array(items)) => items
                    .iter()
                    .filter_map(|item| match item {
                        JsonValue::String(text) => Some(text.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
            Self::Decoded(_) => match self.decoded(key) {
                Some(serde_json::Value::String(text)) => vec![text],
                Some(serde_json::Value::Array(items)) => items
                    .into_iter()
                    .filter_map(|item| match item {
                        serde_json::Value::String(text) => Some(text),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            },
            Self::None | Self::Raw(_) => Vec::new(),
        }
    }

    /// A command: one string, an argv array joined by spaces, or the whole
    /// argument text of a call that carries no object.
    fn command(&self, key: &str) -> Option<String> {
        match self {
            Self::Raw(text) => Some((*text).to_owned()),
            _ => self.text(key).or_else(|| {
                let argv = self.strings(key);
                (!argv.is_empty()).then(|| argv.join(" "))
            }),
        }
    }
}

const BEGIN_PATCH: &str = "*** Begin Patch";
const END_PATCH: &str = "*** End Patch";
/// First lines Codex's lenient parser accepts before `*** Begin Patch`.
const HEREDOC_MARKERS: &[&str] = &["<<EOF", "<<'EOF'", "<<\"EOF\""];

/// Whether `text` is a patch by Codex's boundary check (0.166.0 lenient mode,
/// `apply-patch/src/parser.rs`). After trimming, either the first line is
/// `*** Begin Patch` and the last is `*** End Patch`, or the first line is
/// exactly `<<EOF`, `<<'EOF'` or `<<"EOF"`, the last ends with `EOF`, and the
/// lines just inside them are the two markers (compared trimmed). Text before
/// the opening marker or after the closing one is not a patch, so no command
/// text can hide around one.
pub(crate) fn is_patch(text: &str) -> bool {
    let mut lines = text.trim().lines();
    let (Some(first), Some(last)) = (lines.next(), lines.next_back()) else {
        return false;
    };
    if HEREDOC_MARKERS.contains(&first) {
        let (Some(begin), Some(end)) = (lines.next(), lines.next_back()) else {
            return false;
        };
        last.ends_with("EOF") && begin.trim() == BEGIN_PATCH && end.trim() == END_PATCH
    } else {
        first.trim() == BEGIN_PATCH && last.trim() == END_PATCH
    }
}

/// File-operation headers of the `*** Begin Patch` format. `Move to` names the
/// new path of an updated file.
const PATCH_HEADERS: &[&str] = &[
    "*** Add File: ",
    "*** Update File: ",
    "*** Delete File: ",
    "*** Move to: ",
];

/// The files a patch in the `*** Begin Patch` format names. Only a header at
/// the start of a line counts, so content lines, which start with a space, `+`
/// or `-`, never do. Text without the `*** Begin Patch` line names nothing.
fn patch_targets(text: &str) -> Vec<String> {
    if !text.lines().any(|line| line.trim() == BEGIN_PATCH) {
        return Vec::new();
    }
    text.lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            PATCH_HEADERS
                .iter()
                .find_map(|header| line.strip_prefix(header))
        })
        .map(|path| path.trim().to_owned())
        .filter(|path| !path.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tool(name: &str, arguments: serde_json::Value) -> ToolObservation {
        ToolObservation::new()
            .with_name(name)
            .unwrap()
            .with_arguments(JsonValue::try_from_source_value(&arguments).unwrap())
    }

    fn declared(table: &[ToolSpec], body: ToolObservation) -> ToolOperation {
        declare(table, body).operation().cloned().expect("declared")
    }

    /// The attempts [`build_fitted`] makes: the first only, unless it fails on
    /// a bound under [`ValueBounds::Replace`]; then the omitted text, the
    /// fitted values and the whole replacement, stopping at the first that
    /// builds. Strict conversion never retries.
    #[test]
    fn build_fitted_omits_searchable_text_before_fitting_values() {
        let attempts = |bounds, builds: Option<ValueBounds>, error: &'static str| {
            let mut seen = Vec::new();
            let outcome = build_fitted(
                bounds,
                |error: &&str| *error == "bound",
                |attempt| {
                    seen.push(attempt);
                    if Some(attempt) == builds {
                        Ok(attempt)
                    } else {
                        Err(error)
                    }
                },
            );
            (seen, outcome)
        };
        use ValueBounds::{Fit, OmitText, Replace, Strict, Whole};
        assert_eq!(
            attempts(Replace, Some(Replace), "bound"),
            (vec![Replace], Ok(Replace))
        );
        assert_eq!(
            attempts(Replace, Some(OmitText), "bound"),
            (vec![Replace, OmitText], Ok(OmitText))
        );
        assert_eq!(
            attempts(Replace, Some(Fit), "bound"),
            (vec![Replace, OmitText, Fit], Ok(Fit))
        );
        assert_eq!(
            attempts(Replace, Some(Whole), "bound"),
            (vec![Replace, OmitText, Fit, Whole], Ok(Whole))
        );
        assert_eq!(
            attempts(Replace, None, "bound"),
            (vec![Replace, OmitText, Fit, Whole], Err("bound"))
        );
        assert_eq!(
            attempts(Replace, None, "other"),
            (vec![Replace], Err("other"))
        );
        assert_eq!(
            attempts(Strict, None, "bound"),
            (vec![Strict], Err("bound"))
        );
    }

    /// Only the retries omit a searchable text over its bound; the first
    /// attempt and strict conversion set it as given, so it fails the call.
    #[test]
    fn searchable_text_is_omitted_only_on_a_retry() {
        let text = "x".repeat(4_097);
        for target in [
            BoundedTarget::SearchableArguments,
            BoundedTarget::SearchableResult,
        ] {
            for bounds in [ValueBounds::Replace, ValueBounds::Strict] {
                let body =
                    with_searchable_text(ToolObservation::new(), target, &text, bounds).unwrap();
                assert!(body.bounded_values().is_empty(), "{bounds:?}");
                assert!(
                    body.searchable_arguments()
                        .or(body.searchable_result())
                        .is_some(),
                    "{bounds:?}"
                );
            }
            for bounds in [ValueBounds::OmitText, ValueBounds::Fit, ValueBounds::Whole] {
                let body =
                    with_searchable_text(ToolObservation::new(), target, &text, bounds).unwrap();
                assert_eq!(
                    body.searchable_arguments().or(body.searchable_result()),
                    None
                );
                assert_eq!(
                    body.bounded_values()
                        .iter()
                        .map(|value| (value.target(), value.dimension()))
                        .collect::<Vec<_>>(),
                    [(target, BoundDimension::StringBytes)],
                    "{bounds:?}"
                );
                // Within its bound the text is kept on every attempt.
                let kept =
                    with_searchable_text(ToolObservation::new(), target, "short", bounds).unwrap();
                assert!(kept.bounded_values().is_empty());
            }
        }
    }

    type TextRow = (&'static str, &'static [&'static str], bool, bool);

    /// Every row of `table` that declares authored text, as `(name, keys,
    /// whole, strict)`.
    fn text_rows(table: &[ToolSpec]) -> Vec<TextRow> {
        table
            .iter()
            .filter_map(|spec| {
                let (keys, whole, strict) = spec.text_declaration();
                (!keys.is_empty() || whole || strict).then_some((spec.name(), keys, whole, strict))
            })
            .collect()
    }

    #[test]
    fn claude_declares_its_authored_text_arguments() {
        let expected: &[TextRow] = &[
            ("Bash", &["command"], false, false),
            ("PowerShell", &["command"], false, false),
            ("Write", &["content"], false, false),
            ("Edit", &["old_string", "new_string"], false, false),
            ("NotebookEdit", &["new_source"], false, false),
            ("Task", &["prompt"], false, false),
            ("Agent", &["prompt"], false, false),
            ("SendMessage", &["message"], false, false),
            ("SubagentHandback", &["message"], false, false),
        ];
        assert_eq!(text_rows(claude::tools::TOOLS), expected);
    }

    #[test]
    fn opencode_declares_its_authored_text_arguments() {
        let expected: &[TextRow] = &[
            ("bash", &["command"], false, false),
            ("shell", &["command"], true, false),
            ("write", &["content"], false, false),
            ("edit", &["oldString", "newString"], false, false),
            ("patch", &["patchText"], false, false),
            ("apply_patch", &["patchText"], false, true),
            ("task", &["prompt"], false, false),
            ("subagent", &["prompt"], false, false),
            ("execute", &["code"], false, false),
        ];
        assert_eq!(text_rows(opencode::tools::TOOLS), expected);
    }

    #[test]
    fn pi_declares_its_authored_text_arguments() {
        let expected: &[TextRow] = &[
            ("bash", &["command"], false, false),
            ("powershell", &["command"], false, false),
            ("write", &["content"], false, false),
            ("edit", &["oldText", "newText"], false, false),
        ];
        assert_eq!(text_rows(pi::tools::TOOLS), expected);
    }

    #[test]
    fn codex_declares_its_authored_text_arguments() {
        let expected: &[TextRow] = &[
            ("apply_patch", &[], true, false),
            ("exec", &[], true, false),
        ];
        assert_eq!(text_rows(codex::tools::TOOLS), expected);
    }

    /// Copilot, Qwen and OpenClaw convert their own records with the structured
    /// bounds and declare no text; their hook journals read shared spellings.
    #[test]
    fn copilot_qwen_and_openclaw_declare_no_authored_text() {
        for table in [
            copilot::tools::TOOLS,
            qwen::tools::TOOLS,
            openclaw::tools::TOOLS,
        ] {
            assert!(text_rows(table).is_empty());
        }
    }

    /// The move from one shared list into the adapters keeps every name's
    /// declaration wherever the name is read, including a hook journal read
    /// with a table that has no row for it. The message tools are new.
    #[test]
    fn every_formerly_shared_declaration_holds_for_every_table() {
        let expected: &[TextRow] = &[
            ("apply_patch", &["patchText"], true, true),
            ("patch", &["patchText"], false, false),
            ("shell", &["command"], true, false),
            ("bash", &["command"], false, false),
            ("powershell", &["command"], false, false),
            ("write", &["content"], false, false),
            (
                "edit",
                &["oldString", "newString", "oldText", "newText"],
                false,
                false,
            ),
            ("execute", &["code"], false, false),
            ("subagent", &["prompt"], false, false),
            ("task", &["prompt"], false, false),
            ("exec", &[], true, false),
            ("Bash", &["command"], false, false),
            ("PowerShell", &["command"], false, false),
            ("Write", &["content"], false, false),
            ("Edit", &["old_string", "new_string"], false, false),
            ("NotebookEdit", &["new_source"], false, false),
            ("Task", &["prompt"], false, false),
            ("Agent", &["prompt"], false, false),
            ("SendMessage", &["message"], false, false),
            ("SubagentHandback", &["message"], false, false),
        ];
        for client in ClientId::ALL {
            let own = table(*client).expect("every client has a table");
            for (name, keys, whole, strict) in expected {
                let declared = argument_text(own, Some(name));
                let mut actual: Vec<&str> = declared.keys().iter().map(String::as_str).collect();
                let mut keys = keys.to_vec();
                actual.sort_unstable();
                keys.sort_unstable();
                assert_eq!(
                    (actual, declared.whole(), declared.strict()),
                    (keys, *whole, *strict),
                    "{client:?} {name}"
                );
            }
            for name in [None, Some("NoSuchTool"), Some("mcp__server__write")] {
                assert_eq!(argument_text(own, name), ArgumentText::new());
            }
        }
    }

    #[test]
    fn a_tool_with_no_row_stays_undeclared() {
        let body = declare(
            claude::tools::TOOLS,
            tool("NoSuchTool", serde_json::json!({"file_path": "/p/a"})),
        );
        assert!(body.operation().is_none());
        let body = declare(claude::tools::TOOLS, ToolObservation::new());
        assert!(body.operation().is_none());
    }

    #[test]
    fn operands_come_from_objects_encoded_objects_argv_and_plain_text() {
        let table = &[
            ToolSpec::new("run", ToolKind::Shell).commands(&["cmd", "command"]),
            ToolSpec::new("save", ToolKind::FileWrite).written(&["path"]),
            ToolSpec::new("look", ToolKind::FileRead).read(&["paths"]),
            ToolSpec::new("fetch", ToolKind::Web).urls(&["url"]),
        ];
        let operation = declared(table, tool("run", serde_json::json!({"cmd": "ls /p"})));
        assert_eq!(operation.kind(), ToolKind::Shell);
        assert_eq!(operation.commands(), ["ls /p"]);
        let operation = declared(
            table,
            tool("run", serde_json::json!({"command": ["cat", "/p/a"]})),
        );
        assert_eq!(operation.commands(), ["cat /p/a"]);
        let encoded = serde_json::json!({"command": "ls"}).to_string();
        let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
        assert_eq!(operation.commands(), ["ls"]);
        let operation = declared(table, tool("run", serde_json::json!("ls /bare")));
        assert_eq!(operation.commands(), ["ls /bare"]);
        let operation = declared(table, tool("save", serde_json::json!({"path": "/p/a"})));
        assert_eq!(operation.written_paths(), ["/p/a"]);
        let operation = declared(
            table,
            tool("look", serde_json::json!({"paths": ["/p/a", "/p/b"]})),
        );
        assert_eq!(operation.read_paths(), ["/p/a", "/p/b"]);
        let operation = declared(
            table,
            tool(
                "fetch",
                serde_json::json!({"url": "https://example.test/x"}),
            ),
        );
        assert_eq!(operation.urls(), ["https://example.test/x"]);
        // The kind is declared even when the call holds no operand.
        let operation = declared(table, tool("save", serde_json::json!({"other": 1})));
        assert_eq!(operation.kind(), ToolKind::FileWrite);
        assert!(operation.written_paths().is_empty());
    }

    #[test]
    fn patch_tools_name_their_files_from_headers_only() {
        let table = &[ToolSpec::new("patch", ToolKind::FileWrite).patch(&["patchText"])];
        let text = "*** Begin Patch\n*** Add File: /p/new\n+*** Update File: /p/not-a-header\n*** Update File: /p/old\n*** Move to: /p/moved\n*** Delete File: /p/gone\n*** End Patch";
        let expected = ["/p/new", "/p/old", "/p/moved", "/p/gone"];
        for arguments in [
            serde_json::json!({"patchText": text}),
            serde_json::json!(text),
            serde_json::Value::String(serde_json::json!({"patchText": text}).to_string()),
        ] {
            let operation = declared(table, tool("patch", arguments));
            assert_eq!(operation.written_paths(), expected);
        }
        let operation = declared(
            table,
            tool(
                "patch",
                serde_json::json!({"patchText": "*** Add File: /p/x"}),
            ),
        );
        assert!(operation.written_paths().is_empty());
    }

    #[test]
    fn an_over_deep_member_hides_no_other_member_and_adds_no_command() {
        let table = &[ToolSpec::new("run", ToolKind::Shell).commands(&["command"])];
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        let encoded = format!(r#"{{"command":"ls /p","prose":"not a command","deep":{deep}}}"#);
        let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
        assert_eq!(operation.commands(), ["ls /p"]);
        // An over-deep member under a key the table reads has no operand.
        let encoded = format!(r#"{{"command":{deep},"prose":"not a command"}}"#);
        let operation = declared(table, tool("run", serde_json::Value::String(encoded)));
        assert!(operation.commands().is_empty());
        // Only text that is no JSON object at all is a bare command.
        let operation = declared(table, tool("run", serde_json::json!("{not json")));
        assert_eq!(operation.commands(), ["{not json"]);
    }

    #[test]
    fn restored_rows_declare_their_operands_only_when_the_call_carries_them() {
        use ToolKind::{FileRead, FileWrite, Shell, Web};
        let patch = "*** Begin Patch\n*** Add File: /p/new\n+x\n*** End Patch";
        let cases: [(&[ToolSpec], &str, serde_json::Value, ToolKind); 7] = [
            (
                qwen::tools::TOOLS,
                "monitor",
                serde_json::json!({"command": "ls /p"}),
                Shell,
            ),
            (
                qwen::tools::TOOLS,
                "list_directory",
                serde_json::json!({"path": "/p"}),
                FileRead,
            ),
            (
                qwen::tools::TOOLS,
                "web_fetch",
                serde_json::json!({"url": "https://example.test/x"}),
                Web,
            ),
            (
                openclaw::tools::TOOLS,
                "exec",
                serde_json::json!({"command": "ls /p"}),
                Shell,
            ),
            (
                openclaw::tools::TOOLS,
                "apply_patch",
                serde_json::json!({"input": patch}),
                FileWrite,
            ),
            (
                openclaw::tools::TOOLS,
                "web_fetch",
                serde_json::json!({"url": "https://example.test/x"}),
                Web,
            ),
            (
                codex::tools::TOOLS,
                "view_image",
                serde_json::json!({"path": "/p/image"}),
                FileRead,
            ),
        ];
        for (table, name, arguments, kind) in cases {
            let operation = declared(table, tool(name, arguments));
            assert_eq!(operation.kind(), kind, "{name}");
            let operands = operation.commands().len()
                + operation.written_paths().len()
                + operation.read_paths().len()
                + operation.urls().len();
            assert_eq!(operands, 1, "{name}");
            // The same call without its operand declares the kind and no fact.
            let operation = declared(table, tool(name, serde_json::json!({"other": "x"})));
            assert_eq!(operation.kind(), kind, "{name}");
            assert!(
                operation.commands().is_empty()
                    && operation.written_paths().is_empty()
                    && operation.read_paths().is_empty()
                    && operation.urls().is_empty(),
                "{name}"
            );
        }
    }

    const PATCH: &str = "*** Begin Patch\n*** Update File: /p/old\n+x\n*** End Patch\n";

    #[test]
    fn argument_roles_come_only_from_the_keys_a_row_names() {
        let table = copilot::tools::TOOLS;
        let operation = declared(
            table,
            tool(
                "edit",
                serde_json::json!({"path": "/p/a", "new_str": "n", "old_str": "o", "note": "x"}),
            ),
        );
        assert_eq!(operation.authored_keys(), ["new_str"]);
        assert_eq!(operation.replaced_keys(), ["old_str"]);
        // A key no row names has no role, whatever it looks like, and neither
        // has a row that names none.
        let operation = declared(
            table,
            tool(
                "edit",
                serde_json::json!({"path": "/p/a", "newString": "n"}),
            ),
        );
        assert!(!operation.has_roles());
        let operation = declared(
            claude::tools::TOOLS,
            tool(
                "Edit",
                serde_json::json!({"file_path": "/p/a", "new_str": "n", "old_str": "o"}),
            ),
        );
        assert!(!operation.has_roles());
    }

    #[test]
    fn a_patch_key_is_authored_content_only_when_its_text_is_a_patch() {
        let table = codex::tools::TOOLS;
        let operation = declared(
            table,
            tool("apply_patch", serde_json::json!({"command": PATCH})),
        );
        assert_eq!(operation.authored_keys(), ["command"]);
        assert_eq!(operation.written_paths(), ["/p/old"]);
        let heredoc = format!("<<'EOF'\n{PATCH}EOF\n");
        let operation = declared(
            table,
            tool("apply_patch", serde_json::json!({"command": heredoc})),
        );
        assert_eq!(operation.authored_keys(), ["command"]);
        // A command, or text around a patch, keeps its structural reading.
        for text in [
            "ls /p".to_owned(),
            format!("ls /p\n{PATCH}"),
            format!("{PATCH}ls /p\n"),
            "*** Begin Patch\n+x\n".to_owned(),
        ] {
            let operation = declared(
                table,
                tool("apply_patch", serde_json::json!({"command": text})),
            );
            assert!(!operation.has_roles(), "{text:?}");
        }
        // The same holds for the whole argument text of a call with no object.
        let operation = declared(
            copilot::tools::TOOLS,
            tool("apply_patch", serde_json::json!(PATCH)),
        );
        assert!(operation.authored_text());
        assert_eq!(operation.written_paths(), ["/p/old"]);
        for text in ["rm -rf /p", &format!("rm -rf /p\n{PATCH}")] {
            let operation = declared(
                copilot::tools::TOOLS,
                tool("apply_patch", serde_json::json!(text)),
            );
            assert!(!operation.authored_text(), "{text:?}");
        }
    }

    #[test]
    fn a_namespaced_call_gets_a_kind_and_operands_and_no_role() {
        let patch = "*** Begin Patch\n*** Add File: /p/a.rs\n+x\n*** End Patch\n";
        let call = || tool("apply_patch", serde_json::json!({"input": patch}));
        let table = codex::tools::TOOLS;
        let bare = declare_in(table, call(), None);
        assert!(bare.operation().unwrap().has_roles());
        // An MCP server's namespace: the row is not this tool's.
        assert!(
            declare_in(table, call(), Some("mcp__srv__files"))
                .operation()
                .is_none()
        );
        // Any other namespace: the kind and the written paths, and no role.
        let other = declare_in(table, call(), Some("extension"));
        let operation = other.operation().unwrap();
        assert_eq!(operation.kind(), bare.operation().unwrap().kind());
        assert_eq!(operation.written_paths(), ["/p/a.rs".to_owned()]);
        assert!(!operation.has_roles());
        // A built-in tool that carries a namespace keeps its kind.
        let delegate = declare_in(
            table,
            tool("spawn_agent", serde_json::json!({"message": "m"})),
            Some("collaboration"),
        );
        assert_eq!(delegate.operation().unwrap().kind(), ToolKind::Delegate);
    }

    #[test]
    fn a_name_an_mcp_server_gives_its_tools_is_never_declared() {
        let table = &[
            ToolSpec::new("mcp__srv__edit", ToolKind::FileWrite)
                .written(&["path"])
                .authored(&["new_str"]),
            ToolSpec::new("edit", ToolKind::FileWrite)
                .written(&["path"])
                .authored(&["new_str"]),
        ];
        let arguments = serde_json::json!({"path": "/p/a", "new_str": "n"});
        assert!(
            declare(table, tool("mcp__srv__edit", arguments.clone()))
                .operation()
                .is_none()
        );
        assert!(
            declare(table, tool("MCP-srv.edit", arguments.clone()))
                .operation()
                .is_none()
        );
        assert!(declared(table, tool("edit", arguments.clone())).has_roles());
        // A tool a harness names after a server and its tool is not the built-in.
        for name in ["mcp__srv__apply_patch", "mcp__srv__edit"] {
            for harness in [
                copilot::tools::TOOLS,
                codex::tools::TOOLS,
                opencode::tools::TOOLS,
            ] {
                assert!(
                    declare(harness, tool(name, arguments.clone()))
                        .operation()
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn no_table_lists_a_tool_twice() {
        let tables: &[(&str, &[ToolSpec])] = &[
            ("claude", claude::tools::TOOLS),
            ("codex", codex::tools::TOOLS),
            ("copilot", copilot::tools::TOOLS),
            ("openclaw", openclaw::tools::TOOLS),
            ("opencode", opencode::tools::TOOLS),
            ("qwen", qwen::tools::TOOLS),
        ];
        for &(source, table) in tables {
            let mut names = std::collections::BTreeSet::new();
            for spec in table {
                assert!(
                    names.insert(spec.name()),
                    "{source} lists {} twice",
                    spec.name()
                );
            }
        }
    }
}
