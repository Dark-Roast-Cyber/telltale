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
mod tests;
