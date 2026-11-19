# Rule format: Rule v2, a Sigma profile

Telltale rules are written in Rule v2: [Sigma](https://sigmahq.io/docs/basics/rules.html)
2.1 rules marked `taxonomy: telltale`, with a Telltale extension block and a
checked subset of Sigma's detection language. This page is the authoring
reference. The accepted keys, fields, modifiers and values are also published
as data in the generated [rule vocabulary](catalog/rule-vocabulary.json).

Rule v2 replaces Rule v1, which stops loading in 0.8.0; there is no automatic
converter. The [0.8.0 migration guide](migrations/0.8.0.md) maps every Rule v1
key to its Rule v2 spelling. Process-chain rules are a separate, internal pack
and are not written in this format (see
[process-chain detections](process-chain-detections.md)).

Every YAML example on this page is loaded by `cargo test --test catalog`, so an
example that stops loading, or an error it shows that changes, fails the build.
Examples that show only part of a rule, such as a `detection` block, are loaded
inside an otherwise complete rule.

## Files and documents

- A rule file is a YAML file ending in `.yml` or `.yaml`. It holds one or more
  YAML documents separated by `---`, and each document is one rule or one
  chain.
- A document with `taxonomy: telltale` and `detection` is a rule. One with
  `taxonomy: telltale` and `correlation` is a [chain](#chains). Anything else
  is an error that names the problem, including a Sigma document without
  `taxonomy: telltale` and a Sigma filter document.
- Keys are closed: an unknown top-level key, or an unknown key inside
  `logsource`, `telltale` or `correlation`, is an error. This catches typos
  that Sigma tools would keep as custom attributes.
- YAML anchors and aliases work within a document, so a pattern shared by
  several fields is written once. Anchor names must be unique within a
  document: a document that defines the same anchor name twice and uses it
  in an alias is rejected. YAML tags (`!name`) and invisible or control
  characters (including bidirectional formatting characters) are rejected.
- Telltale reads `detection` in document order, because matchers follow the
  order of the selections.

This rule is rejected because `&pattern` is defined twice; give the second
pattern its own name, such as `&wget`:

<!-- rule-example: error: YAML anchor `&pattern` is defined more than once in this document -->
```yaml
title: Download tool in an agent command
id: 1b4e28ba-2fa1-41d2-883f-0016d3cca427
name: example.download.tool
taxonomy: telltale
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        - tool.command|re|i: &pattern '\bcurl\b'
        - tool.arguments|re|i: *pattern
        - tool.url|re|i: &pattern '\bwget\b'
    condition: selection
level: low
telltale:
    category: execution
    score: 10
    explanation: An agent ran a download tool.
```

The same files load from every rule tier: `organization-rules.d`, `rules.d`
and `ui-rules.d`, explicit `--rules` files, rule packages, and documents an
embedding host passes to `Pipeline`. See [Install](install.md#local-rule-policy-and-allowlist-config)
for the directory layout.

## A complete rule

```yaml
title: Force push from an agent shell command
id: 7c9e6679-7425-40de-944b-e07fc1f90ae7
name: example.git.force_push
taxonomy: telltale
status: experimental
description: An agent ran git push with a force flag.
references:
    - https://git-scm.com/docs/git-push
author: Example security team
date: 2026-11-18
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection_command:
        tool.command|re|i: '\bgit\s+push\b.*\s(--force|-f)\b'
    filter_command:
        tool.command|contains: '--force-with-lease'
    condition: selection_command and not filter_command
falsepositives:
    - Rewriting a personal feature branch after a rebase.
level: medium
tags:
    - attack.t1565.001
telltale:
    category: destructive_change
    score: 40
    explanation: A force push can overwrite shared history.
    tags: [git, example]
```

## Document keys

| Key | Rule | Chain | Checks |
| --- | --- | --- | --- |
| `title` | required | required | One line of at most 256 characters. A display label; it may change at any time. |
| `id` | required | required | A lowercase UUIDv4, generated once when the rule is written and never changed. The catalog key. See [Identity and replacement](#identity-and-replacement). |
| `name` | required | required | The dotted rule name: lowercase segments of `a-z`, `0-9` and `_`, at least two segments, at most 96 bytes, starting with a letter. It is the rule ID in events, overrides, policies, chains and tier replacement, and it never changes once released. |
| `taxonomy` | required | required | Exactly `telltale`. |
| `status` | optional | optional | `experimental`, `test`, `stable`, `deprecated` or `unsupported`, in lowercase. See [Status and enablement](#status-and-enablement). |
| `description` | optional | optional | Plain text: no URLs, Markdown links or HTML tags. |
| `references` | optional | optional | A list of distinct `http` or `https` URLs without spaces. |
| `author` | optional | optional | Plain text, like `description`. |
| `license` | optional | optional | Plain text, such as an SPDX identifier. |
| `date` | optional | optional | The date the rule was written, `YYYY-MM-DD`. |
| `modified` | optional | optional | The date of the last change, `YYYY-MM-DD`. With `date` it is the rule's change history. |
| `related` | optional | optional | A list of `{id, type}`: another rule's lowercase UUID and one of `derived`, `obsolete`, `merged`, `renamed`, `similar`. |
| `logsource` | required | not accepted | See [Log source](#log-source). |
| `detection` | required | not accepted | See [Detection](#detection). |
| `correlation` | not accepted | required | See [Chains](#chains). |
| `fields` | optional | not accepted | A list of one-line strings. Catalog metadata only. |
| `scope` | optional | not accepted | Sigma's intended scopes (for example `workstation`), a list of one-line strings. Catalog metadata only; unrelated to the [scope modifiers](#scope-modifiers). |
| `falsepositives` | optional | optional | A list of non-empty strings: known benign workflows that look the same. |
| `level` | required | not accepted | `informational`, `low`, `medium`, `high` or `critical`. Outputs call it the rule's severity. `warning` is an operational event severity, not a rule level. |
| `tags` | optional | optional | Sigma tags. See [Tags](#tags). |
| `telltale` | required | required | The Telltale extension block. See [The `telltale` block](#the-telltale-block). |

`title`, `description`, `references`, `author`, `license`, `date`,
`modified`, `related`, `logsource`, `fields`, `scope`, `falsepositives` and
the Sigma tags other than `atlas.*` are descriptive metadata. They appear in
the [rule catalog](embedding.md) with a separate metadata revision, and
changing them does not change the rule's behaviour fingerprint or its
detections.

## Log source

```yaml
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        tool.name: 'web_fetch'
    condition: selection
```

- `product` must be `ai_agent`.
- `category` must fit the fields the rule reads: `tool_activity` when it reads
  only `tool.*` fields, `message` when it reads only `message.*` fields, and
  `agent_activity` when it reads both. The category does not change what the
  rule matches; it makes visible that a rule reading both kinds of field needs
  sources that record both.
- `definition` is optional plain text.
- `service` is reserved and rejected.

<!-- rule-example: error: this rule needs `tool_activity` -->
```yaml
logsource:
    product: ai_agent
    category: agent_activity
detection:
    selection:
        tool.command|contains: 'terraform destroy'
    condition: selection
```

## Detection

### Fields

| Field | What it reads |
| --- | --- |
| `tool.command` | The command a shell tool call requested, as parsed from the call. |
| `tool.arguments` | The raw arguments text of a tool call. Absent where a source records only structured arguments. |
| `tool.written_path` | The path a file-writing tool call requested. |
| `tool.path` | A file path named by a tool call. What it names depends on the source. |
| `tool.name` | The tool name the source reported. |
| `tool.kind` | What a call does, derived from known built-in tool names: `shell`, `file_read`, `file_write`, `web`, `delegate` or `other`. |
| `tool.url` | The URL-keyed string arguments of a tool call. |
| `tool.result` | The tool result text the source reported. |
| `message.assistant_text` | Assistant message text. |
| `message.user_text` | User message text. |

`tool.command` and `tool.arguments` are read at every tool stage, results
included. A field the source did not record does not match. When a source
cannot show a kind of evidence at all, the rule is reported as not evaluated
for that source rather than as a miss; [agent capability
profiles](agent-capability-profiles.md) list what each source records. Evidence
in outputs keeps the field names `command`, `arguments`, `written_path`,
`file_path`, `tool_name`, `tool_kind`, `url`, `tool_result`,
`assistant_context` and `user_context`, which the vocabulary lists as
`evidence_field`.

### Search identifiers

A search identifier is a key of `detection` other than `condition`:

- a map with exactly one `field|modifiers` key, or
- a list of such maps, which matches when any item matches (Sigma OR).

Identifiers named `filter` or starting with `filter_` are filters; all others
are selections. Names use `A-Z`, `a-z`, `0-9`, `_` and `-`, may not start with
`_`, and may not be a condition keyword. Each field appears in at most one
selection and at most one filter.

```yaml
detection:
    selection:
        - tool.command|contains: 'chmod 777'
        - tool.arguments|contains: 'chmod 777'
    condition: selection
```

A map with several keys means AND across fields in Sigma. Profile level 1 does
not implement it and says so:

<!-- rule-example: error: a map with several keys (an AND across fields) needs profile level 2 -->
```yaml
detection:
    selection:
        tool.name: 'Bash'
        tool.command|contains: 'curl'
    condition: selection
```

### Values

A value is a string or a list of strings. A list matches when any item
matches. Numbers, booleans, `null`, empty strings, empty lists and nested lists
are rejected, so quote values such as `'22'`. Keyword searches (a bare string
or a list of strings under an identifier) are not supported.

| Form | Matches when the field |
| --- | --- |
| `tool.command: V` | equals V as a whole |
| `tool.command\|contains: V` | contains V |
| `tool.command\|startswith: V` | starts with V |
| `tool.command\|endswith: V` | ends with V |
| `tool.command\|re: R` | contains a match of the regular expression R |

- **Case.** Plain, `contains`, `startswith` and `endswith` values match
  case-insensitively; add `|cased` to match case. `|re` is case-sensitive;
  add the flag `|re|i` to ignore case.
- **Wildcards.** In non-`re` values, `*` matches any run of characters and `?`
  one character. Both also match a line break, because agent commands span
  lines. `\*`, `\?` and `\\` are a literal `*`, `?` and `\`; a backslash
  before any other character is itself literal, so `C:\Windows` needs no
  escaping. Use single-quoted YAML strings so YAML does not read backslashes
  first.
- **Regular expressions.** `re` takes Rust [`regex`](https://docs.rs/regex/latest/regex/#syntax)
  syntax: there are no look-around assertions or backreferences, and matching
  time is linear in the input. The search is unanchored; write `^` and `$`
  where needed. `re` must be the first modifier. It may be followed by the flags
  `i` (ignore case), `m` (`^` and `$` match at line breaks) and `s` (`.` matches
  a line break), and it cannot be combined with `contains`, `startswith`,
  `endswith` or `cased`. Inline flags such as `(?-i:...)` work inside the
  pattern.
- **Lists.** Each item of a value list is checked on its own, then joined, so
  an inline flag in one item cannot reach the next.
- **Size.** Each identifier compiles to one pattern per field, flags and list
  joins included, of at most 1,024 bytes.

```yaml
detection:
    selection_url:
        tool.url|startswith:
            - 'http://169.254.169.254/'
            - 'http://metadata.google.internal/'
    selection_command:
        tool.command: 'kubectl delete namespace *'
    selection_path:
        tool.written_path|re|i: '(^|/)\.git/hooks/[^/]+$'
    condition: 1 of selection_*
```

Sigma modifiers that profile level 1 does not implement are errors that name
the modifier: `all`, `exists`, `base64`, `base64offset`, `utf16le`, `utf16be`,
`utf16`, `wide`, `windash`, `cidr`, `fieldref`, `gt`, `gte`, `lt`, `lte`,
`neq`, `expand`, and the time modifiers `minute`, `hour`, `day`, `week`,
`month` and `year`. Any other unknown modifier is an error too.

<!-- rule-example: error: modifier `base64` is not supported at profile level 1 -->
```yaml
detection:
    selection:
        tool.command|base64|contains: 'secret'
    condition: selection
```

### Scope modifiers

`segment`, `exclusion_segment` and `recorded_exclusion` are Telltale extension
modifiers. They apply only to `tool.command`, `tool.arguments` and `tool.url`,
and a key takes at most one. Without one, a selection and its filter read the
whole field (field scope).

| Modifier | What the selection and its filter read |
| --- | --- |
| `segment` | Each shell command segment of the field, split outside quotes on `;`, `\|`, `\|\|`, `&&` and line breaks. The field matches when one segment matches the selection and that same segment does not match the filter. |
| `exclusion_segment` | The selection reads the whole field. A selection match is dropped only when the segment holding it matches the filter. |
| `recorded_exclusion` | Field scope. For `tool.command`, the selection also reads the command with the quotes around its words removed, and the filter is judged on the recorded text alone. |

A filter takes its selection's scope: it may repeat the same scope modifier or
leave it out, and a different one is an error. A scope modifier changes the
rule's behaviour fingerprint. The [detection model](detection-model.md#configurable-rules-and-policies)
describes each scope in full, including the limits of the lexical split.

```yaml
detection:
    selection:
        tool.command|re|segment: '\bwget\b.*https?://'
    filter:
        tool.command|re|segment: '\bwget\b.*--spider'
    condition: selection and not filter
```

<!-- rule-example: error: applies only to tool.command, tool.arguments and tool.url -->
```yaml
detection:
    selection:
        tool.path|contains|segment: '.ssh'
    condition: selection
```

### Filters and conditions

A filter vetoes exactly one selection. It reads the same field as that
selection, the selection has one key (not a list), and the condition writes it
as `<selection> and not <filter>`. This is narrower than Sigma, where
`and not filter` applies to everything before it: a Telltale filter never
removes a match on another field.

Accepted conditions:

| Condition | Meaning |
| --- | --- |
| `<selection>` | The only selection. Only in a rule without filters. |
| `1 of <pattern>` | Any selection whose name matches the pattern; `*` matches any run of characters. Only in a rule without filters. |
| `1 of them` | Any selection. Only in a rule without filters. |
| `<selection> and not <filter>` | The selection, vetoed by its filter. |
| `<term> or <term> ...` | Any term, where each term is `<selection>` or `<selection> and not <filter>`, optionally in parentheses. |

Every identifier is used exactly once. Parentheses nest at most 32 deep.

```yaml
detection:
    selection_command:
        tool.command|contains: 'npm publish'
    filter_command:
        tool.command|contains: '--dry-run'
    selection_arguments:
        tool.arguments|contains: 'npm publish'
    condition: (selection_command and not filter_command) or selection_arguments
```

`rules validate` rejects every other shape with an error that names it,
including:

- `and` between selections, and `all of ...` (these need profile level 2);
- `not <selection>`, `not` before a filter that does not follow its
  selection, and a filter written alone;
- one filter applied to several selections, such as `selection and not 1 of
  filter*` or a filter named in two terms;
- an identifier that the condition never uses, or uses twice;
- a list of conditions, and aggregations (`| count()`).

<!-- rule-example: error: `and` between selections needs profile level 2 -->
```yaml
detection:
    selection_name:
        tool.name: 'Bash'
    selection_command:
        tool.command|contains: 'curl'
    condition: selection_name and selection_command
```

<!-- rule-example: error: cannot be used in a rule with filters -->
```yaml
detection:
    selection_command:
        tool.command|contains: 'rm -rf'
    filter_command:
        tool.command|contains: 'rm -rf ./build'
    condition: 1 of selection_*
```

A filter whose case mode differs from its selection's loads, with a notice,
because such a pair is often a mistake:

<!-- rule-example: notice: filter_case_mismatch -->
```yaml
detection:
    selection:
        tool.command|contains: 'deploy'
    filter:
        tool.command|contains|cased: 'deploy --dry-run'
    condition: selection and not filter
```

## The `telltale` block

The one place for Telltale semantics. For a rule:

| Key | Required | Meaning |
| --- | --- | --- |
| `category` | yes | The observed behaviour, one line, for example `secret_access` (see the [threat taxonomy](threat-taxonomy.md)). Not `logsource.category`. Policies select rules by it. |
| `score` | yes | The risk contribution, 0 to 100. |
| `explanation` | yes | One sentence on what was seen and why it matters. It is the event rationale and part of the behaviour fingerprint. |
| `analytic_intent` | no | `alert` (default), `hunt`, `enrich`, `baseline` or `audit`. |
| `detection_class` | no | `security_detection` (default), `policy_violation`, `threat_hunting`, `compliance_observation`, `operational_health` or `baseline_deviation`. |
| `signal_type` | no | `atomic` (default), `chain`, `correlation` or `baseline_deviation`. |
| `tags` | no | Free-form Telltale labels, each one line. They are the rule's tags in its output. |
| `enabled` | no | `true` (default) or `false`. |

A chain's block has `score`, `explanation`, `analytic_intent`,
`detection_class`, `signal_type` (default `chain`) and `enabled`.

```yaml
telltale:
    category: policy_guardrail
    score: 25
    explanation: An agent edited its own guardrail configuration.
    analytic_intent: audit
    detection_class: policy_violation
    tags: [policy, guardrail]
```

## Tags

`tags` holds Sigma tags: `namespace.name` in lowercase `a-z`, `0-9`, `_` and
`-` (the name may also use `.`), each listed once.

- `atlas.<id>` is a MITRE ATLAS technique. `atlas.aml.t0051` becomes the ATLAS
  tag `atlas:AML.T0051` in detections.
- `attack.tNNNN` and `attack.tNNNN.NNN` are MITRE ATT&CK techniques, listed in
  the catalog's `attack_techniques` as `TNNNN` and `TNNNN.NNN`.
- Other tags, such as `attack.execution` or `cve.2021-44228`, are catalog
  metadata only.

None of these become the rule's own tags; put labels in `telltale.tags`.
ATLAS and ATT&CK mappings are offline documentation; Telltale never fetches
them.

```yaml
tags:
    - attack.exfiltration
    - attack.t1567
    - atlas.aml.t0025
```

## Status and enablement

`experimental`, `test` and `stable` rules load enabled, as does a rule without
`status`. `deprecated` and `unsupported` rules and chains load disabled: they
stay in the catalog and keep their `name` and `id`, but do not run.
`telltale.enabled: false` disables a rule regardless of status. Overrides
(`overrides.d`) and policies (`policies.d`) select rules by `name` and category
without editing the rule; see [Install](install.md#community-rules-and-rule-packages).

## Chains

A chain raises a session's score when rules of given categories, or given
rules, match close together. It uses the shape of a Sigma correlation with the
Telltale type `telltale_chain`, which Sigma tools reject rather than misread.

```yaml
title: Secret file read followed by an upload
id: 1b4e28ba-2fa1-41d2-883f-0016d3cca427
name: example.chain.secret_then_upload
taxonomy: telltale
status: test
correlation:
    type: telltale_chain
    categories: [secret_access, exfiltration]
    within_calls: 3
    order: ordered
falsepositives:
    - An authorized backup that reads a key file and uploads an archive.
telltale:
    score: 35
    explanation: A secret read followed by an upload suggests exfiltration.
```

- `type` is `telltale_chain`.
- Exactly one of `categories` (rule categories) and `rules` (rule names)
  lists the steps; it may not be empty.
- `within_calls` (0 to 10) is how many tool calls apart the steps may be: 0
  means one call, 1 the next call. A call and its result count once; messages
  add no distance. Without `within_calls` the steps may match anywhere in the
  session.
- `order` is `ordered` (the default: steps in the order listed) or `any`. It
  needs `within_calls`.

A chain has no `logsource`, `detection` or `level`, and its `telltale` block
has no `category` or `tags`. Session scoring and action findings apply the same
link.

## Rule packages

A rule package ships namespaced rules and chains as one YAML file in
`rule-packages.d`; see [Install](install.md#community-rules-and-rule-packages)
for installation and trust. The file is a YAML stream: the first document is
the package header, and every following `---` document is one rule or chain,
written exactly as in a rule file. A package can therefore be built by writing
the header and appending rule files.

```yaml
format: telltale-rule-package/v2
id: example.agent-rules
title: Example agent rules
version: '1.0.0'
publisher: Example security team
license: Apache-2.0
rule_namespace: example
source: https://example.invalid/agent-rules
---
title: Package manager configuration written
id: f47ac10b-58cc-4372-a567-0e02b2c3d479
name: example.persistence.npmrc_write
taxonomy: telltale
status: test
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        tool.written_path|endswith: '/.npmrc'
    condition: selection
level: low
telltale:
    category: persistence
    score: 20
    explanation: An agent wrote a package manager configuration file.
---
title: Shell profile written
id: a3bb189e-8bf9-4888-9912-ace4e6543002
name: example.persistence.shell_profile_write
taxonomy: telltale
status: test
logsource:
    product: ai_agent
    category: tool_activity
detection:
    selection:
        tool.written_path|endswith:
            - '/.bashrc'
            - '/.zshrc'
    condition: selection
level: medium
telltale:
    category: persistence
    score: 30
    explanation: An agent wrote a shell startup file.
```

- `format` is `telltale-rule-package/v2`. Telltale 0.7 does not read it.
- `id` (dot-separated lowercase segments, at most 64 characters), `title`,
  `version` (at most 64 characters of `A-Z`, `a-z`, `0-9`, `.`, `+`, `-`, `_`),
  `publisher` and `license` are required; `source` and `revision` are optional
  labels. Labels are one line of at most 256 characters. The header has no
  other keys; in particular there is no `documents` list.
- `rule_namespace` (lowercase, at most 32 characters) may not be a core rule
  namespace or `telltale`/`procchain`. Every `name` starts with
  `<rule_namespace>.`.
- At least one rule or chain document follows the header. The documents are
  sorted by `name`, each name once, and each `id` is used once. Errors number
  the documents in the file, the header being document 1.
- Each document is read on its own, like a document of a rule file, so YAML
  anchors never reach from one rule into another.
- A package file is at most 4 MiB.

Packages only add definitions: a package never replaces a core rule or another
package's rule.

## Identity and replacement

A rule has two identities:

- `name`, the dotted rule name, is what operators and outputs use: Event 3.0
  `rule_ids`, overrides, policies, chain `rules`, `telltale rules show <name>`
  and replacement across tiers.
- `id`, a UUIDv4, is the stable catalog key. Generate it once with any UUID
  tool when the rule is first written, and keep it through every later edit,
  including a change of `title`. Write a new rule with a new `id` and a new
  `name` when a change is really a different detection, and link them with
  `related`.

Rule tiers resolve in order: bundled core rules, rule packages,
`organization-rules.d`, `rules.d`, `ui-rules.d`, then explicit `--rules` files.
A rule in a higher managed tier replaces the rule with the same `name` in
place, and:

- the replacement must carry the same `id` as the rule it replaces. To
  replace a bundled rule, start from `telltale rules export-default`, which
  writes each bundled rule with its `id`;
- an `id` used under two different names in the effective rule set is an
  error;
- the same `name` twice within one tier is an error, and so is a rule
  replacing a chain or a chain a rule;
- packages and `--rules` files only add: a `name` they share with another tier
  is an error.

A replacement that changes a bundled rule's detection loses that rule's
built-in action profile, the precision that native action findings apply to
some bundled rules; `rules validate` reports it as the notice
`native_profile_not_applied`.

## Validating rules

```sh
telltale rules validate --no-local-config --rules my-rules.yml
telltale rules show example.git.force_push --no-local-config --rules my-rules.yml
telltale rules test --no-local-config --rules my-rules.yml fixture.jsonl
```

`rules validate` loads the bundled rules (unless `--no-default-rules`), the
managed tiers and the files given, and prints a JSON summary. A rule that does
not load stops the command with an error naming the file, the document number,
the rule name and the problem, for example:

```text
invalid rule document '<source>': rule document 1: rule 'example.git.force_push': condition `selection_name and selection_command`: `and` between selections needs profile level 2
```

Findings that do not stop a rule from loading are listed under `notices`,
each with `rule_id`, `kind` and `message`:

| Kind | Meaning |
| --- | --- |
| `filter_case_mismatch` | A filter's case mode differs from its selection's. |
| `native_profile_not_applied` | A rule replaces a bundled rule by name with different matchers, so the bundled action profile does not apply. |

`telltale rules show <name>` prints one rule or chain: its metadata, compiled
field targets and scopes, and notices. `telltale rules catalog` prints the
[rule catalog v2](../schemas/rule-catalog-v2.schema.json) of the resolved
rules. The [detection content standard](detection-content-standard.md) sets
the quality bar for bundled rules.

## Differences from Sigma

| Sigma 2.1 | Telltale Rule v2 | Why |
| --- | --- | --- |
| `id`, `name`, `level` and `taxonomy` are optional. | Required; `taxonomy` is `telltale`, `id` a UUIDv4, `name` a dotted rule name. | Rules need a stable catalog key and the rule name operators already use. |
| Unknown top-level keys are kept as custom attributes. | Rejected; Telltale semantics live in the `telltale` block. | A typo must not silently drop a setting. |
| `status` and `level` are case-insensitive. | Lowercase only. | One spelling per value. |
| A map ANDs its keys; `all`, `all of` and `and` between selections combine fields. | Not supported at level 1; each selection reads one field. | Planned for a later profile level. An accepted rule never changes meaning when more is accepted. |
| `and not filter` applies to the whole expression before it. | A filter vetoes only its own selection's field. | Matches how Telltale evaluates exclusions per field. |
| Keyword searches, numbers, booleans and `null` values. | Not supported; values are strings. | Agent evidence is text in named fields. |
| Whether wildcards cross line breaks is left to each backend. | `*` and `?` match line breaks. | Agent commands and messages span lines. |
| `re` follows the backend's regex dialect. | Rust `regex` syntax, unanchored, at most 1,024 bytes per compiled pattern. | Linear-time matching on untrusted text. |
| Encoding, numeric, network, time and placeholder modifiers. | Rejected by name. | No Telltale field needs them yet. |
| No scope modifiers. | `segment`, `exclusion_segment`, `recorded_exclusion`. | Command lines hold several commands. Sigma tools reject the unknown modifiers instead of evaluating such a rule with whole-field semantics. |
| `logsource` names any product and category. | `product: ai_agent`; the category must fit the fields read; `service` is reserved. | Makes rules that need both tool and message evidence visible. |
| Correlation types `event_count`, `value_count`, `temporal` and others. | Only `telltale_chain`, by categories or rule names and tool-call distance. | Telltale chains count tool calls in one session, not events in a time window. |
| Filter documents. | Not supported. | Use overrides, policies or a replacement rule. |
| `deprecated` and `unsupported` are informational. | They load disabled. | A retired rule keeps its identity in the catalog without running. |

Telltale does not test Rule v2 against Sigma tools. Expect rules that use
scope modifiers, and chains, to fail there, because those tools reject unknown
modifiers and correlation types. Absent fields do not match, and a rule a
source cannot evaluate is reported as not evaluated.
