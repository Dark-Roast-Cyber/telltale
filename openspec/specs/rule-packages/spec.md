# rule-packages Specification

## Purpose
Defines identified, versioned, namespaced Rule v1 content that Telltale adds to its bundled core rules: the embedded community package, operator-installed packages, and packages supplied through the embedding facade. One rule engine evaluates all of them.

## Requirements
### Requirement: A package is one validated, namespaced document

A rule package SHALL be one `telltale-rule-package/v1` YAML document with `format`, `id`, `version`, `publisher`, `license`, `rule_namespace`, optional informational `source` and `revision`, and one or more Rule v1 `documents`. Telltale SHALL reject unknown header fields, malformed identities, packages larger than 4 MiB, control or invisible formatting characters anywhere in the text, definitions outside `<rule_namespace>.`, duplicate definition IDs, and packages without definitions. A namespace SHALL NOT reuse the first ID segment of a bundled core rule or modifier, `procchain`, or `telltale`.

#### Scenario: Definition outside the namespace

- **WHEN** a package with `rule_namespace: acme` defines `other.marker`
- **THEN** loading fails before any scan and names the namespace violation

#### Scenario: Hidden formatting character

- **WHEN** a package line contains a bidirectional override such as U+202E
- **THEN** loading fails and reports the line and code point without echoing the content

#### Scenario: YAML-escaped hidden character

- **WHEN** a YAML escape in a package string decodes to a forbidden control or formatting character
- **THEN** loading fails and reports the code point without echoing the decoded content
- **AND** ordinary multiline rule text and literal regex escape sequences remain valid

### Requirement: Packages only add definitions

Package definitions SHALL load at a package tier after bundled core rules and before `organization-rules.d`, `rules.d`, and `ui-rules.d`. A package definition SHALL NOT replace a bundled core definition or another package's definition; a repeated ID fails with both sources. Higher operator tiers MAY replace a package definition by ID, and explicit `--rules` files remain additive-only. Two effective packages SHALL NOT share an ID or a namespace.

#### Scenario: Operator tunes a package rule

- **WHEN** an `organization-rules.d` file defines a rule with a package rule's ID
- **THEN** the organization definition wins and provenance lists the package source as replaced

#### Scenario: Two packages claim one namespace

- **WHEN** two installed packages declare the same `rule_namespace`
- **THEN** rule resolution fails and names both packages

### Requirement: Community rules are on by default with an explicit opt-out

Telltale SHALL embed the community package (`telltale.community`, namespace `tdx`) and load it with the bundled core rules by default in the CLI and the embedding facade. `--no-community-rules`, `TELLTALE_COMMUNITY_RULES=0` (CLI only), and `PipelineBuilder::without_community_rules` SHALL remove community content from every origin, leaving core rules. `--no-default-rules` and `without_bundled_defaults` SHALL omit both the core rules and the embedded community snapshot while installed or supplied packages still load.

#### Scenario: Core-only operation

- **WHEN** an operator runs a scan with `--no-community-rules`
- **THEN** the effective rule set equals the bundled core rules plus local configuration, and `effective_configuration.rules.community` is `disabled`

### Requirement: An installed community package replaces the embedded snapshot

A package in `<config-root>/rule-packages.d/*.yaml|yml`, or supplied through `PipelineBuilder::rule_package`, whose ID is `telltale.community` SHALL replace the embedded community snapshot as a whole. Provenance SHALL report the active package's ID, version, content SHA-256, origin, and the replaced embedded version.

#### Scenario: Newer community release without a Telltale release

- **WHEN** an operator installs a newer `telltale.community` package file
- **THEN** its definitions replace the embedded community definitions and `rules validate` reports `origin: installed` with `replaced_embedded_version`

### Requirement: Package provenance is reportable without paths

`rules validate`, `config validate`, and the scan effective configuration SHALL list effective packages with ID, version, content SHA-256, and origin (`embedded` or `installed`). Package file locations SHALL receive the same hashing and path sanitization as other managed rule paths. The embedding facade SHALL expose the same identity through `Pipeline::rule_packages`, and the bundled rule catalog SHALL attribute community entries to their package ID.

#### Scenario: Inventory reporting

- **WHEN** an embedding host builds the default pipeline
- **THEN** `Pipeline::rule_packages` returns the embedded community package's ID, version, and content SHA-256

### Requirement: Packages are local content, not a remote feed

Telltale SHALL NOT fetch rule packages over a network or resolve package dependencies. Packages arrive as embedded content, operator-installed files, or caller-supplied text; acquisition, signature verification, and distribution belong to the operator, release tooling, or an embedding host.

#### Scenario: Invalid installed package

- **WHEN** an installed package fails validation
- **THEN** rule resolution fails closed before scan outputs or state activate, as for other invalid managed configuration
