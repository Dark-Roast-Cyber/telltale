use super::same_instant;

fn own_state_document(paths: &[std::path::PathBuf]) -> (String, super::GeneratedCoverage) {
    let mut coverage = super::GeneratedCoverage::default();
    let family = super::own_state_family(paths, &mut coverage);
    let document = super::family_document(&family, &mut coverage).unwrap_or_default();
    (document, coverage)
}

#[test]
fn generated_rules_dedupe_and_never_drop_a_path_for_size() {
    use std::path::PathBuf;
    let (doc, coverage) = own_state_document(&[
        PathBuf::from("/srv/tth/state"),
        PathBuf::from("/srv/tth/state/telemetry.jsonl"),
        PathBuf::from("/var/log/tth/telemetry.jsonl"),
        PathBuf::from("/etc/tth/config.toml"),
    ]);
    let sep = r"[\\/]+";
    assert!(
            doc.contains(&format!(
                "{sep}srv{sep}tth{sep}state|{sep}var{sep}log{sep}tth{sep}telemetry\\.jsonl|{sep}etc{sep}tth{sep}config\\.toml"
            )),
            "{doc}"
        );
    // The nested telemetry file is covered by its state dir; the other is
    // kept. One copy in each of the write, command, reverse, redirect and
    // reference rules.
    assert_eq!(doc.matches("telemetry\\.jsonl").count(), 5, "{doc}");
    assert!(!doc.contains("state[\\\\/]+telemetry"), "{doc}");
    assert_eq!((coverage.paths, coverage.rules), (3, 5));

    // Past the cap the same rule IDs continue with a number.
    let many: Vec<PathBuf> = (0..12)
        .map(|i| PathBuf::from(format!("/srv/{}/rules-{i}.yaml", "x".repeat(150))))
        .collect();
    let (doc, coverage) = own_state_document(&many);
    assert!(coverage.reduced.is_empty());
    assert!(doc.contains("tth.tamper.own_state_command_2"), "{doc}");
    for i in 0..12 {
        assert_eq!(doc.matches(&format!("rules\\-{i}\\.yaml")).count(), 5);
    }

    // One path too long for any rule keeps its last bytes and is reported.
    let long = format!("/{}/state.json", "y".repeat(1200));
    let (doc, coverage) = own_state_document(&[PathBuf::from(&long)]);
    assert_eq!(coverage.reduced, [long]);
    assert_eq!(doc.matches("state\\.json").count(), 5, "{doc}");
    for (_, pattern) in doc.lines().filter_map(|line| line.split_once(": '")) {
        let pattern = pattern.strip_suffix('\'').unwrap().replace("''", "'");
        assert!(pattern.len() <= 1024, "{pattern}");
    }
}

#[cfg(unix)]
#[test]
fn a_path_that_is_not_utf8_is_reported_not_dropped_silently() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::ffi::OsString::from_vec(b"/srv/\xff/state".to_vec());
    let (doc, coverage) = own_state_document(&[path.into()]);
    assert!(doc.is_empty());
    assert_eq!(coverage.paths, 1);
    assert_eq!(coverage.unrepresentable.len(), 1);
}

/// Every placeholder in a template names a fragment, sits in a single-quoted value
/// (the quoting `expand_fragments` writes), and none is left once expanded. Every
/// fragment is named somewhere.
#[test]
fn every_rule_template_placeholder_is_a_known_fragment() {
    let placeholder = regex::Regex::new(r"\{\{([A-Z][A-Z0-9_]*)\}\}").unwrap();
    let quoted = regex::Regex::new(r"^\s*(?:- )?[a-z_.|]+: '.*'$").unwrap();
    let mut named = std::collections::BTreeSet::new();
    for (name, template) in super::host_rule_templates()
        .into_iter()
        .chain([super::GRANT_RULE_TEMPLATE])
    {
        for line in template.lines() {
            for found in placeholder.captures_iter(line) {
                let fragment = found.get(1).unwrap().as_str();
                assert!(
                    super::rule_fragments()
                        .iter()
                        .any(|(known, _)| *known == fragment),
                    "{name}: {fragment}"
                );
                assert!(
                    quoted.is_match(line),
                    "{name}: {fragment} outside a quoted value"
                );
                named.insert(fragment);
            }
        }
    }
    for (name, document) in super::host_rule_documents()
        .iter()
        .chain([super::grant_protection_document()])
    {
        assert!(!placeholder.is_match(document), "{name}");
    }
    let unnamed: Vec<&str> = super::rule_fragments()
        .iter()
        .map(|(fragment, _)| *fragment)
        .filter(|fragment| !named.contains(fragment))
        .collect();
    assert!(unnamed.is_empty(), "{unnamed:?}");
}

#[test]
fn harness_launcher_and_package_fragments_cover_all_harnesses_and_clients() {
    let launchers = crate::hooks::harness::all_harness_launchers();
    for harness in crate::hooks::harness::Harness::ALL {
        for launcher in harness.adapter().launchers {
            assert!(
                launchers.contains(launcher),
                "missing launcher {launcher} for {}",
                harness.name()
            );
        }
        let packages = crate::hooks::harness::all_harness_packages();
        for package in harness.adapter().packages {
            assert!(
                packages.contains(package),
                "missing package {package} for {}",
                harness.name()
            );
        }
    }
    for client in crate::ClientId::ALL {
        assert!(
            launchers.contains(&client.as_str()),
            "ClientId::{} is missing from hooks self-protection launchers",
            client.as_str()
        );
    }
    for (name, template) in super::host_rule_templates() {
        assert!(
            !template.contains("claude|codex|copilot|opencode"),
            "{name} still hardcodes a hand-written harness launcher alternation"
        );
        assert!(
            !template.contains("openai/codex|github/copilot"),
            "{name} still hardcodes a hand-written harness package alternation"
        );
        assert!(
            !template.contains("claude-code|copilot-cli"),
            "{name} still hardcodes a hand-written hooks subcommand alternation"
        );
    }
}

/// An exclusion lets commands through its rule, so none is written out by hand: each
/// is built from the shared texts, and a change to one reaches every rule that uses it.
#[test]
fn every_exclusion_is_built_from_shared_text() {
    let mut filters = 0;
    for (name, template) in super::host_rule_templates() {
        let mut lines = template.lines();
        while let Some(line) = lines.next() {
            if line.trim().starts_with("filter_") {
                filters += 1;
                let value = lines.next().unwrap_or_default();
                assert!(value.contains("{{"), "{name}: {value}");
            }
        }
    }
    assert!(filters > 0);
}

/// Every generated family, with written-path and command rules, the 90- and
/// 60-point shapes, reverse, reference and fail-safe rules and numbered
/// chunks, loads and compiles without notices, case-sensitive (Unix) and
/// case-insensitive (Windows).
#[test]
fn generated_rule_documents_load_and_compile_in_every_shape() {
    use std::path::PathBuf;
    use telltale_rules::load_rule_set_from_documents;
    let mut coverage = super::GeneratedCoverage::default();
    let many: Vec<PathBuf> = (0..12)
        .map(|i| PathBuf::from(format!("/srv/{}/rules-{i}.yaml", "x".repeat(150))))
        .collect();
    let homes: Vec<crate::hooks::config::HarnessHome> = crate::hooks::harness::Harness::ALL
        .iter()
        .filter_map(|harness| harness.adapter().home)
        .map(|home| crate::hooks::config::HarnessHome {
            variable: home.variable,
            hook_files: home.hook_files,
            path: PathBuf::from(format!("/srv/synthetic-home/{}", home.variable)),
        })
        .collect();
    assert!(!homes.is_empty());
    let [home_files, home_dirs] = super::harness_home_families(&homes, &mut coverage);
    let families = [
        super::own_state_family(
            &[
                PathBuf::from("/srv/tth/state"),
                PathBuf::from("/srv/tth/it's here/telemetry.jsonl"),
            ],
            &mut coverage,
        ),
        super::own_state_family(&many, &mut coverage),
        home_files,
        home_dirs,
        super::installed_binary_family(
            Some(std::path::Path::new("/srv/synthetic/bin/telltale")),
            &mut coverage,
        ),
    ];
    let mut shapes = std::collections::BTreeSet::new();
    for family in &families {
        for case_insensitive in [false, true] {
            let v2 = super::family_document_with_case(
                family,
                &mut super::GeneratedCoverage::default(),
                case_insensitive,
            )
            .unwrap();
            let v2_rules = load_rule_set_from_documents(&[&v2], None).unwrap();
            assert!(v2_rules.notices().is_empty());
            let v2 = v2_rules.compatibility_export();
            assert!(!v2.rules().is_empty(), "{}", family.prefix);
            for rule in v2.rules() {
                shapes.insert((
                    rule.matchers[0].target.clone(),
                    rule.score,
                    rule.matchers[0].regex.starts_with("(?i:"),
                ));
            }
            telltale_detect::v2::compile_rule_v1(&v2).unwrap();
        }
    }
    // Both selections, both scores and both case modes were covered.
    for target in ["command", "written_path"] {
        for case_insensitive in [false, true] {
            assert!(shapes.contains(&(target.to_owned(), 90, case_insensitive)));
        }
    }
    assert!(shapes.contains(&("command".to_owned(), 60, false)));
    let names = families
        .iter()
        .flat_map(super::family_rules)
        .map(|rule| rule.id)
        .collect::<Vec<_>>();
    assert!(names.iter().any(|name| name.ends_with("_2")));
    assert!(names.iter().any(|name| name.contains("failsafe")));
    assert!(names.iter().any(|name| name.contains("reverse")));
}

#[test]
fn a_generated_rule_uuid_is_a_v4_shaped_uuid_derived_from_its_name() {
    let first = super::generated_rule_uuid("tth.tamper.own_state_write");
    assert_eq!(
        first,
        super::generated_rule_uuid("tth.tamper.own_state_write")
    );
    assert_ne!(
        first,
        super::generated_rule_uuid("tth.tamper.own_state_write_2")
    );
    let bytes = first.as_bytes();
    assert_eq!(bytes.len(), 36);
    assert_eq!((bytes[14], bytes[8], bytes[13]), (b'4', b'-', b'-'));
    assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
}

#[test]
fn expansion_quotes_a_fragment_and_keeps_other_braces() {
    let expanded = super::expand_fragments("a: '{{SEGMENT}}' # {{}} {{NOT_A_FRAGMENT}}");
    assert_eq!(
        expanded,
        format!(
            "a: '{}' # {{{{}}}} {{{{NOT_A_FRAGMENT}}}}",
            super::SEGMENT.replace('\'', "''")
        )
    );
}

/// Every writer word of the deny rules is a writer word of the fail-safe rules, so what a
/// deny rule stops in one spelling at least asks in the rest. A list is any alternation
/// that holds a word every list has; a new word in one is checked without being named here.
#[test]
fn the_fail_safe_writers_cover_every_deny_writer() {
    // What the rules on `main` had before there were fail-safe rules, in case one is cut.
    const BEFORE_FAIL_SAFE: &[&str] = &[
        "Add-Content",
        "Clear-Content",
        "Copy-Item",
        "Move-Item",
        "New-Item",
        "Out-File",
        "Remove-Item",
        "Rename-Item",
        "Set-Content",
        "ac",
        "copy",
        "cp",
        "cpi",
        "del",
        "erase",
        "ln",
        "mi",
        "move",
        "mv",
        "rd",
        "ren",
        "rename",
        "ri",
        "rm",
        "rmdir",
        "sc",
        "sed",
        "shred",
        "tee",
        "truncate",
        "unlink",
    ];
    let list = regex::Regex::new(r"\(\?:((?:[A-Za-z_][-A-Za-z_0-9]*\|)+[A-Za-z_][-A-Za-z_0-9]*)\)")
        .unwrap();
    let mut words: std::collections::BTreeSet<String> =
        BEFORE_FAIL_SAFE.iter().map(ToString::to_string).collect();
    // Not in a list: `git -C <home> clean`, with its flags between the words.
    words.insert("clean".to_owned());
    for (_, document) in super::host_rule_documents() {
        let flat = document
            .replace(
                "(?:Remove|Move|Copy|Rename|New)-Item",
                "Remove-Item|Move-Item|Copy-Item|Rename-Item|New-Item",
            )
            .replace(
                "(?:Set|Add|Clear)-Content",
                "Set-Content|Add-Content|Clear-Content",
            );
        for found in list.captures_iter(&flat) {
            let found: Vec<&str> = found[1].split('|').collect();
            if ["rm", "del", "rmtree"]
                .iter()
                .any(|word| found.contains(word))
            {
                words.extend(found.iter().map(ToString::to_string));
            }
        }
    }
    assert!(words.len() > BEFORE_FAIL_SAFE.len() + 5, "{words:?}");
    let writer = regex::Regex::new(super::WRITER_ANYWHERE).unwrap();
    assert!(!writer.is_match("wipe -i x"));
    for word in &words {
        for spelling in [format!("{word} -i x"), format!("{word}.exe -i x")] {
            assert!(writer.is_match(&spelling), "{spelling}");
        }
    }
}

/// A character YAML refuses or folds reaches the regex by its code point, and
/// the pattern still matches the path. So does every other character outside
/// printable ASCII, which costs a non-ASCII path room: `\x{e9}` is six bytes where
/// `é` is two, and past the cap the path moves to a numbered rule or keeps its tail.
#[test]
fn a_path_character_yaml_cannot_carry_is_written_by_its_code_point() {
    use std::path::PathBuf;
    let patterns = |doc: &str| -> Vec<String> {
        doc.lines()
            .filter_map(|line| line.split_once(": '"))
            .map(|(_, pattern)| pattern.strip_suffix('\'').unwrap().replace("''", "'"))
            .collect()
    };
    let rule = |doc: &str, rule: &str| -> String {
        let id = format!("name: tth.tamper.{rule}");
        let rest: Vec<&str> = doc
            .lines()
            .skip_while(|line| line.trim_start() != id)
            .collect();
        patterns(&rest.join("\n")).swap_remove(0)
    };
    for (c, written) in [
        ('\x01', r"\x{1}"),
        ('\x1b', r"\x{1b}"),
        ('\x7f', r"\x{7f}"),
        ('\u{9f}', r"\x{9f}"),
        ('\u{fffe}', r"\x{fffe}"),
        ('\t', r"\x{9}"),
        ('\n', r"\x{a}"),
        ('\r', r"\x{d}"),
        ('\u{85}', r"\x{85}"),
        ('\u{2028}', r"\x{2028}"),
        ('\u{2029}', r"\x{2029}"),
        ('\u{feff}', r"\x{feff}"),
    ] {
        let path = format!("/srv/a{c}b");
        let (doc, _) = own_state_document(&[PathBuf::from(&path)]);
        // Every rule the path went into, not one of them.
        let all = patterns(&doc);
        let carrying: Vec<&String> = all
            .iter()
            .filter(|pattern| pattern.contains(r"[\\/]+srv[\\/]+a"))
            .collect();
        assert_eq!(carrying.len(), 5, "{c:?}: {doc}");
        for pattern in carrying {
            assert!(pattern.contains(&format!("a{written}b")), "{c:?}: {doc}");
            assert!(!pattern.contains(c), "{c:?}: {doc}");
        }
        let written = regex::Regex::new(&rule(&doc, "own_state_write")).unwrap();
        assert!(written.is_match(&path), "{c:?}");
        let command = regex::Regex::new(&rule(&doc, "own_state_command")).unwrap();
        assert!(command.is_match(&format!("rm -rf {path}")), "{c:?}");
    }
    // Everything else outside printable ASCII goes the same way, and still means that path.
    let path = "/home/synthetic/josé/日本語";
    let (doc, _) = own_state_document(&[PathBuf::from(path)]);
    assert!(
        doc.contains(r"jos\x{e9}[\\/]+\x{65e5}\x{672c}\x{8a9e}"),
        "{doc}"
    );
    let written = regex::Regex::new(&rule(&doc, "own_state_write")).unwrap();
    assert!(written.is_match(path), "{doc}");
}

/// A rules file that is not listed would silently never load. The
/// self-protection documents and the test signatures are the two lists.
#[test]
fn every_bundled_rules_file_is_a_listed_document() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/hooks/rules");
    let mut files: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read_to_string(&path).unwrap())
        })
        .collect();
    files.sort();
    let mut listed: Vec<(String, String)> = super::host_rule_templates()
        .into_iter()
        .chain([super::test_signature_document(), super::GRANT_RULE_TEMPLATE])
        .map(|(name, content)| (name.to_owned(), content.to_owned()))
        .collect();
    listed.sort();
    assert_eq!(listed, files);
}

/// User content is kept out of the host rules by namespace, so no host or
/// generated rule may be outside it.
#[test]
fn every_host_and_generated_rule_is_in_the_reserved_namespace() {
    let mut coverage = super::GeneratedCoverage::default();
    let generated =
        super::generated_documents(&[std::path::PathBuf::from("/srv/tth/state")], &mut coverage);
    assert!(!generated.is_empty());
    let host = super::host_rule_documents()
        .iter()
        .chain([super::grant_protection_document()])
        .map(|(_, document)| document);
    for document in host.chain(&generated) {
        let set = telltale_rules::LoadedRules::parse(document).unwrap();
        assert!(!set.is_empty());
        for rule in set.definitions() {
            assert!(
                rule.id()
                    .starts_with(crate::hooks::config::HOST_RULE_ID_PREFIX),
                "{}",
                rule.id()
            );
        }
    }
}

#[test]
fn source_times_compare_as_instants() {
    assert!(same_instant(
        "2026-11-04T00:01:01.000Z",
        "2026-11-04T00:01:01Z"
    ));
    assert!(same_instant(
        "2026-11-04T00:01:01.000Z",
        "2026-11-04T01:01:01.000+01:00"
    ));
    assert!(!same_instant(
        "2026-11-04T00:01:01.001Z",
        "2026-11-04T00:01:01.000Z"
    ));
    assert!(same_instant("not a time", "not a time"));
}

#[cfg(test)]
mod recovery;
