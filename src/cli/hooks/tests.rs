use std::path::{Path, PathBuf};

use super::{
    STATE_DIR, USER_CONFIG_DIR, command_roots, config_dirs, declares_enforce, hook_flags,
    load_config, pin_command, split_pin,
};

#[test]
fn each_pin_is_one_value_and_passes_over_other_directory_values() {
    for switch in [USER_CONFIG_DIR, STATE_DIR] {
        assert_eq!(
            split_pin(&["--json-reply", switch, "/a b"], switch),
            Some((vec!["--json-reply"], Some(PathBuf::from("/a b")))),
            "{switch}"
        );
        assert_eq!(
            split_pin(&["--config-dir", switch], switch),
            Some((vec!["--config-dir", switch], None)),
            "{switch}"
        );
        let joined = format!("{switch}=/a");
        assert_eq!(
            split_pin(&[joined.as_str()], switch),
            Some((Vec::new(), Some(PathBuf::from("/a")))),
            "{switch}"
        );
        let (empty, glued) = (format!("{switch}="), format!("{switch}x"));
        for refused in [
            &[switch][..],
            &[empty.as_str()],
            &[switch, ""],
            &[switch, "/a", switch, "/b"],
            &[glued.as_str()],
        ] {
            assert_eq!(split_pin(refused, switch), None, "{refused:?}");
        }
    }
    // Either pin's value may be spelled like the other switch.
    assert_eq!(
        split_pin(&[STATE_DIR, USER_CONFIG_DIR], USER_CONFIG_DIR),
        Some((vec![STATE_DIR, USER_CONFIG_DIR], None))
    );
    assert_eq!(
        split_pin(&[USER_CONFIG_DIR, STATE_DIR], STATE_DIR),
        Some((vec![USER_CONFIG_DIR, STATE_DIR], None))
    );
}

/// POSIX sh reads `'\''` as a quote inside single quotes; PowerShell and Git
/// Bash both read single quotes literally, and have no common escape for
/// one, so a Windows path holding a quote is not pinned.
#[test]
fn the_pin_is_quoted_for_the_harness_shell() {
    for switch in [USER_CONFIG_DIR, STATE_DIR] {
        assert_eq!(
            pin_command(
                "t hooks claude-code hook",
                switch,
                Path::new("/h/it's a $dir"),
                false
            ),
            Some(format!(
                r"t hooks claude-code hook {switch} '/h/it'\''s a $dir'"
            ))
        );
        assert_eq!(
            pin_command(
                "t hooks copilot-cli hook",
                switch,
                Path::new(r"C:\Users\a b\AppData\Local\telltale"),
                true
            ),
            Some(format!(
                r"t hooks copilot-cli hook {switch} 'C:\Users\a b\AppData\Local\telltale'"
            ))
        );
    }
    for quoted in [r"C:\Users\o'b\.config", "C:\\Users\\o\u{2019}b\\.config"] {
        for switch in [USER_CONFIG_DIR, STATE_DIR] {
            let pinned = pin_command("t", switch, Path::new(quoted), true);
            assert_eq!(pinned, None, "{quoted}");
        }
    }
}

/// Only what every harness shell reads alike names a command's roots.
#[test]
fn a_command_names_its_roots_only_when_every_shell_reads_them_alike() {
    assert_eq!(
        command_roots("'/opt/t b' hooks x hook --config-dir '/a b' --config-dir=/c"),
        Some((vec![PathBuf::from("/a b"), PathBuf::from("/c")], None))
    );
    assert_eq!(
        command_roots(r"'C:\t.exe' hooks x hook --user-config-dir 'C:\u r'"),
        Some((Vec::new(), Some(PathBuf::from(r"C:\u r"))))
    );
    for unreadable in [
        "t hook --config-dir \"/a b\"",
        r"t hook --config-dir /a\ b",
        "t hook --config-dir $HOME/c",
        "t hook --config-dir '/it'\\''s'",
        "t hook --config-dir 'a''b'",
        "t hook --config-dir '/a",
        "t hook --config-dir /a; rm x",
        "t hook --config-dir",
        "t hook --config-dir /a --user-config-dir /b",
    ] {
        assert_eq!(command_roots(unreadable), None, "{unreadable}");
    }
}

#[test]
fn hook_switches_do_not_consume_a_config_directory_named_like_a_switch() {
    assert_eq!(
        hook_flags(&["--json-reply", "--config-dir", "--detect-only"]),
        Some((vec![PathBuf::from("--detect-only")], true, false, false))
    );
    assert_eq!(
        hook_flags(&["--detect-only", "--config-dir=root", "--json-reply"]),
        Some((vec![PathBuf::from("root")], true, true, false))
    );
    assert_eq!(hook_flags(&["--json-reply", "--config-dir"]), None);
    assert_eq!(
        hook_flags(&["--expect-enforce"]),
        Some((Vec::new(), false, false, true))
    );
    assert_eq!(hook_flags(&["--expect-enforce", "--detect-only"]), None);
}

#[test]
fn config_dirs_reads_repeated_flags_and_refuses_anything_else() {
    assert_eq!(config_dirs(&[]), Some(Vec::new()));
    assert_eq!(
        config_dirs(&["--config-dir", "a", "--config-dir=b"]),
        Some(vec![PathBuf::from("a"), PathBuf::from("b")])
    );
    for refused in [
        &["--config-dir"][..],
        &["--config-dir="],
        &["--config-dir", ""],
        &["--config-dirs=a"],
        &["--bogus"],
        &["--config-dir", "a", "extra"],
    ] {
        assert_eq!(config_dirs(refused), None, "{refused:?}");
    }
}

#[test]
fn only_hooks_mode_enforce_declares_enforcement() {
    for enforcing in [
        "version: 1\nhooks:\n  mode: enforce\n",
        "hooks:\n  mode: \"enforce\"\n  bogus: 1\n",
        // Not YAML, so read as `key: value` pairs: any spelling of the
        // pair counts, wherever it sits (fail closed).
        "hooks:\n  on_error: deny\n  mode: enforce\n  thresholds: [\n",
        "hooks:\n    mode: 'enforce'  # on\n  : : [\n",
        "hooks: {mode: enforce, bogus: [}\n",
        "version: 1\n\"hooks\":\n  mode: enforce\nbroken: [\n",
        "hooks:\n  \"mode\": enforce\nbroken: [\n",
        "hooks: {\n  on_error: deny,\n  mode: enforce\n}\nbroken: [\n",
        "hooks:\r\n  mode: enforce\r\nbroken: [\r\n",
        "other:\n  mode: enforce\n  bogus: [\n",
    ] {
        assert!(declares_enforce(enforcing), "{enforcing}");
    }
    for not_enforcing in [
        "",
        "version: 1\n",
        "hooks:\n  mode: observe\n",
        "mode: enforce\n",
        "hooks:\n  # mode: enforce\n",
        "hooks:\n  evaluator:\n    mode: enforce\n",
        "other:\n  mode: enforce\nhooks:\n  mode: detect\n",
        // Not YAML, and no `mode: enforce` outside a comment.
        "hooks:\n  # mode: enforce\n  : : [\n",
        "hooks:\n  mode: observe\n  bogus: [\n",
    ] {
        assert!(!declares_enforce(not_enforcing), "{not_enforcing}");
    }
}

fn write(root: &Path, relative: &str, text: &str) -> PathBuf {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    path
}

/// The hooks configuration takes its rule content from the same folders as
/// `scan`, and its settings from the `hooks:` section, later roots winning.
#[test]
fn load_config_reads_the_hooks_section_and_the_shared_rule_folders() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    write(
        &first,
        "settings.d/10-hooks.yaml",
        "version: 1\nhooks:\n  mode: enforce\n  on_error: deny\n  thresholds:\n    action_ask: 30\n",
    );
    let settings = write(
        &second,
        "settings.d/10-hooks.yaml",
        "version: 1\nhooks:\n  on_error: ask\n  self_protection_rules: false\n",
    );
    let rules = write(&first, "rules.d/local.yaml", "version: 1\nrules: []\n");
    let organization = write(
        &second,
        "organization-rules.d/org.yaml",
        "version: 1\nrules: []\n",
    );
    let override_file = write(&second, "overrides.d/quiet.yaml", "version: 1\n");
    let policy = write(&second, "policies.d/policy.yaml", "version: 1\n");

    let config = load_config(&[first.clone(), second.clone()]).unwrap();
    assert_eq!(config.mode, telltale_core::hooks::config::Mode::Enforce);
    assert_eq!(
        config.on_error,
        telltale_core::hooks::config::OnError::Ask,
        "the later root wins"
    );
    assert_eq!(config.thresholds.action_ask, 30);
    assert!(!config.rules.self_protection);
    let absolute = |path: &Path| std::path::absolute(path).unwrap();
    assert_eq!(config.rules.packs.deployment, vec![absolute(&rules)]);
    assert_eq!(
        config.rules.packs.organization,
        vec![absolute(&organization)]
    );
    assert_eq!(config.rules.overrides, vec![absolute(&override_file)]);
    assert_eq!(config.rules.policy, Some(absolute(&policy)));
    // The roots and settings files are protected, like the rule files.
    let protected = config.protected_paths();
    for path in [&first, &second, &settings, &rules, &policy] {
        assert!(protected.contains(&absolute(path)), "{}", path.display());
    }
}

#[test]
fn load_config_refuses_unknown_hooks_keys_and_invalid_thresholds() {
    let dir = tempfile::tempdir().unwrap();
    for (body, expected) in [
        ("hooks:\n  bogus: 1\n", "bogus"),
        (
            "hooks:\n  thresholds:\n    action_ask: 90\n    action_deny: 80\n",
            "hooks.thresholds",
        ),
    ] {
        let root = dir.path().join(expected);
        write(
            &root,
            "settings.d/hooks.yaml",
            &format!("version: 1\n{body}"),
        );
        let error = load_config(&[root]).unwrap_err();
        assert!(error.contains(expected), "{body}: {error}");
    }
}

/// A linked root, folder or file is read through the link, so its target
/// is protected too: a file added to a linked `settings.d` later must not
/// be an unprotected way to change the configuration.
#[cfg(unix)]
#[test]
fn link_targets_in_a_config_root_are_protected() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let dropins = base.join("dropins");
    write(
        &dropins,
        "hooks.yaml",
        "version: 1\nhooks:\n  mode: enforce\n",
    );
    let rule_target = write(&base.join("elsewhere"), "local.yaml", "rules: []\n");
    let root = base.join("root");
    std::fs::create_dir_all(root.join("rules.d")).unwrap();
    symlink(&dropins, root.join("settings.d")).unwrap();
    symlink(&rule_target, root.join("rules.d/local.yaml")).unwrap();
    let linked_root = base.join("linked-root");
    symlink(&root, &linked_root).unwrap();

    let config = load_config(&[linked_root]).unwrap();
    assert_eq!(config.mode, telltale_core::hooks::config::Mode::Enforce);
    let protected = config.protected_paths();
    for target in [&root, &dropins, &dropins.join("hooks.yaml"), &rule_target] {
        assert!(
            protected.contains(target),
            "{} not in {protected:?}",
            target.display()
        );
    }
}
