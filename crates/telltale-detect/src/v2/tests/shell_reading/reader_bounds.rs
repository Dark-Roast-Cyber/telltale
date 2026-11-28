use super::*;

/// Text no shell parses as written. The reader must neither panic on a byte
/// boundary nor let `code` drift from `command`, whose offsets it shares.
#[test]
fn reader_holds_its_offsets_on_any_text() {
    const ALPHABET: [&str; 17] = [
        "#", "<<", "\n", "'", "\"", "\\", "$(", ")", "`", " ", "é", "-", "${", "a", "bash -c ",
        "(", ";",
    ];
    fn check(text: &str) {
        let shell = super::super::super::shell_text::read(text);
        assert_eq!(shell.command.len(), shell.code.len(), "{text:?}");
        for (command, code) in shell.command.bytes().zip(shell.code.bytes()) {
            assert!(command == code || code == b' ', "{text:?}");
        }
        // The action view slices both texts with the spans the reader reports.
        for span in shell.stages.iter().chain(&shell.inner_commands) {
            assert!(
                shell.code.get(span.clone()).is_some() && shell.command.get(span.clone()).is_some(),
                "{text:?} {span:?}"
            );
        }
        for pipe in &shell.pipes {
            assert!(*pipe <= shell.command.len(), "{text:?}");
        }
    }
    fn extend(text: &mut String, left: usize) {
        check(text);
        if left == 0 {
            return;
        }
        for piece in ALPHABET {
            let length = text.len();
            text.push_str(piece);
            extend(text, left - 1);
            text.truncate(length);
        }
    }
    extend(&mut String::new(), 5);
}

/// Each shape revisits text if the reader rescans it for every operator.
#[test]
fn reader_work_stays_linear_on_adversarial_text() {
    const SIZE: usize = 1 << 20;
    for piece in [
        "cat <<A\n",
        "<<A ",
        "# a\n",
        "'x' ",
        "-c 'x' ",
        "$(",
        "$()",
        "`",
        "$(<<A\nA\n)",
        "bash -c '# a\n'",
    ] {
        check(&piece.repeat(SIZE / piece.len()));
    }
    // Closing a nested substitution returns to an ever longer word.
    let depth = SIZE / 3;
    check(&format!("{}{}", "$(".repeat(depth), ")".repeat(depth)));
    // The same inside bodies a shell reads or expands.
    for (open, piece) in [
        ("cat <<A\n", "$("),
        ("cat <<A\n", "$(x) "),
        ("cat <<A\n", "`x` "),
        ("bash <<A\n", "cat <<B\nx\nB\n"),
    ] {
        check(&format!("{open}{}\nA\n", piece.repeat(SIZE / piece.len())));
    }
    // One long command that a reader must judge at each of its substitutions.
    let piece = "$(cat <<A\nA\n) a ";
    for command in ["uv ", "x=1 ", ""] {
        check(&format!("{command}{}", piece.repeat(SIZE / piece.len())));
    }
    // One long word that a reader must judge at each of its substitutions.
    let piece = "$(<<A\nA\n)";
    check(&format!("x={}", piece.repeat(SIZE / piece.len())));
    // Text with no place to go, and a body each layer reads more than once.
    check(&format!("cat <<$(x)\n{}", "'a' ".repeat(SIZE / 4)));
    let mut layered = "$x\n".repeat(SIZE / 3);
    for level in 0..6 {
        layered = format!("x=`cat <<A{level}\n{layered}A{level}\n`\n");
    }
    check(&layered);
    fn check(text: &str) {
        let started = std::time::Instant::now();
        let shell = super::super::super::shell_text::read(text);
        let shape = &text[..text.len().min(24)];
        assert!(shell.work <= 80 * text.len(), "{shape:?}: {}", shell.work);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{shape:?}: {:?}",
            started.elapsed()
        );
    }
}

/// An opener padded past the longest word the reader classifies still counts.
#[test]
fn an_opener_too_long_to_classify_leaves_later_bodies_in_doubt() {
    let padding = "\\\n".repeat(128);
    let text = format!("{{{padding} true; cat <<'E'\nbody\nE\n}} | sh");
    assert!(
        super::super::super::shell_text::read(&text)
            .command
            .contains("body")
    );
}

#[test]
fn redirection_targets_are_found_in_linear_work() {
    for piece in [">", "> ", ">a", ">a "] {
        let text = piece.repeat((1 << 22) / piece.len());
        let started = std::time::Instant::now();
        let _ = super::super::super::actions::without_written(&text);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{piece:?}: {:?}",
            started.elapsed()
        );
    }
}

#[test]
fn reader_separates_comments_bodies_and_code() {
    let shell =
        super::super::super::shell_text::read("cat > a <<'EOF' # c\nbody\nEOF\nnext # don't\n");
    assert_eq!(shell.command, "cat > a <<'EOF' # c\nnext # don't");
    assert_eq!(shell.code, "cat > a <<'EOF'    \nnext        ");
    assert_eq!(shell.authored, "body\n");
    let shell = super::super::super::shell_text::read("# see <<EOF\nnext");
    assert_eq!(shell.command, "# see <<EOF\nnext");
    assert_eq!(shell.code, "           \nnext");
    let shell = super::super::super::shell_text::read("cat <<NOPE\nnext\ncat <<A\nb\nA");
    assert_eq!(shell.command, "cat <<NOPE\nnext\ncat <<A\nb\nA");
    // Array-form commands are joined with a trailing space.
    let shell = super::super::super::shell_text::read("cat <<EOF\nbody\nEOF ");
    assert_eq!(shell.command, "cat <<EOF");
    let shell = super::super::super::shell_text::read("cat <<EOF\r\nbody\r\nEOF\r\nnext\r\n");
    assert_eq!(shell.command, "cat <<EOF\nnext");
    // A command before the one holding the body never sees it.
    let shell = super::super::super::shell_text::read("bash -s | cat <<'EOF'\nbody\nEOF");
    assert_eq!(shell.command, "bash -s | cat <<'EOF'");
    // The word after `>|` is a file.
    let shell = super::super::super::shell_text::read("cat <<'EOF' >| bash\nbody\nEOF");
    assert_eq!(shell.command, "cat <<'EOF' >| bash");
    // A body holding a `case` is kept whole, because its patterns could close a
    // substitution early to this reader. Its substitution is also lifted.
    let shell =
        super::super::super::shell_text::read("cat <<EOF\n$(case x in x) true;; esac)\nbody\nEOF");
    assert_eq!(
        shell.command,
        "cat <<EOF\n$(case x in x) true;; esac)\nbody\ncase x in x) true;; esac"
    );
    // A group makes every later body in the text doubtful, even a closed group,
    // because no closer of one can be told from a word.
    let shell = super::super::super::shell_text::read("{ a; }\ncat <<'EOF'\nbody\nEOF");
    assert_eq!(shell.command, "{ a; }\ncat <<'EOF'\nbody");
    // An `if` or a loop closed before the body has no hold on it.
    let shell = super::super::super::shell_text::read("if a; then b; fi\ncat <<'EOF'\nbody\nEOF");
    assert_eq!(shell.command, "if a; then b; fi\ncat <<'EOF'");
    // A stage that was split inside a substitution ends with the substitution,
    // and each of its commands is a stage too, quoted or not.
    let stages = |text: &str| {
        let shell = super::super::super::shell_text::read(text);
        shell
            .stages
            .iter()
            .chain(&shell.inner_commands)
            .map(|stage| shell.code[stage.clone()].trim().to_owned())
            .collect::<BTreeSet<_>>()
    };
    let expected = |list: &[&str]| {
        list.iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(
        stages("echo $(a; b) c"),
        expected(&["echo $(a", "a", "b", "c"])
    );
    assert_eq!(
        stages("echo \"$(a; b)\" c"),
        expected(&["echo \"$(a; b)\" c", "a", "b"])
    );
    assert_eq!(stages("x=`a`"), expected(&["x=`a`", "a"]));
    assert_eq!(
        stages("bash -c 'a; b'"),
        expected(&["bash -c 'a; b'", "a", "b"])
    );
    // A body's only reader names no file, so it adds no stage.
    assert_eq!(
        stages("x=$(cat <<'E'\nbody\nE\n)"),
        expected(&["x=$(cat <<'E'", ""])
    );
}
