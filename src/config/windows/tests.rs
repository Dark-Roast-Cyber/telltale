use super::*;
use std::process::Command;

fn current_user() -> String {
    let output = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    text.trim()
        .rsplit(',')
        .next()
        .unwrap()
        .trim_matches('"')
        .to_owned()
}

fn icacls(path: &Path, args: &[&str]) {
    let output = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

/// The ACL as icacls prints it, for assertion messages.
fn acl(path: &Path) -> String {
    let output = Command::new("icacls").arg(path).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn program_data_is_the_known_folder() {
    let path = program_data().unwrap();
    assert!(path.is_absolute());
    assert!(path.is_dir());
    assert!(path.ends_with("ProgramData"));
}

#[test]
fn sid_strings_round_trip() {
    for sid in TRUSTED {
        assert_eq!(sid_string(&sid_bytes(sid).unwrap()), *sid);
    }
}

/// Real system folders pass with the production principals; a folder the
/// test creates is owned by its user and refused.
#[test]
fn administrator_only_reads_real_acls() {
    let windows = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    for path in [
        windows.join("System32"),
        windows.join("System32\\kernel32.dll"),
    ] {
        assert_eq!(administrator_only(&path).unwrap(), Ok(()), "{path:?}");
    }
    let temp = tempfile::tempdir().unwrap();
    // Run elevated, the creator may be Administrators: owner or write.
    assert!(matches!(
        administrator_only(temp.path()).unwrap(),
        Err(Untrusted::Owner | Untrusted::Writable(_))
    ));
    assert_eq!(
        administrator_only(&temp.path().join("missing"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

/// The root that docs/install.md tells operators to create passes, with a
/// file an administrator adds. Setting the owner to Administrators needs
/// elevation, which Windows CI runners have.
#[test]
fn documented_root_passes_when_elevated() {
    let groups = Command::new("whoami").arg("/groups").output().unwrap();
    if !String::from_utf8_lossy(&groups.stdout).contains("S-1-16-12288") {
        eprintln!("not elevated: documented root not checked");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("telltale");
    std::fs::create_dir(&root).unwrap();
    icacls(&root, &["/setowner", "*S-1-5-32-544"]);
    icacls(&root, &["/reset"]);
    icacls(
        &root,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
        ],
    );
    let file = root.join("settings.yaml");
    std::fs::write(&file, b"version: 1\n").unwrap();
    icacls(&file, &["/setowner", "*S-1-5-32-544"]);
    assert_eq!(administrator_only(&root).unwrap(), Ok(()), "{}", acl(&root));
    assert_eq!(administrator_only(&file).unwrap(), Ok(()), "{}", acl(&file));
    // A user-writable file in it is still refused.
    icacls(&file, &["/grant", "*S-1-5-32-545:(M)"]);
    assert_eq!(
        administrator_only(&file).unwrap(),
        Err(Untrusted::Writable("S-1-5-32-545".into()))
    );
}

/// The same check with the test's own user standing in for the trusted
/// principals, so pass and fail cases run without elevation.
#[test]
fn write_grants_owner_and_links_decide() {
    let user = current_user();
    let trusted = trusted_sids(&[&user, "S-1-5-18"]).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let file = root.join("settings.yaml");
    std::fs::write(&file, b"version: 1\n").unwrap();
    // Elevated, new objects are owned by Administrators instead.
    let owner = format!("*{user}");
    let grant = format!("*{user}:(OI)(CI)F");
    icacls(&root, &["/setowner", &owner]);
    icacls(&root, &["/reset"]);
    icacls(
        &root,
        &[
            "/inheritance:r",
            "/grant:r",
            &grant,
            "/grant:r",
            "*S-1-5-32-545:(OI)(CI)RX",
        ],
    );
    icacls(&file, &["/setowner", &owner]);
    icacls(&file, &["/reset"]);
    let check = |path: &Path| check(path, &trusted, 1).unwrap();
    assert_eq!(check(&root), Ok(()), "{}", acl(&root));
    assert_eq!(check(&file), Ok(()), "{}", acl(&file));

    // Users may add files: the folder's content can change.
    icacls(&root, &["/grant", "*S-1-5-32-545:(AD,WD)"]);
    assert_eq!(
        check(&root),
        Err(Untrusted::Writable("S-1-5-32-545".into()))
    );
    // An inherit-only grant does not apply to the folder itself.
    icacls(
        &root,
        &[
            "/remove:g",
            "*S-1-5-32-545",
            "/grant",
            "*S-1-5-32-545:(OI)(CI)(IO)RX",
        ],
    );
    icacls(&root, &["/grant", "*S-1-1-0:(OI)(IO)M"]);
    assert_eq!(check(&root), Ok(()));
    // ...but it does apply to a file that inherits it.
    icacls(&file, &["/reset"]);
    assert_eq!(check(&file), Err(Untrusted::Writable("S-1-1-0".into())));
    // Deny entries never make an object trusted.
    icacls(&file, &["/deny", "*S-1-1-0:(WD,AD)"]);
    assert_eq!(check(&file), Err(Untrusted::Writable("S-1-1-0".into())));
    // Extended-attribute writes do not change what is read...
    icacls(&file, &["/reset"]);
    icacls(&root, &["/remove:g", "*S-1-1-0"]);
    icacls(&file, &["/reset"]);
    icacls(&file, &["/grant", "*S-1-5-32-545:(WEA)"]);
    assert_eq!(check(&file), Ok(()));
    // ...but attribute writes can turn the file into a link.
    icacls(&file, &["/grant", "*S-1-5-32-545:(WA)"]);
    assert_eq!(
        check(&file),
        Err(Untrusted::Writable("S-1-5-32-545".into()))
    );
    icacls(&file, &["/reset"]);
    // The owner must be trusted: SYSTEM alone is not an owner here.
    assert_eq!(
        super::check(&file, &trusted[1..], 1).unwrap(),
        Err(Untrusted::Owner)
    );

    // A junction is refused as a link, whatever its ACL.
    let junction = root.join("linked");
    let made = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(temp.path())
        .output()
        .unwrap();
    assert!(made.status.success());
    assert_eq!(check(&junction), Err(Untrusted::Link));
}
