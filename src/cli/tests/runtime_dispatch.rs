use super::super::*;

#[test]
fn runtime_observation_is_lazy_and_only_for_scan_or_watch() {
    for (arguments, expected) in [
        (vec!["telltale", "discover", "--licenses"], false),
        (vec!["telltale", "discover", "--root", "synthetic"], false),
        (vec!["telltale", "rules", "list"], false),
        (vec!["telltale", "config", "show"], false),
        (vec!["telltale", "status"], false),
        (vec!["telltale", "export"], false),
        (vec!["telltale", "scan", "--once"], true),
        (vec!["telltale", "watch"], true),
    ] {
        let args = Args::try_parse_from(arguments).unwrap();
        let calls = std::cell::Cell::new(0_usize);
        let runtime = command_runtime(&args.command, || {
            calls.set(calls.get() + 1);
            RuntimeSnapshot {
                value: serde_json::Value::Null,
            }
        });
        assert_eq!(runtime.is_some(), expected);
        assert_eq!(calls.get(), usize::from(expected));
    }
}
