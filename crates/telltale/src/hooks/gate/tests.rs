use super::*;
use serde_json::json;

#[test]
fn detect_only_releases_nothing_whatever_it_is_handed() {
    let deny = json!({"hookSpecificOutput": {"permissionDecision": "deny"}});
    for answer in [
        Answer::NONE,
        Answer::output(Some(deny.clone())),
        Answer::exit(1),
        Answer::exit(2),
        Answer::exit(101),
        Answer {
            output: Some(deny.clone()),
            exit_code: 2,
        },
    ] {
        assert_eq!(Gate::DetectOnly.release(answer.clone()), Answer::NONE);
        assert_eq!(Gate::Enforce.release(answer.clone()), answer);
    }
}

#[test]
fn only_a_configuration_that_says_enforce_opens_the_gate() {
    let never = || -> bool { panic!("asked about a configuration that loaded") };
    let loaded = |mode| -> Result<Config, ()> {
        Ok(Config {
            mode,
            ..Config::default()
        })
    };
    assert_eq!(
        Gate::for_config(&loaded(Mode::Observe), never),
        Gate::DetectOnly
    );
    assert_eq!(
        Gate::for_config(&loaded(Mode::Enforce), never),
        Gate::Enforce
    );

    let broken: Result<Config, ()> = Err(());
    assert_eq!(Gate::for_config(&broken, || false), Gate::DetectOnly);
    assert_eq!(Gate::for_config(&broken, || true), Gate::Enforce);
}
