// Standalone sentinel: any attempted native invocation makes the test fail.
fn main() {
    let executable = std::env::current_exe().unwrap();
    std::fs::write(
        executable.parent().unwrap().join("launched"),
        b"unexpected invocation",
    )
    .unwrap();
}
