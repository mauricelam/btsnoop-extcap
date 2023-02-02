use assert_cmd::prelude::*; // Add methods on commands
use predicates::prelude::*; // Used for writing assertions
use std::process::Command; // Run programs

#[test]
fn list_interfaces() {
    let mut cmd = Command::cargo_bin("btsnoop-extcap").unwrap();
    cmd.arg("--extcap-interfaces")
        .arg("--extcap-version")
        .arg("v0_testing")
        .arg("--adb-path=mock");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(concat!(
            "interface {value=btsnoop-TEST_SERIAL_1}{display=BTsnoop Test device 1 TEST_SERIAL_1}\n",
            "interface {value=btsnoop-TEST_SERIAL_2}{display=BTsnoop Test device 2 TEST_SERIAL_2}"
        )));
}

fn contains(needle: &[u8]) -> impl Fn(&[u8]) -> bool + '_ {
    move |bytes| bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn capture() {
    let mut cmd = Command::cargo_bin("btsnoop-extcap").unwrap();
    cmd.arg("--extcap-interface")
        .arg("btsnoop-SERIAL")
        .arg("--capture")
        .arg("--fifo")
        .arg("/dev/stdout")
        .arg("--btsnoop-log-file-path")
        .arg("local:tests/testdata/btsnoop_hci.log");
    cmd.assert()
        .success()
        .stdout(predicate::function(contains(b"Pixel 6 Pro")));
}

#[test]
fn missing_fifo() {
    let mut cmd = Command::cargo_bin("btsnoop-extcap").unwrap();
    cmd.arg("--extcap-interface")
        .arg("btsnoop-SERIAL")
        .arg("--capture");
    cmd.assert().failure().stderr(
        predicate::str::contains("the following required arguments were not provided:")
            .and(predicate::str::contains("--fifo <FIFO>")),
    );
}
