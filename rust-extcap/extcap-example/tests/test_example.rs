use assert_cmd::prelude::*;
use indoc::indoc;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn interfaces() {
    let mut cmd = Command::cargo_bin("extcap-example").unwrap();
    cmd.args(["--extcap-interfaces"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::diff(indoc! {"
            extcap {version=0.1.0}{help=http://www.wireshark.org}{display=Rust Example extcap interface}
            interface {value=rs-example1}{display=Rust Example interface 1 for extcap}
            interface {value=rs-example2}{display=Rust Example interface 2 for extcap}
            control {number=0}{type=string}{display=Message}{tooltip=Package message content. Must start with a capital letter.}{placeholder=Enter package message content here ...}{validation=^[A-Z]+}
            control {number=1}{type=selector}{display=Time delay}{tooltip=Time delay between packets}
            value {control=1}{value=1}{display=1s}
            value {control=1}{value=2}{display=2s}
            value {control=1}{value=3}{display=3s}
            value {control=1}{value=4}{display=4s}
            value {control=1}{value=5}{display=5s}{default=true}
            value {control=1}{value=60}{display=60s}
            control {number=2}{type=boolean}{display=Verify}{tooltip=Verify package control}
            control {number=3}{type=button}{display=Turn on}{tooltip=Turn on or off}
            control {number=4}{type=button}{role=help}{display=Help}{tooltip=Show help}
            control {number=5}{type=button}{role=restore}{display=Restore}{tooltip=Restore default values}
            control {number=6}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}
            "}
        ));
}

#[test]
fn config() {
    let mut cmd = Command::cargo_bin("extcap-example").unwrap();
    cmd.args(["--extcap-interface", "rs-example1", "--extcap-config"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::diff(indoc! {"
            arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{range=1,15}{default=5}{type=integer}
            arg {number=1}{call=--message}{display=Message}{tooltip=Package message content}{placeholder=Please enter a message here ...}{required=true}{save=false}{type=string}
            arg {number=2}{call=--verify}{display=Verify}{tooltip=Verify package content}{default=true}{type=boolflag}
            arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{placeholder=Load interfaces ...}{type=selector}{reload=true}
            value {arg=3}{value=if1}{display=Remote1}{default=true}
            value {arg=3}{value=if2}{display=Remote2}{default=false}
            arg {number=4}{call=--fake_ip}{display=Fake IP Address}{tooltip=Use this ip address as sender}{validation=\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b}{save=true}{type=string}
            arg {number=5}{call=--ltest}{display=Long Test}{tooltip=Long Test Value}{default=123123123123123123}{type=long}{group=Numeric Values}
            arg {number=6}{call=--d1test}{display=Double 1 Test}{tooltip=Double Test Value}{default=123.456}{type=double}{group=Numeric Values}
            arg {number=7}{call=--d2test}{display=Double 2 Test}{tooltip=Double Test Value}{default=123456}{type=double}{group=Numeric Values}
            arg {number=8}{call=--password}{display=Password}{tooltip=Package message password}{type=password}
            arg {number=9}{call=--ts}{display=Start Time}{tooltip=Capture start time}{group=Time / Log}{type=timestamp}
            arg {number=10}{call=--logfile}{display=Log File Test}{tooltip=The Log File Test}{group=Time / Log}{type=fileselect}{mustexist=true}
            arg {number=11}{call=--radio}{display=Radio Test}{tooltip=Radio Test Value}{group=Selection}{type=radio}
            value {arg=11}{value=r1}{display=Radio1}{default=false}
            value {arg=11}{value=r2}{display=Radio2}{default=true}
            arg {number=12}{call=--multi}{display=MultiCheck Test}{tooltip=MultiCheck Test Value}{group=Selection}{type=multicheck}
            value {arg=12}{value=m1}{display=Checkable Parent 1}{default=false}{enabled=true}
            value {arg=12}{value=m1c1}{display=Checkable Child 1}{default=false}{enabled=true}{parent=m1}
            value {arg=12}{value=m1c1g1}{display=Uncheckable Grandchild}{default=false}{enabled=false}{parent=m1c1}
            value {arg=12}{value=m1c2}{display=Checkable Child 2}{default=false}{enabled=true}{parent=m1}
            value {arg=12}{value=m2}{display=Checkable Parent 2}{default=false}{enabled=true}
            value {arg=12}{value=m2c1}{display=Checkable Child 1}{default=false}{enabled=true}{parent=m2}
            value {arg=12}{value=m2c1g1}{display=Checkable Grandchild}{default=false}{enabled=true}{parent=m2c1}
            value {arg=12}{value=m2c2}{display=Uncheckable Child 2}{default=false}{enabled=false}{parent=m2}
            value {arg=12}{value=m2c2g1}{display=Uncheckable Grandchild}{default=false}{enabled=false}{parent=m2c2}
        "}
    ));
}

#[test]
fn config_reload_options() {
    let mut cmd = Command::cargo_bin("extcap-example").unwrap();
    cmd.args(["--extcap-interface", "rs-example1"])
        .arg("--extcap-config")
        .args(["--extcap-reload-option", "remote"])
        .arg("--verify");
    cmd.assert().success().stdout(predicate::str::diff(indoc!{"
        value {arg=3}{value=if1}{display=Remote Interface 1}{default=false}
        value {arg=3}{value=if2}{display=Remote Interface 2}{default=true}
        value {arg=3}{value=if3}{display=Remote Interface 3}{default=false}
        value {arg=3}{value=if4}{display=Remote Interface 4}{default=false}
    "}));
}

#[test]
fn print_dlt() {
    let mut cmd = Command::cargo_bin("extcap-example").unwrap();
    cmd.args(["--extcap-interface", "rs-example1", "--extcap-dlts"]);
    cmd.assert().success().stdout(predicate::str::diff(
        "dlt {number=147}{name=USER0}{display=Demo Implementation for Extcap}\n",
    ));
}
