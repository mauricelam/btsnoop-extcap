//! Utilities for functionalities related to Android Debug Bridge.

use std::{io::BufRead, path::PathBuf, process::Stdio, sync::OnceLock, time::Duration};

use anyhow::anyhow;
use log::debug;
use thiserror::Error;
use tokio::process::Command;

static ADB_PATH: OnceLock<PathBuf> = OnceLock::new();

#[derive(Error, Debug)]
pub enum AdbError {
    #[error("Adb not found. Please reinstall to configure the correct ADB path")]
    AdbNotFound,
    #[error("Root was declined. Check that you are on a userdebug or eng build.")]
    RootDeclined,

    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

/// Run adb root on the given device.
pub async fn root(serial: &str) -> Result<(), AdbError> {
    let adb_path = load_adb_path_compat().await?;
    Command::new(adb_path)
        .args(["-s", serial, "root"])
        .stdout(Stdio::null())
        .spawn()?
        .wait()
        .await?;
    let shell_uid = shell(serial, "id -u")
        .await?
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .stdout;
    debug!("Shell UID={shell_uid:?}");
    if shell_uid != b"0\n" {
        // If only `adb root` will return a different exit code...
        Err(AdbError::RootDeclined)?;
    }
    Ok(())
}

/// Run adb shell on the given device.
///
/// Example:
/// ```
/// let cmd = adb::shell(serial, format!("echo {}", serial)).spawn()?;
/// assert_eq!(cmd.wait_with_output().await?.stdout, serial);
/// ```
pub async fn shell(serial: &str, command: &str) -> Result<Command, AdbError> {
    let adb_path = load_adb_path_compat().await?;
    let mut cmd = Command::new(adb_path);
    cmd.args(["-s", serial, "shell", command]);
    Ok(cmd)
}

/// A structure representing a device connected over ADB.
pub struct AdbDevice {
    /// The serial number of the device. Most functions in this module requires
    /// the serial number as input.
    pub serial: String,
    /// A user-friendly display name of the device. (e.g. Pixel 6)
    pub display_name: String,
}

/// Query `adb devices` for the list of devices, and return a vec of [`AdbDevice`] structs.
pub async fn adb_devices(adb_path: Option<String>) -> anyhow::Result<Vec<AdbDevice>> {
    debug!("Getting adb devices from {adb_path:?}");
    let adb_path = adb_path.as_deref().unwrap_or("adb");
    if adb_path == "mock" {
        return Ok(mock_adb_devices());
    }
    let adb_path = load_adb_path_compat().await?;
    let cmd = Command::new(adb_path)
        .arg("devices")
        .arg("-l")
        .stdout(Stdio::piped())
        .spawn()?;
    let output = cmd.wait_with_output().await?;
    debug!(
        "Found adb devices {:?}",
        std::str::from_utf8(&output.stdout)
    );
    parse_adb_device(output.stdout.lines())
}

fn parse_adb_device(
    adb_device_output: impl Iterator<Item = std::io::Result<String>>,
) -> anyhow::Result<Vec<AdbDevice>> {
    let re = regex::Regex::new(r"([a-zA-Z0-9\\-]+)\s+device.*model:([^ ]+).*")?;
    Ok(adb_device_output
        .filter_map(|line| {
            let line = line.ok()?;
            let cap = re.captures_iter(&line).next()?;
            Some(AdbDevice {
                serial: cap[1].to_owned(),
                display_name: cap[2].to_owned(),
            })
        })
        .collect())
}

fn mock_adb_devices() -> Vec<AdbDevice> {
    vec![
        AdbDevice {
            serial: String::from("TEST_SERIAL_1"),
            display_name: String::from("Test device 1"),
        },
        AdbDevice {
            serial: String::from("TEST_SERIAL_2"),
            display_name: String::from("Test device 2"),
        },
    ]
}

/// The Btsnoop log mode, as reflected in "Settings > System > Developer options >
/// Enable Bluetooth HCI snoop log".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtsnoopLogMode {
    Disabled,
    Filtered,
    Full,
}

/// Functions for controlling the btsnoop log settings, as controlled in "Settings >
/// System > Developer options > Enable Bluetooth HCI snoop log".
pub enum BtsnoopLogSettings {}

impl BtsnoopLogSettings {
    pub async fn set_mode(serial: &str, mode: BtsnoopLogMode) -> anyhow::Result<()> {
        let mode_str = match mode {
            BtsnoopLogMode::Disabled => "disabled",
            BtsnoopLogMode::Filtered => "filtered",
            BtsnoopLogMode::Full => "full",
        };
        shell(
            serial,
            &format!("setprop persist.bluetooth.btsnooplogmode {mode_str}"),
        )
        .await?
        .spawn()?
        .wait()
        .await?;
        shell(serial, "svc bluetooth disable")
            .await?
            .spawn()?
            .wait()
            .await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        shell(serial, "svc bluetooth enable")
            .await?
            .spawn()?
            .wait()
            .await?;
        Ok(())
    }

    /// Gets the value of btsnoop log mode setting.
    pub async fn mode(serial: &str) -> anyhow::Result<BtsnoopLogMode> {
        let btsnooplogmode_proc = shell(serial, "getprop persist.bluetooth.btsnooplogmode")
            .await?
            .stdout(Stdio::piped())
            .spawn()?;
        let output = btsnooplogmode_proc.wait_with_output().await?;
        match output.stdout.as_slice() {
            b"full\n" => Ok(BtsnoopLogMode::Full),
            b"filtered\n" => Ok(BtsnoopLogMode::Filtered),
            b"disabled\n" | b"\n" => Ok(BtsnoopLogMode::Disabled),
            e => Err(anyhow!(
                "Unknown BTsnoop log mode: {:?}",
                String::from_utf8_lossy(e)
            )),
        }
    }
}

fn config_path() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    Some(exe_path.parent()?.join(crate::install::CONFIG_FILE_NAME))
}

async fn load_adb_path_from_config() -> anyhow::Result<String> {
    let Some(config_path) = config_path() else {
        anyhow::bail!("Cannot resolve path to config file")
    };
    let string = String::from_utf8(tokio::fs::read(config_path).await?)?;
    parse_adb_path(&string)
        .ok_or_else(|| anyhow::anyhow!("ADB_PATH config not found in config file"))
}

fn parse_adb_path(string: &str) -> Option<String> {
    for line in string.lines() {
        match line.split_once('=') {
            Some(("ADB_PATH", value)) => return Some(value.to_string()),
            _ => continue,
        }
    }
    None
}

#[test]
fn test_parse_config() {
    assert_eq!(
        parse_adb_path(r#"ADB_PATH=testing/123"#).unwrap(),
        "testing/123"
    );
}

/// Load the adb_path.
///
/// The recommended way to configure this is by setting `ADB_PATH={adb_path}` in
/// the `btsnoop-config` file, done by running `btsnoop-extcap --install`.
///
/// If that is not available, the legacy way is to try to resolve it from PATH.
/// This is no longer recommended because PATH may not be set when Wireshark is
/// launched from, say, a desktop launcher.
async fn load_adb_path_compat() -> Result<String, AdbError> {
    if let Ok(configured_path) = load_adb_path_from_config().await {
        Ok(configured_path)
    } else {
        resolve_adb_path()
            .await
            .ok_or(AdbError::AdbNotFound)
            .map(|f| f.to_string_lossy().to_string())
    }
}

pub async fn resolve_adb_path() -> Option<&'static PathBuf> {
    if let Some(adb_path) = ADB_PATH.get() {
        return Some(adb_path);
    }

    async fn find_adb_path() -> Option<PathBuf> {
        if let Ok(adb_path) = which::which("adb") {
            return Some(adb_path);
        }
        if let Some(adb_path) = Command::new("sh")
            .args(["-l", "-c", "which adb"])
            .output()
            .await
            .ok()
            .and_then(|output| output.stdout.lines().next())
            .and_then(|result| result.ok().map(|s| s.into()))
        {
            return Some(adb_path);
        }
        None
    }

    find_adb_path().await.map(|adb_path| {
        debug!("Found adb at {adb_path:?}");
        ADB_PATH.get_or_init(|| adb_path)
    })
}

#[cfg(test)]
mod test {
    use crate::adb::parse_adb_device;

    #[test]
    fn test_parse_adb_device_real_device() {
        let devices = parse_adb_device([
        r"List of devices attached",
        r"21111FCN20000W         device usb:1234567X product:panther model:Pixel_7 device:panther transport_id:2",
        r""].into_iter().map(|l| Ok(l.into()))).unwrap();
        assert_eq!("21111FCN20000W", devices[0].serial);
    }

    #[test]
    fn test_parse_adb_device_unauthorized() {
        let devices = parse_adb_device(
            [
                r"List of devices attached",
                r"21111FCN20000W         unauthorized usb:1048576X transport_id:3",
                r"",
            ]
            .into_iter()
            .map(|l| Ok(l.into())),
        )
        .unwrap();
        assert_eq!(0, devices.len());
    }

    #[test]
    fn test_parse_adb_device_emulator() {
        let devices = parse_adb_device([
        r"List of devices attached",
        r"emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a transport_id:1",
        r""].into_iter().map(|l| Ok(l.into()))).unwrap();
        assert_eq!("emulator-5554", devices[0].serial);
    }
}
