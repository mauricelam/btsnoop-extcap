use std::{
    io::Write,
    path::{Path, PathBuf},
};

use crate::adb;

/// The config file is located in the same directory as this executable when it
/// is installed (e.g. `~/.local/lib/wireshark/extcap/btsnoop-config`).
pub const CONFIG_FILE_NAME: &str = "btsnoop-config";

pub async fn install_extcap() -> anyhow::Result<()> {
    let extcap_dir = if cfg!(unix) {
        let home_dir = dirs::home_dir().ok_or(anyhow::anyhow!("Unable to find home directory"))?;
        if input_bool("Is your Wireshark 4.1 or above? [Y/n] ")? != Some(false) {
            // Wireshark 4.1 or above
            home_dir.join(".local/lib/wireshark/extcap")
        } else {
            // Wireshark 4.0 or below
            home_dir.join(".config/wireshark/extcap")
        }
    } else {
        println!("Enter Wireshark extcap path (Help -> About Wireshark -> Folders -> Personal Extcap path):");
        match input("[Default: C:\\Program Files\\Wireshark\\extcap]: ")? {
            s if s.is_empty() => PathBuf::from("C:\\Program Files\\Wireshark\\extcap"),
            s => PathBuf::from(s),
        }
    };
    symlink_executable(&extcap_dir).await?;
    resolve_adb_path(&extcap_dir).await?;
    Ok(())
}

#[cfg(windows)]
async fn symlink_executable(extcap_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(extcap_dir)?;
    let executable_dest = extcap_dir.join("btsnoop-extcap");
    if std::fs::exists(&executable_dest)?
        && input_bool(&format!(
            "Executable {executable_dest:?} already exists. Overwrite? [y/N]"
        ))? != Some(true)
    {
        return Ok(());
    }
    println!("Copying file to {executable_dest:?}");
    let _ = tokio::fs::remove_file(&executable_dest).await;
    tokio::fs::copy(std::env::current_exe()?, executable_dest).await?;
    Ok(())
}

#[cfg(unix)]
async fn symlink_executable(extcap_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(extcap_dir)?;
    let executable_dest = extcap_dir.join("btsnoop-extcap");
    if std::fs::exists(&executable_dest)?
        && input_bool(&format!(
            "Executable {executable_dest:?} already exists. Overwrite? [y/N]"
        ))? != Some(true)
    {
        return Ok(());
    }
    println!("Creating symlink at {executable_dest:?}");
    let _ = tokio::fs::remove_file(&executable_dest).await;
    tokio::fs::symlink(std::env::current_exe()?, executable_dest).await?;
    Ok(())
}

async fn resolve_adb_path(extcap_dir: &Path) -> anyhow::Result<()> {
    let adb_path = if let Some(adb_path) = adb::resolve_adb_path().await {
        match input(&format!(
            "Enter path to adb executable [Default: {}]: ",
            adb_path.to_string_lossy()
        ))? {
            s if s.is_empty() => adb_path.to_string_lossy().to_string(),
            s => s,
        }
    } else {
        input("Enter path to adb executable [Cannot find suitable default]: ")?
    };
    if !PathBuf::from(&adb_path).exists() {
        anyhow::bail!("{adb_path} does not exist")
    }
    tokio::fs::write(
        extcap_dir.join(CONFIG_FILE_NAME),
        format!("ADB_PATH={adb_path}").as_bytes(),
    )
    .await?;
    Ok(())
}

/// Read a line of input from stdin
fn input(prompt: &str) -> std::io::Result<String> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut input_str = String::new();
    std::io::stdin().read_line(&mut input_str)?;
    input_str.truncate(input_str.len() - 1); // Remove trailing \n
    Ok(input_str)
}

/// Read a line of Y/n input from stdin.
fn input_bool(prompt: &str) -> std::io::Result<Option<bool>> {
    let yn = input(prompt)?;
    Ok(match yn.as_str() {
        "n" | "N" => Some(false),
        "y" | "Y" => Some(true),
        _ => None,
    })
}
