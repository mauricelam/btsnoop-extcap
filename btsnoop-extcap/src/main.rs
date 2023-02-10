use crate::{
    adb::{BtsnoopLogMode, BtsnoopLogSettings},
    extcap::{ControlPacket, ExtcapControlSenderTrait},
};
use anyhow::anyhow;
use btsnoop::{FileHeader, PacketHeader};
use btsnoop_ext::Direction;
use clap::Parser;
use extcap::{ControlCommand, ExtcapControlSender};
use log::{debug, info, warn};
use nom_derive::Parse as _;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink,
};
use std::{
    borrow::Cow,
    io::{stdout, Write},
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt},
};
use util::try_read_exact;

mod adb;
mod btsnoop_ext;
mod extcap;
mod util;

#[derive(Debug, Parser)]
#[command(author, version, about)]
pub struct BtsnoopArgs {
    #[command(flatten)]
    extcap: extcap::ExtcapArgs,

    /// Specify the path to the btsnoop log file on the device to stream from. For a special value
    /// with the format `local:<path>`, the log file will be read locally on the host device
    /// instead.
    #[arg(long)]
    pub btsnoop_log_file_path: Option<String>,

    /// Specify the path to the ADB executable, or "mock" for a special mock implementation used
    /// for testing.
    #[arg(long)]
    pub adb_path: Option<String>,

    /// Delay in number of seconds before showing packets. Since btsnoop logs are stored on a file on
    /// the Android device, this allows skipping old packets and only show new ones in the UI.
    #[arg(long, value_parser = |arg: &str| arg.parse().map(std::time::Duration::from_secs), default_value = "1")]
    pub display_delay: Duration,
}

/// Reads from the input, adds the corresponding PCAP headers, and writes to the
/// output data. The `display_delay` can also be set such that packets read
/// during an initial time period will not be displayed.
async fn write_pcap_packets<W: Write, R: AsyncRead + Unpin>(
    mut input_reader: R,
    output_writer: W,
    display_delay: Duration,
) -> anyhow::Result<()> {
    let pcap_header = PcapHeader {
        datalink: DataLink::BLUETOOTH_HCI_H4_WITH_PHDR,
        endianness: pcap_file::Endianness::Big,
        ..Default::default()
    };
    let mut header_buf = [0_u8; FileHeader::LENGTH];
    input_reader.read_exact(&mut header_buf[..]).await?;
    FileHeader::parse(&header_buf).unwrap();
    let mut pcap_writer = PcapWriter::with_header(output_writer, pcap_header).unwrap();
    let start_time = Instant::now();
    while let Some(packet_header_buf) =
        try_read_exact::<_, { PacketHeader::LENGTH }>(&mut input_reader).await?
    {
        let (_rem, packet_header) = PacketHeader::parse(&packet_header_buf).unwrap();
        let mut packet_buf: Vec<u8> = vec![0_u8; packet_header.included_length as usize];
        input_reader.read_exact(&mut packet_buf).await?;
        if start_time.elapsed() > display_delay {
            let timestamp = packet_header.timestamp();
            let direction =
                Direction::parse_from_payload(&packet_buf).unwrap_or(Direction::Unknown);
            pcap_writer.write_packet(&PcapPacket {
                timestamp,
                data: Cow::from(&[&direction.to_hci_pseudo_header(), &packet_buf[..]].concat()),
                orig_len: packet_header.original_length + 4,
            })?;
        }
        stdout().flush()?;
    }
    Ok(())
}

const BUTTON_TURN_ON_BTSNOOP: u8 = 0;
const BUTTON_TURN_OFF_BTSNOOP: u8 = 1;

async fn handle_control_packet(
    serial: String,
    control_packet: ControlPacket<'_>,
    extcap_control: Option<ExtcapControlSender>,
) -> anyhow::Result<()> {
    if control_packet.command == ControlCommand::Set {
        match control_packet.control_number {
            BUTTON_TURN_ON_BTSNOOP => {
                // Turn on
                BtsnoopLogSettings::set_mode(&serial, BtsnoopLogMode::Full).await?;
                extcap_control.disable_button(BUTTON_TURN_ON_BTSNOOP).await;
                extcap_control.enable_button(BUTTON_TURN_OFF_BTSNOOP).await;
            }
            BUTTON_TURN_OFF_BTSNOOP => {
                // Turn off
                BtsnoopLogSettings::set_mode(&serial, BtsnoopLogMode::Disabled).await?;
                extcap_control.disable_button(BUTTON_TURN_OFF_BTSNOOP).await;
                extcap_control.enable_button(BUTTON_TURN_ON_BTSNOOP).await;
            }
            control_number => panic!("Unknown control number {control_number}"),
        }
    }
    Ok(())
}

async fn print_packets(
    serial: &str,
    extcap_control: Option<ExtcapControlSender>,
    output_fifo: &Path,
    btsnoop_log_file_path: &Option<String>,
    display_delay: Duration,
) -> anyhow::Result<()> {
    let writer = std::fs::File::create(output_fifo)?;
    let btsnoop_log_file_path = btsnoop_log_file_path
        .as_deref()
        .unwrap_or("/data/misc/bluetooth/logs/btsnoop_hci.log");
    if let Some(test_file) = btsnoop_log_file_path.strip_prefix("local:") {
        write_pcap_packets(File::open(test_file).await?, writer, display_delay).await?;
    } else {
        adb::root(serial).await?;
        if BtsnoopLogSettings::mode(serial).await? == BtsnoopLogMode::Full {
            extcap_control.disable_button(0).await;
            extcap_control.enable_button(1).await;
        } else {
            extcap_control.disable_button(1).await;
            extcap_control.enable_button(0).await;
            extcap_control.status_message("BTsnoop logging is turned off. Use View > Interface Toolbars to show the buttons to turn it on").await;
        }
        let mut cmd = adb::shell(
            serial,
            format!("tail -F -c +0 {btsnoop_log_file_path}").as_str(),
        )
        .stdout(Stdio::piped())
        .spawn()?;
        info!("Running adb tail -F -c +0 {btsnoop_log_file_path}");
        let stdout = cmd.stdout.as_mut().unwrap();
        write_pcap_packets(stdout, writer, display_delay).await?;
        info!("Print packet finished");
    }
    extcap_control
        .status_message("BT capture connection closed")
        .await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = BtsnoopArgs::parse();
    debug!("Running with args: {args:#?}");
    if args.extcap.extcap_interfaces {
        println!("extcap {{version={}}}", env!("CARGO_PKG_VERSION"));
        for d in adb::adb_devices(args.adb_path).await?.iter() {
            println!(
                "interface {{value=btsnoop-{}}}{{display=BTsnoop {} {}}}",
                d.serial, d.display_name, d.serial
            );
            println!("control {{number=1}}{{type=button}}{{display=Turn off BT logging}}");
            println!("control {{number=0}}{{type=button}}{{display=Turn on BT logging}}");
        }
        Ok(())
    } else if args.extcap.capture {
        let interface = args.extcap.extcap_interface.unwrap();
        let fifo = args.extcap.fifo.unwrap();
        assert!(
            interface.starts_with("btsnoop-"),
            "Interface must start with \"btsnoop-\""
        );
        let serial = interface.split('-').nth(1).unwrap();
        let extcap_control = extcap::ExtcapControl::new_option(
            args.extcap.extcap_control_in,
            args.extcap.extcap_control_out,
        );
        let control_pipe = extcap_control
            .as_ref()
            .map(|control| control.get_control_pipe());
        let control_in_pipe = extcap_control.as_ref().map(|r| r.subscribe());
        let result = tokio::try_join!(
            async {
                if let Some(mut control) = extcap_control {
                    control.process().await?;
                }
                debug!("Extcap control ending");
                Ok(())
            },
            async {
                if let Some(mut pipe) = control_in_pipe {
                    while let Ok(packet) = pipe.recv().await {
                        handle_control_packet(serial.to_string(), packet, control_pipe.clone())
                            .await?;
                    }
                }
                debug!("Control packet handling ending");
                Ok::<(), anyhow::Error>(())
            },
            print_packets(
                serial,
                control_pipe.clone(),
                &fifo,
                &args.btsnoop_log_file_path,
                args.display_delay
            ),
        );
        if let Err(e) = result {
            warn!("Error capturing packets: {e}");
        }
        debug!("Capture ending");
        Ok(())
    } else if args.extcap.extcap_config {
        Ok(())
    } else if args.extcap.extcap_dlts {
        // Values from https://github.com/wireshark/wireshark/blob/master/wiretap/wtap.h
        println!(
            "dlt {{number=99}}{{name=BluetoothH4}}{{display=Bluetooth HCI UART transport layer plius pseudo-header}}"
        );
        Ok(())
    } else {
        let exe_path = std::env::current_exe()
            .map(|exe| {
                let path = exe.to_string_lossy();
                format!("\n  ln -s \"{path}\" ~/.config/wireshark/extcap/")
            })
            .unwrap_or_default();
        Err(anyhow!(
            concat!(
                "Missing command. To use this extcap plugin, symlink or copy this executable ",
                "to your Wireshark extcap directory {}"
            ),
            exe_path
        ))
    }
}