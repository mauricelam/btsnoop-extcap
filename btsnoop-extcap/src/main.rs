use std::{
    fs::File,
    io::{BufRead, Read, Write},
    process::{Command, Stdio},
};

use anyhow::{anyhow, Ok};
use btsnoop::{FileHeader, PacketHeader};
use clap::{Parser, CommandFactory};
use nom_derive::Parse as _;
use pcap_file::{pcap::PcapHeader, DataLink, PcapWriter};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct ExtcapArgs {
    /// Wireshark 2.9 and later pass `--extcap-version=x.x` when querying for the list of
    /// interfaces, which provides the calling Wireshark’s major and minor version. This can be used
    /// to change behavior depending on the Wireshark version in question.
    #[arg(long)]
    extcap_version: Option<String>,

    /// To run the capture, the extcap must implement the `--capture`, `--extcap-capture-filter` and
    /// `--fifo` options.
    ///
    /// These arguments are specified by Wireshark, which opens the fifo for reading. All the other
    /// options are automatically added to run the capture. The extcap interface is used like all
    /// other interfaces (meaning that capture on multiple interfaces, as well as stopping and
    /// restarting the capture is supported).
    #[arg(long, requires = "fifo", requires = "extcap_interface")]
    capture: bool,

    /// First step in the extcap exchange: this program is queried for its interfaces.
    /// ```sh
    /// $ extcapbin --extcap-interfaces
    /// ```
    /// This call must print the existing interfaces for this extcap and must return 0. The output
    /// must conform to the grammar specified for extcap, and it is specified in the
    /// [doc/extcap.4](https://www.wireshark.org/docs/man-pages/extcap.html) generated man page (in
    /// the build dir).
    #[arg(long, verbatim_doc_comment)]
    extcap_interfaces: bool,

    /// Second step in the extcap exchange: this program is asked for the configuration of each
    /// specific interface
    /// ```sh
    /// $ extcap_example.py --extcap-interface <iface> --extcap-config
    /// ```
    ///
    /// Each interface can have custom options that are valid for this interface only. Those config
    /// options are specified on the command line when running the actual capture. To allow an
    /// end-user to specify certain options, such options may be provided using the extcap config
    /// argument.
    ///
    /// To share which options are available for an interface, the extcap responds to the command
    /// `--extcap-config`, which shows all the available options (aka additional command line
    /// options).
    ///
    /// Those options are used to build a configuration dialog for the interface.
    #[arg(long, verbatim_doc_comment)]
    extcap_config: bool,

    /// The extcap interface to perform [capture] or [extcap_config] operations on. This should
    /// match one of the values returned earlier in [extcap-interfaces].
    #[arg(long)]
    extcap_interface: Option<String>,

    /// Specifies the fifo for the packet captures. The extcap implementation should write the
    /// captured packets to this fifo in pcap or pcapng format.
    #[arg(long, requires = "capture")]
    fifo: Option<String>,

    /// The capture filter provided by wireshark. This extcap should avoid capturing packets that do
    /// not match this filter.
    #[arg(long, requires = "capture")]
    extcap_capture_filter: Option<String>,

    /// Third step in the extcap exchange: the extcap binary is queried for all valid DLTs for all
    /// the interfaces returned by step 1 ([extcap_interfaces]).
    ///
    /// ```sh
    /// $ extcap_example.py --extcap-dlts --extcap-interface <iface>
    /// ```
    ///
    /// This call must print the valid DLTs for the interface specified. This call is made for all
    /// the interfaces and must return exit code 0.
    ///
    /// Example for the DLT query.
    /// ```sh
    /// $ extcap_example.py --extcap-interface IFACE --extcap-dlts
    /// dlt {number=147}{name=USER1}{display=Demo Implementation for Extcap}
    /// ```
    ///
    /// A binary or script which neither provides an interface list or a DLT list will not show up
    /// in the extcap interfaces list.
    #[arg(long, requires = "extcap_interface", verbatim_doc_comment)]
    extcap_dlts: bool,

    /// Specify the path to the btsnoop log file on the device to stream from. For a special value
    /// with the format "local:<path>", the log file will be read locally on the host device
    /// instead.
    #[arg(long)]
    btsnoop_log_file_path: Option<String>,

    /// Specify the path to the ADB executable, or "mock" for a special mock implementation used
    /// for testing.
    #[arg(long)]
    adb_path: Option<String>,
}

const SENT: [u8; 4] = 0_u32.to_be_bytes();
const RECEIVED: [u8; 4] = 1_u32.to_be_bytes();

const HCI_PACKET_TYPE_COMMAND: u8 = 0x01;
const HCI_PACKET_TYPE_SYNCHRONOUS_DATA: u8 = 0x02;
const HCI_PACKET_TYPE_ASYNC_DATA: u8 = 0x03;
const HCI_PACKET_TYPE_EVENT: u8 = 0x04;
const HCI_PACKET_TYPE_EXTENDED_COMMAND: u8 = 0x09;

fn get_direction(payload: &[u8]) -> anyhow::Result<[u8; 4]> {
    // Check the HCI packet type header to determine the direction
    // Additional reference for format inside of the payload: https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_sdk/1.60.00.29_new/exports/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html#specification-interface
    Ok(match payload[0] {
        HCI_PACKET_TYPE_COMMAND => SENT,
        HCI_PACKET_TYPE_SYNCHRONOUS_DATA | HCI_PACKET_TYPE_ASYNC_DATA => {
            // Check the "PB Flag" for the direction. This is taken from Wireshark's androiddump.c,
            // even though it doesn't seem to exactly match the BT specs.
            // See 5.4.2 HCI ACL Data Packets in Specification of the Bluetooth System, v4.2
            if payload[2] & 0x20 == 0 {
                SENT
            } else {
                RECEIVED
            }
        }
        HCI_PACKET_TYPE_EVENT => RECEIVED,
        HCI_PACKET_TYPE_EXTENDED_COMMAND => Err(anyhow!("Extended Command (0x09) not supported"))?,
        _ => Err(anyhow!("Unknown payload header {}", payload[0]))?,
    })
}

fn print_packets_impl<W: Write, R: Read>(
    mut input_reader: R,
    output_writer: W,
) -> anyhow::Result<()> {
    let mut header_buf = [0_u8; FileHeader::LENGTH];
    let mut pcap_header = PcapHeader {
        datalink: DataLink::BLUETOOTH_HCI_H4_WITH_PHDR,
        ..Default::default()
    };
    pcap_header.set_endianness(pcap_file::Endianness::Big);
    input_reader.read_exact(&mut header_buf[..])?;
    FileHeader::parse(&header_buf).unwrap();
    let mut pcap_writer = PcapWriter::with_header(pcap_header, output_writer).unwrap();
    loop {
        let mut packet_header_buf = [0_u8; PacketHeader::LENGTH];
        let bytes_read = input_reader.read(&mut packet_header_buf[..])?;
        if bytes_read == 0 {
            break;
        }
        assert_eq!(bytes_read, PacketHeader::LENGTH);
        let (_rem, packet_header) = PacketHeader::parse(&packet_header_buf).unwrap();
        let mut packet_buf: Vec<u8> = vec![0_u8; packet_header.included_length as usize];
        input_reader.read_exact(&mut packet_buf)?;
        let tv = packet_header.timestamp_tv();
        pcap_writer.write(
            tv.sec.try_into().unwrap(),
            tv.usec.try_into().unwrap(),
            &[&get_direction(&packet_buf).unwrap(), &packet_buf[..]].concat(),
            packet_header.original_length + 4,
        )?;
    }
    Ok(())
}

fn print_packets(
    serial: &str,
    output_fifo: &str,
    btsnoop_log_file_path: &Option<String>,
) -> anyhow::Result<()> {
    let writer = File::create(output_fifo)?;
    let btsnoop_log_file_path = btsnoop_log_file_path
        .as_deref()
        .unwrap_or("/data/misc/bluetooth/logs/btsnoop_hci.log");
    if let Some(test_file) = btsnoop_log_file_path.strip_prefix("local:") {
        print_packets_impl(File::open(test_file)?, writer)
    } else {
        // TODO: Add warning if the adb device is not rooted, or HCI log is not enabled
        let mut cmd = Command::new("adb")
            .args([
                "-s",
                serial,
                "shell",
                format!("tail -f -c +0 {btsnoop_log_file_path}").as_str(),
            ])
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = cmd.stdout.as_mut().unwrap();
        print_packets_impl(stdout, writer)
    }
}

struct AdbDevice {
    serial: String,
    display_name: String,
}

/// Query `adb devices` for the list of devices, and return a vec of [AdbDevic] structs.
fn adb_devices(adb_path: Option<String>) -> anyhow::Result<Vec<AdbDevice>> {
    let adb_path = adb_path.as_deref().unwrap_or("adb");
    if adb_path == "mock" {
        return Ok(mock_adb_devices());
    }
    let cmd = Command::new("adb")
        .arg("devices")
        .arg("-l")
        .stdout(Stdio::piped())
        .spawn()?;
    let output = cmd.wait_with_output()?;
    let re = regex::Regex::new(r"([a-zA-Z0-9]+)\s+device.*model:([^ ]+).*")?;
    Ok(output
        .stdout
        .lines()
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

fn main() -> anyhow::Result<()> {
    let args = ExtcapArgs::parse();
    if args.extcap_interfaces {
        println!("extcap {{version={}}}", env!("CARGO_PKG_VERSION"));
        for d in adb_devices(args.adb_path)?.iter() {
            println!(
                "interface {{value=btsnoop-{}}}{{display=BTsnoop {} {}}}",
                d.serial, d.display_name, d.serial
            );
        }
        Ok(())
    } else if args.capture {
        let interface = args.extcap_interface.unwrap();
        let fifo = args.fifo.unwrap();
        assert!(
            interface.starts_with("btsnoop-"),
            "Interface must start with \"btsnoop-\""
        );
        let serial = interface.split('-').nth(1).unwrap();
        print_packets(serial, &fifo, &args.btsnoop_log_file_path)?;
        Ok(())
    } else if args.extcap_config || args.extcap_dlts {
        println!("dlt {{number=99}}{{name=BluetoothH4}}{{display=Bluetooth HCI UART transport layer plus pseudo-header}}");
        Ok(())
    } else {
        ExtcapArgs::command().print_help().unwrap();
        Err(anyhow::format_err!("Missing command"))
    }
}
