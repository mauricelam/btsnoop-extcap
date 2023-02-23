use clap::{CommandFactory, Parser, ValueEnum};
use log::debug;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink,
};
use rust_extcap::{
    config::{ArgValue, ConfigContainer, MultiCheckValue, BoolFlagConfig},
    dlt::Dlt,
    interface::{
        BooleanControl, ButtonControl, Control, ControlValue, ControlWithLabel, EnableableControl,
        HelpControl, LoggerControl, RestoreControl, SelectorControl, StringControl,
    },
    threaded::{ExtcapControl, ExtcapControlReader, ExtcapControlSenderTrait},
    ControlCommand,
};
use std::{
    fmt::Display,
    fs::File,
    io::{stdout, Write},
    ops::DerefMut,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH}, mem::Discriminant,
};

pub enum Exit {
    Usage = 0,
    ErrorArg = 1,
    ErrorInterface = 2,
    ErrorFifo = 3,
    ErrorDelay = 4,
}

impl Exit {
    fn exit(self) -> ! {
        std::process::exit(self as i32)
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Remote {
    If1,
    If2,
    If3,
    If4,
}

impl Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_possible_value().unwrap().get_name())
    }
}

fn control_write_defaults(
    extcap_control: &mut rust_extcap::threaded::ExtcapControl,
    message: &str,
    delay: u8,
    verify: bool,
) {
    // TODO: Wait for initial control values
    CTRL_MESSAGE.set_value(extcap_control, message);
    CTRL_BUTTON.set_label(extcap_control, &delay.to_string());
    CTRL_VERIFY.set_checked(extcap_control, verify);

    for i in 1..16 {
        CTRL_DELAY.add_value(extcap_control, &i.to_string(), &format!("{i} sec"));
    }
    CTRL_DELAY.remove_value(extcap_control, "60");
}

#[derive(Debug, Parser)]
struct AppArgs {
    #[command(flatten)]
    extcap: rust_extcap::ExtcapArgs,

    /// Demonstrates a verification bool flag
    #[arg(long)]
    verify: bool,

    /// Demonstrates an integer variable
    #[arg(long, default_value_t = 5)]
    delay: u8,

    /// Demonstrates a selector choice
    #[arg(long, value_enum, default_value_t = Remote::If1)]
    remote: Remote,

    /// Demonstrates string variable
    #[arg(long, default_value = "Extcap Test")]
    message: String,

    /// Add a fake sender IP address
    #[arg(long, default_value = "127.0.0.1")]
    fake_ip: String,

    /// Capture start time
    #[arg(long, value_parser = |arg: &str| arg.parse().map(std::time::Duration::from_secs))]
    ts: Option<Duration>,

    #[arg(long)]
    ltest: Option<String>,
    #[arg(long)]
    d1test: Option<String>,
    #[arg(long)]
    d2test: Option<String>,
    #[arg(long)]
    radio: Option<String>,
    #[arg(long)]
    multi: Option<String>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    debug!("argv: {:?}", std::env::args());
    let args = AppArgs::parse();
    debug!("Args: {args:?}");
    if !args.extcap.extcap_interfaces && args.extcap.extcap_interface.is_none() {
        eprintln!("An interface must be provided or the selection must be displayed");
        Exit::ErrorArg.exit();
    }
    if !args.extcap.capture {
        if let Some(filter) = args.extcap.extcap_capture_filter {
            validate_capture_filter(&filter);
            std::process::exit(0);
        }
    }
    if args.extcap.extcap_interfaces || args.extcap.extcap_interface.is_none() {
        extcap_interfaces();
        std::process::exit(0);
    }

    let re = regex::Regex::new(r"rs-example(\d+)")?;
    if let Some(interface_full) = args.extcap.extcap_interface {
        if let Some(cap) = re.captures(&interface_full) {
            let interface = cap.get(1).map_or("", |m| m.as_str());
            if args.extcap.extcap_config {
                extcap_config(interface, args.extcap.extcap_reload_option);
            } else if args.extcap.extcap_dlts {
                extcap_dlts(interface);
            } else if args.extcap.capture {
                let fifo = args.extcap.fifo.unwrap_or_else(|| Exit::ErrorFifo.exit());
                if args.delay > 5 {
                    eprintln!("Value for delay {} too high", args.delay);
                    // Close the fifo to signal to prevent wireshark from blocking
                    drop(File::open(fifo));
                    Exit::ErrorDelay.exit();
                }
                extcap_capture(
                    interface,
                    &fifo,
                    args.extcap.extcap_control_in,
                    args.extcap.extcap_control_out,
                    args.delay,
                    args.verify,
                    args.message,
                    args.remote,
                    args.fake_ip,
                );
            } else {
                AppArgs::command().print_help()?;
                Exit::Usage.exit();
            }
        } else {
            Exit::ErrorInterface.exit();
        }
    }

    Ok(())
}

fn control_read_thread(
    extcap_control_in: &mut ExtcapControlReader,
    extcap_control_out: &Mutex<ExtcapControl>,
    initialized: &mut bool,
    message: &Mutex<String>,
    delay: &mut u8,
    verify: &mut bool,
    button: &mut bool,
    button_disabled: &mut bool,
) -> anyhow::Result<()> {
    loop {
        let control_packet = extcap_control_in.read_control_packet()?;
        debug!("Read control packet: {control_packet:?}");
        if control_packet.control_number == 0 {
            // TODO: Not sure when this is sent, logic copied from the Python impl
            debug!("Control number is 0. break");
            break;
        }
        let mut log: Option<String> = None;
        match control_packet.command {
            ControlCommand::Initialized => *initialized = true,
            ControlCommand::Set => {
                if control_packet.control_number == CTRL_MESSAGE.control_number {
                    let msg = String::from_utf8(control_packet.payload.to_vec())?;
                    log = Some(format!("Message = {}", msg));
                    *message.lock().unwrap() = msg;
                } else if control_packet.control_number == CTRL_DELAY.control_number {
                    *delay = std::str::from_utf8(control_packet.payload.as_ref())?
                        .parse::<u8>()
                        .unwrap();
                    log = Some(format!("Time delay = {}", *delay));
                } else if control_packet.control_number == CTRL_VERIFY.control_number {
                    // Only read this after initialized
                    if *initialized {
                        *verify = control_packet.payload[0] != 0_u8;
                        log = Some(format!("Verify = {verify:?}"));
                        extcap_control_out
                            .lock()
                            .unwrap()
                            .status_message("Verify changed");
                    }
                } else if control_packet.control_number == CTRL_BUTTON.control_number {
                    let mut extcap_control = extcap_control_out.lock().unwrap();
                    CTRL_BUTTON.set_enabled(&mut extcap_control, false);
                    debug!("Got button control event. button={button}");
                    *button_disabled = true;
                    // TODO: Fix "Turn on" button doesn't work
                    if *button {
                        let mut extcap_control = extcap_control_out.lock().unwrap();
                        CTRL_BUTTON.set_label(&mut extcap_control, "Turn on");
                        *button = false;
                        log = Some(String::from("Button turned off"));
                    } else {
                        let mut extcap_control = extcap_control_out.lock().unwrap();
                        CTRL_BUTTON.set_label(&mut extcap_control, "Turn off");
                        *button = true;
                        log = Some(String::from("Button turned on"));
                    }
                } else {
                    panic!(
                        "Unexpected control number {}",
                        control_packet.control_number
                    )
                }
            }
            _ => panic!("Unexpected control command {:?}", control_packet.command),
        }
        if let Some(log) = log {
            let mut extcap_control = extcap_control_out.lock().unwrap();
            CTRL_LOGGER.add_log_entry(&mut extcap_control, &format!("{}\n", log));
        }
        debug!("Read control packet Loop end");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn extcap_capture(
    _interface: &str,
    fifo: &std::path::Path,
    extcap_control_in: Option<std::path::PathBuf>,
    extcap_control_out: Option<std::path::PathBuf>,
    mut delay: u8,
    mut verify: bool,
    message: String,
    remote: Remote,
    fake_ip: String,
) {
    let mut button_disabled = false;
    let mut counter = 1;
    let message = Mutex::new(message);
    const DATA: &[u8] = b"\
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor \
incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nost \
rud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis \
aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugi \
at nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culp \
a qui officia deserunt mollit anim id est laborum.";

    let mut extcap_control_in = extcap_control_in.map(|p| ExtcapControlReader::new(&p));
    let extcap_control_out = extcap_control_out.map(|p| Mutex::new(ExtcapControl::new(&p)));
    std::thread::scope(|s| {
        let mut initialized = false;
        let mut button = false;
        if let (Some(in_pipe), Some(out_pipe)) =
            (extcap_control_in.as_mut(), extcap_control_out.as_ref())
        {
            let mut extcap_control = out_pipe.lock().unwrap();
            CTRL_LOGGER.set_log_entry(
                &mut extcap_control,
                &format!("Log started at {:?}\n", SystemTime::now()),
            );
            control_write_defaults(
                out_pipe.lock().unwrap().deref_mut(),
                &message.lock().unwrap().clone(),
                delay,
                verify,
            );
            let message_ref = &message;
            s.spawn(move || {
                control_read_thread(
                    in_pipe,
                    out_pipe,
                    &mut initialized,
                    message_ref,
                    &mut delay,
                    &mut verify,
                    &mut button,
                    &mut button_disabled,
                )
                .unwrap()
            });
        }

        let fh = File::create(fifo).unwrap();
        let pcap_header = PcapHeader {
            datalink: DataLink::ETHERNET,
            endianness: pcap_file::Endianness::Big,
            ..Default::default()
        };
        let mut pcap_writer = PcapWriter::with_header(fh, pcap_header).unwrap();
        let mut data_packet = 0;
        let data_total = DATA.len() / 20 + 1;

        for i in 0..usize::MAX {
            if let Some(out_pipe) = extcap_control_out.as_ref() {
                let mut extcap_control = out_pipe.lock().unwrap();
                CTRL_LOGGER.add_log_entry(
                    &mut extcap_control,
                    &format!("Received packet #{counter}\n"),
                );
                counter += 1;

                debug!("Extcap out control. btn disabled = {button_disabled}");

                if button_disabled {
                    CTRL_BUTTON.set_enabled(&mut extcap_control, true);
                    out_pipe
                        .lock()
                        .unwrap()
                        .info_message("Turn action finished.");
                    button_disabled = false;
                }
            }

            if data_packet * 20 > DATA.len() {
                data_packet = 0;
            }
            let data_sub = &DATA[data_packet * 20..(data_packet + 1) * 20];
            data_packet += 1;
            let out = create_out_packet(
                remote,
                data_packet,
                data_total,
                data_sub,
                message.lock().unwrap().as_bytes(),
                verify,
            );
            let packet = pcap_fake_packet(&out, &fake_ip, i);

            pcap_writer
                .write_packet(&PcapPacket::new(
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
                    (packet.len() + 14 + 20) as u32,
                    &packet,
                ))
                .unwrap();
            stdout().flush().unwrap();
            std::thread::sleep(Duration::from_secs(delay.into()));
        }
    });
}

fn create_out_packet(
    remote: Remote,
    data_packet: usize,
    data_total: usize,
    data_sub: &[u8],
    message: &[u8],
    verify: bool,
) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let remote_str = remote.to_string();
    result.push(remote_str.len() as u8);
    result.extend_from_slice(remote_str.as_bytes());
    result.push(data_packet as u8);
    result.push(data_total as u8);
    result.push(data_sub.len() as u8);
    result.extend_from_slice(data_sub);
    result.push(message.len() as u8);
    result.extend_from_slice(message);
    result.push(u8::from(verify));
    result
}

fn pcap_fake_packet(message: &[u8], fake_ip: &str, iterate_counter: usize) -> Vec<u8> {
    let mut result = Vec::<u8>::new();

    // ETH
    let mut dest_value = 0x2900_u16;
    let mut src_value = 0x3400_u16;
    if iterate_counter % 2 == 0 {
        std::mem::swap(&mut dest_value, &mut src_value);
    }

    result.extend_from_slice(&dest_value.to_le_bytes());
    result.extend_from_slice(&dest_value.to_le_bytes());
    result.extend_from_slice(&dest_value.to_le_bytes());
    result.extend_from_slice(&src_value.to_le_bytes());
    result.extend_from_slice(&src_value.to_le_bytes());
    result.extend_from_slice(&src_value.to_le_bytes());
    result.extend_from_slice(&8_u16.to_le_bytes()); // protocol (ip)

    result.push(0x45_u8); // IP version
    result.push(0);
    result.extend_from_slice(&((message.len() + 20) as u16).to_be_bytes());
    result.extend_from_slice(&0_u16.to_be_bytes()); // Identification
    result.push(0x40); // Don't fragment
    result.push(0); // Fragment offset
    result.push(0x40_u8);
    result.push(0xFE_u8); // (2 = unspecified)
    result.extend_from_slice(&0_u16.to_be_bytes()); // Checksum

    let parts: Vec<u8> = fake_ip
        .split('.')
        .map(|p| p.parse::<u8>().unwrap())
        .collect();
    result.extend_from_slice(&parts);
    result.extend_from_slice(&[0x7f, 0x00, 0x00, 0x01]); // Dest IP

    result.extend_from_slice(message);

    result
}

fn extcap_dlts(interface: &str) {
    match interface {
        "1" => Dlt {
            data_link_type: DataLink::USER0,
            name: "USER0",
            display: "Demo Implementation for Extcap",
        }
        .print_config(),
        "2" => Dlt {
            data_link_type: DataLink::USER1,
            name: "USER1",
            display: "Demo Implementation for Extcap",
        }
        .print_config(),
        _ => panic!("Unexpected interface {interface}"),
    }
}

fn extcap_config(_interface: &str, extcap_reload_option: Option<String>) {
    let mut configs = ConfigContainer::default();
    configs.integer(|b| {
        b
            .call("--delay")
            .display("Time delay")
            .tooltip("Time delay between packages")
            .range(1..15)
            .default_value(5)
    });
    configs.string(|b| {
        b
            .call("--message")
            .display("Message")
            .tooltip("Package message content")
            .required(true)
            .placeholder("Please enter a message here ...")
    });
    configs.bool_flag(|b| {
        b.call("--verify")
            .display("Verify")
            .tooltip("Verify package content")
            .default_value(true)
    });
    let remote_control = configs.selector(|b| {
        b.call("--remote")
            .display("Remote Channel")
            .tooltip("Remote Channel Selector")
            .placeholder("Load interfaces ...")
            .reload(true)
            .options([
                ArgValue::builder()
                    .value("if1")
                    .display("Remote1")
                    .default(true)
                    .build(),
                ArgValue::builder().value("if2").display("Remote2").build(),
            ])
    });
    configs.string(|b| b.call("--fake_ip")
        .display("Fake IP Address")
        .tooltip( "Use this ip address as sender")
        .validation(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"));
    configs.long(|b| {
        b.call("--ltest")
            .display("Long Test")
            .tooltip("Long Test Value")
            .default_value(123123123123123123)
            .group("Numeric Values")
    });
    configs.double(|b| {
        b.call("--d1test")
            .display("Double 1 Test")
            .tooltip("Double Test Value")
            .default_value(123.456)
            .group("Numeric Values")
    });
    configs.double(|b| {
        b.call("--d2test")
            .display("Double 2 Test")
            .tooltip("Double Test Value")
            .default_value(123456.0)
            .group("Numeric Values")
    });
    configs.password(|b| {
        b.call("--password")
            .display("Password")
            .tooltip("Package message password")
    });
    configs.timestamp(|b| {
        b.call("--ts")
            .display("Start Time")
            .tooltip("Capture start time")
            .group("Time / Log")
    });
    configs.file_select(|b| {
        b.call("--logfile")
            .display("Log File Test")
            .tooltip("The Log File Test")
            .group("Time / Log")
    });
    let radio_control = configs.radio(|b| {
        b.call("--radio")
            .display("Radio Test")
            .tooltip("Radio Test Value")
            .group("Selection")
            .options([
                ArgValue::builder().value("r1").display("Radio1").build(),
                ArgValue::builder()
                    .value("r2")
                    .display("Radio2")
                    .default(true)
                    .build(),
            ])
    });
    configs.multi_check(|b| {
        b.call("--multi")
            .display("MultiCheck Test")
            .tooltip("MultiCheck Test Value")
            .group("Selection")
            .options([
                MultiCheckValue::builder()
                    .value("m1")
                    .display("Checkable Parent 1")
                    .children([
                        MultiCheckValue::builder()
                            .value("m1c1")
                            .display("Checkable Child 1")
                            .children([MultiCheckValue::builder()
                                .value("m1c1g1")
                                .display("UncheckableGranchild")
                                .enabled(false)
                                .build()])
                            .build(),
                        MultiCheckValue::builder()
                            .value("m1c2")
                            .display("Checkable Child 2")
                            .build(),
                    ])
                    .build(),
                MultiCheckValue::builder()
                    .value("m2")
                    .display("Checkable Parent 2")
                    .children([
                        MultiCheckValue::builder()
                            .value("m2c1")
                            .display("Checkable Child 1")
                            .children([MultiCheckValue::builder()
                                .value("m2c1g1")
                                .display("CheckableGranchild")
                                .build()])
                            .build(),
                        MultiCheckValue::builder()
                            .value("m2c2")
                            .display("Uncheckable Child 2")
                            .enabled(false)
                            .children([MultiCheckValue::builder()
                                .value("m2c2g1")
                                .display("Uncheckable Granchild")
                                .enabled(false)
                                .build()])
                            .build(),
                    ])
                    .build(),
            ])
    });
    match extcap_reload_option.as_deref() {
        Some("remote") => {
            ArgValue::builder()
                .value("if1")
                .display("Remote Interface 1")
                .build()
                .print_config(remote_control);
            ArgValue::builder()
                .value("if2")
                .display("Remote Interface 2")
                .default(true)
                .build()
                .print_config(remote_control);
            ArgValue::builder()
                .value("if3")
                .display("Remote Interface 3")
                .build()
                .print_config(remote_control);
            ArgValue::builder()
                .value("if4")
                .display("Remote Interface 4")
                .build()
                .print_config(remote_control);
        }
        Some("radio") => {
            // TODO: `reload` is not specified in the "radio" control??
            ArgValue::builder()
                .value("r1")
                .display("Radio Option 1")
                .build()
                .print_config(radio_control);
            ArgValue::builder()
                .value("r2")
                .display("Radio Option 2")
                .build()
                .print_config(radio_control);
            ArgValue::builder()
                .value("r3")
                .display("Radio Option 3")
                .default(true)
                .build()
                .print_config(radio_control);
        }
        None => {
            
            configs.print_configs();
        }
        _ => panic!("No other possible values?"),
    }
}

const CTRL_MESSAGE: StringControl<&str> = StringControl {
    control_number: 0,
    display: "Message",
    tooltip: Some("Package message content. Must start with a capital letter."),
    placeholder: Some("Enter package message content here ..."),
    validation: Some(r"^[A-Z]+"),
};

const CTRL_DELAY: SelectorControl<&str> = SelectorControl {
    control_number: 1,
    display: "Time delay",
    tooltip: Some("Time delay between packets"),
    options: &[
        ControlValue::new("1", "1"),
        ControlValue::new("2", "2"),
        ControlValue::new("3", "3"),
        ControlValue::new("4", "4"),
        ControlValue::new_default("5", "5"),
        ControlValue::new("60", "60"),
    ],
};

const CTRL_VERIFY: BooleanControl<&str> = BooleanControl {
    control_number: 2,
    display: "Verify",
    tooltip: Some("Verify package control"),
};

const CTRL_BUTTON: ButtonControl<&str> = ButtonControl {
    control_number: 3,
    display: "Turn on",
    tooltip: Some("Turn on or off"),
};
const CTRL_HELP: HelpControl<&str> = HelpControl {
    control_number: 4,
    display: "Help",
    tooltip: Some("Show help"),
};
const CTRL_RESTORE: RestoreControl<&str> = RestoreControl {
    control_number: 5,
    display: "Restore",
    tooltip: Some("Restore default values"),
};
const CTRL_LOGGER: LoggerControl<&str> = LoggerControl {
    control_number: 6,
    display: "Log",
    tooltip: Some("Show capture log"),
};

fn extcap_interfaces() {
    rust_extcap::interface::Metadata {
        version: "1.0",
        help_url: "http://www.wireshark.org",
        display_description: "Rust Example extcap interface",
    }
    .print_config();
    rust_extcap::interface::Interface {
        value: "rs-example1",
        display: "Rust Example interface 1 for extcap",
    }
    .print_config();
    rust_extcap::interface::Interface {
        value: "rs-example2",
        display: "Rust Example interface 2 for extcap",
    }
    .print_config();
    CTRL_MESSAGE.print_config();
    CTRL_DELAY.print_config();
    CTRL_VERIFY.print_config();
    CTRL_BUTTON.print_config();
    CTRL_HELP.print_config();
    CTRL_RESTORE.print_config();
    CTRL_LOGGER.print_config();
}

fn validate_capture_filter(filter: &str) {
    if filter != "filter" && filter != "valid" {
        println!("Illegal capture filter");
    }
}

#[test]
fn test_parse() {
    AppArgs::command().debug_assert();
}
