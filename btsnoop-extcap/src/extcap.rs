//! Utilities for working with the extcap interface. The extcap interface is a
//! versatile plugin interface used by Wireshark to allow external binaries to
//! act as capture interfaces.
//!
//! References:
//! * <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html>
//! * <https://www.wireshark.org/docs/man-pages/extcap.html>
//! * <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py>

use crate::util::AsyncReadExt as _;
use anyhow::anyhow;
use async_trait::async_trait;
use clap::Args;
use log::{debug, warn};
use nom::number::complete::be_u24;
use nom_derive::{Nom, Parse};
use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

/// The arguments defined by extcap. These arguments are usable as a clap
/// parser.
///
/// For example, if you use `clap` with the feature `derive`:
/// ```
/// #[derive(Debug, Parser)]
/// #[command(author, version, about)]
/// pub struct ApplicationArgs {
///    #[command(flatten)]
///    extcap: extcap::ExtcapArgs,
///
///    // Other application args
/// }
/// ```
///
/// Wireshark will call extcap in 4 phases:
///
/// 1. [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces]: Declare all
///    supported interfaces and controls.
/// 2. [`--extcap-config`][ExtcapArgs::extcap_config]: Called for each interface
///    to declare configuration options that can be changed by the user in the
///    UI. (This is used only in Wireshark, not available in tshark).
/// 3. [`--extcap-dlts`][ExtcapArgs::extcap_dlts]: Called for each interface
///    returned in `--extcap-interfaces` to specify which Data Link Type is
///    being captured.
/// 4. [`--capture`][ExtcapArgs::capture]: Called to initiate capture of the
///    packets. See the documentation on the field for details.
///
/// When the capturing stops (i.e. the user presses the red Stop button),
/// `SIGTERM` is sent by Wireshark.
#[derive(Debug, Args)]
pub struct ExtcapArgs {
    /// First step in the extcap exchange: this program is queried for its
    /// interfaces.
    /// ```sh
    /// $ extcapbin --extcap-interfaces
    /// ```
    /// This call must print the existing interfaces for this extcap and must
    /// return 0. The output must conform to the grammar specified in the
    /// [doc/extcap.4](https://www.wireshark.org/docs/man-pages/extcap.html)
    /// man pages.
    #[arg(long, verbatim_doc_comment)]
    pub extcap_interfaces: bool,

    /// The version of Wireshark (or tshark) calling into this extcap.
    ///
    /// Wireshark 2.9 and later pass `--extcap-version=x.x` when querying for
    /// the list of interfaces, which provides the calling Wireshark's major and
    /// minor version. This can be used to change behavior depending on the
    /// Wireshark version in question.
    ///
    /// This argument is passed during the
    /// [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces] call.
    #[arg(long)]
    pub extcap_version: Option<String>,

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
    pub extcap_config: bool,

    /// Third step in the extcap exchange: the extcap binary is queried for all valid DLTs for all
    /// the interfaces returned during [`--extcap-interfaces`][Self::extcap_interfaces]).
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
    pub extcap_dlts: bool,

    /// Start the capturing phase.
    ///
    /// In addition to `--capture`, the
    /// [`--extcap-capture-filter`][ExtcapArgs::extcap_capture_filter] and
    /// [`--fifo`][ExtcapArgs::fifo] options are also required in this phase.
    ///
    /// Additionally, if `{config}` entries were returned during the
    /// `--extcap-interfaces` phase, then
    /// [`--extcap-control-in`][ExtcapArgs::extcap_control_in] and
    /// [`--extcap-control-out`][ExtcapArgs::extcap_control_out] will be passed,
    /// which are a pair of fifos in which [control
    /// messages](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#_messages)
    /// are sent.
    #[arg(long, requires = "fifo", requires = "extcap_interface")]
    pub capture: bool,

    /// The extcap interface to perform the operation on.
    ///
    /// This should match one of the values returned earlier in
    /// [`extcap_interfaces`][Self::extcap_interfaces], and is used in the
    /// [`capture`][Self::capture], [`extcap_config`][Self::extcap_config], and
    /// [`extcap_dlts`][Self::extcap_dlts] phases.
    #[arg(long)]
    pub extcap_interface: Option<String>,

    /// Specifies the fifo for the packet captures. The extcap implementation
    /// should write the captured packets to this fifo in pcap or pcapng format.
    #[arg(long, requires = "capture")]
    pub fifo: Option<PathBuf>,

    /// The capture filter provided by wireshark. This extcap should avoid capturing packets that do
    /// not match this filter. Used during the `--capture` phase.
    #[arg(long, requires = "capture")]
    pub extcap_capture_filter: Option<String>,

    /// Used to get control messages from toolbar. Control messages are in the
    /// format documented in [`ControlPacket`].
    #[arg(long, requires = "capture")]
    pub extcap_control_in: Option<PathBuf>,

    /// Used to send control messages to toolbar. Control messages are in the
    /// format documented in [`ControlPacket`].
    #[arg(long, requires = "capture")]
    pub extcap_control_out: Option<PathBuf>,
}

/// Control packets for the extcap interface. This is used for communication of
/// control data between Wireshark and this extcap program.
///
/// Reference:
/// <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#_messages>
#[derive(Debug, Nom, Clone, PartialEq, Eq)]
pub struct ControlPacket<'a> {
    /// The common sync pipe indication. This protocol uses the value "T".
    #[nom(Verify = "*sync_pipe_indication == b'T'")]
    pub sync_pipe_indication: u8,
    /// Length of `payload` + 2 bytes for `control_number` and `command`.
    #[nom(Parse = "be_u24")]
    pub message_length: u32,
    /// Unique number to identify the control, as previously returned in the
    /// `{control}` declarations returned in the
    /// [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces] phase. This
    /// number also gives the order of the controls in the interface toolbar.
    pub control_number: u8,
    /// The command associated with this packet. See [`ControlCommand`] for
    /// details.
    pub command: ControlCommand,
    /// Payload specific to the [`command`][Self::command]. For example, the
    /// payload for [`StatusbarMessage`][ControlCommand::StatusbarMessage] is
    /// the message string.
    #[nom(Map = "Cow::from", Take = "(message_length - 2) as usize")]
    pub payload: Cow<'a, [u8]>,
}

impl<'a> ControlPacket<'a> {
    pub fn new(control_number: u8, command: ControlCommand, payload: &'a [u8]) -> Self {
        ControlPacket {
            sync_pipe_indication: b'T',
            message_length: (payload.len() + 2) as u32,
            control_number,
            command,
            payload: Cow::from(payload),
        }
    }

    /// Outputs the serialzied bytes of the header to send back to wireshark.
    pub fn to_header_bytes(&self) -> [u8; 6] {
        let mut bytes = [0_u8; 6];
        bytes[0] = self.sync_pipe_indication;
        bytes[1..4].copy_from_slice(&self.message_length.to_be_bytes()[1..]);
        bytes[4] = self.control_number;
        bytes[5] = self.command as u8;
        bytes
    }

    /// Turns the given ControlPacket into a ControlPacket with fully owned data
    /// and 'static lifetime.
    pub fn into_owned(self) -> ControlPacket<'static> {
        match self.payload {
            Cow::Borrowed(v) => ControlPacket {
                payload: Cow::Owned(v.to_vec()),
                ..self
            },
            Cow::Owned(v) => ControlPacket {
                payload: Cow::Owned(v),
                ..self
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Nom)]
#[repr(u8)]
pub enum ControlCommand {
    /// Sent by Wireshark to indicate that this extcap has been initialized and
    /// is ready to accept packets.
    ///
    /// Control type: None
    Initialized = 0,
    /// Either sent by Wireshark to indicate that the user has interacted with
    /// one of the controls, or sent by the extcap program to change the value
    /// on a given control.
    ///
    /// Control type: boolean / button / logger / selector / string
    Set = 1,
    /// Sent by the extcap program to add a value to the given logger or
    /// selector.
    ///
    /// Control type: logger / selector
    Add = 2,
    /// Sent by the extcap program to remove a value from the given selector.
    ///
    /// Control type: selector
    Remove = 3,
    /// Sent by the extcap program to enable a given control.
    ///
    /// Control type: boolean / button / selector / string
    Enable = 4,
    /// Sent by the extcap program to disable a given control.
    ///
    /// Control type: boolean / button / selector / string
    Disable = 5,
    /// Sent by the extcap program to show a message in the status bar.
    ///
    /// Control type: None
    StatusbarMessage = 6,
    /// Sent by the extcap program to show a message in an information dialog
    /// popup.
    ///
    /// Control type: None
    InformationMessage = 7,
    /// Sent by the extcap program to show a message in a warning dialog popup.
    ///
    /// Control type: None
    WarningMessage = 8,
    /// Sent by the extcap program to show a message in an error dialog popup.
    ///
    /// Control type: None
    ErrorMessage = 9,
}

/// Manager for the extcap control pipes. The control pipes are a pair of FIFOs, one incoming and
/// one outgoing, and used to control extra functionalities, mostly UI-related, with Wireshark.
///
/// This class manages the serialization and deserialization of the control packets, and dispatches
/// them onto Tokio channels, so that functions running on other tasks can subcribe to and emit
/// those control packets.
///
/// See <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html> for details.
pub struct ExtcapControl {
    in_path: PathBuf,
    out_path: PathBuf,
    in_tx: tokio::sync::broadcast::Sender<ControlPacket<'static>>,
    out_tx: mpsc::Sender<ControlPacket<'static>>,
    out_rx: mpsc::Receiver<ControlPacket<'static>>,
}

impl ExtcapControl {
    /// Subscribe to new incoming control packets.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ControlPacket<'static>> {
        self.in_tx.subscribe()
    }

    /// Monitors the given tokio channel for control packets, and forwards the
    /// serialized bytes onto `out_file`.
    async fn mon_output_pipe(
        rx: &mut mpsc::Receiver<ControlPacket<'static>>,
        mut out_file: File,
    ) -> anyhow::Result<()> {
        while let Some(packet) = rx.recv().await {
            debug!("Got outgoing control packet: {packet:?}");
            out_file.write_all(&packet.to_header_bytes()).await?;
            out_file.write_all(&packet.payload).await?;
            out_file.flush().await?;
            debug!("Packet written and flushed");
        }
        Ok(())
    }

    /// Read one control packet from the given input file.
    async fn read_control_packet(in_file: &mut File) -> anyhow::Result<ControlPacket<'static>> {
        let header_bytes = in_file
            .try_read_exact::<6>()
            .await?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        debug!(
            "Read header bytes from incoming control message, now parsing... {:?}",
            header_bytes
        );
        let (_rem, packet) = match ControlPacket::parse(&header_bytes) {
            Ok((rem, packet)) => (rem, packet.into_owned()),
            Err(nom::Err::Incomplete(nom::Needed::Size(size))) => {
                let mut payload_bytes = vec![0_u8; size.get() - 2];
                in_file.read_exact(&mut payload_bytes).await?;
                let all_bytes = [header_bytes.as_slice(), payload_bytes.as_slice()].concat();
                ControlPacket::parse(&all_bytes)
                    .map(|(_, packet)| (&[][..], packet.into_owned()))
                    .unwrap_or_else(|e| panic!("Unable to parse header packet: {e}"))
            }
            Err(e) => Err(anyhow!("Error parsing control packet: {e}"))?,
        };
        debug!("Parsed incoming control message: {packet:?}");
        Ok(packet)
    }

    /// Monitors the input pipe (`in_file`) for incoming control packets, parses
    /// them into [`ControlPackets`][ControlPacket], forwards them to the given
    /// tokio channel `tx`.
    async fn mon_input_pipe(
        tx: &tokio::sync::broadcast::Sender<ControlPacket<'static>>,
        mut in_file: File,
    ) -> anyhow::Result<()> {
        loop {
            let packet = Self::read_control_packet(&mut in_file).await?;
            tx.send(packet).unwrap();
        }
    }

    /// Creates a new instance of [`ExtcapControl`].
    pub fn new(in_path: &Path, out_path: &Path) -> Self {
        let (in_tx, _) = tokio::sync::broadcast::channel::<ControlPacket<'static>>(100);
        let (out_tx, out_rx) = mpsc::channel::<ControlPacket<'static>>(100);
        Self {
            in_path: in_path.to_owned(),
            out_path: out_path.to_owned(),
            in_tx,
            out_tx,
            out_rx,
        }
    }

    /// Optionally creates a new instance of [`ExtcapControl`], if both
    /// `in_path` and `out_path` are present.
    pub fn new_option(in_path: Option<PathBuf>, out_path: Option<PathBuf>) -> Option<Self> {
        Some(Self::new(in_path?.as_path(), out_path?.as_path()))
    }

    /// Starts processing the control packets on both the input and output
    /// pipes. Note that this method loops infinitely, and will not complete
    /// unless an error has occurred or a signal is received. (`SIGTERM` is sent
    /// by Wireshark when the capture stops).
    pub async fn process(&mut self) -> anyhow::Result<()> {
        let mut in_file = File::open(&self.in_path).await?;
        let out_file = File::create(&self.out_path).await?;
        let init_packet = Self::read_control_packet(&mut in_file).await?;
        assert_eq!(init_packet.command, ControlCommand::Initialized);
        tokio::try_join!(
            Self::mon_input_pipe(&self.in_tx, in_file),
            Self::mon_output_pipe(&mut self.out_rx, out_file),
        )?;
        Ok(())
    }

    /// Gets a control pipe that can send control messages to Wireshark.
    pub fn get_control_pipe(&self) -> mpsc::Sender<ControlPacket<'static>> {
        self.out_tx.clone()
    }
}

/// Sender for extcap control packets. These control packets controls the UI generated by Wireshark.
/// See <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html> for details.
#[async_trait]
pub trait ExtcapControlSenderTrait {

    const UNUSED_CONTROL_NUMBER: u8 = 255;

    async fn send(&self, packet: ControlPacket<'static>);

    /// Enable a button with the given control number.
    async fn enable_button(&self, button: u8) {
        self.send(ControlPacket::new(button, ControlCommand::Enable, &[]))
            .await
    }

    /// Disable a button with the given control number.
    async fn disable_button(&self, button: u8) {
        self.send(ControlPacket::new(button, ControlCommand::Disable, &[]))
            .await
    }

    /// Shows a message in an information dialog popup.
    async fn info_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::InformationMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in a warning dialog popup.
    async fn warning_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::WarningMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in an error dialog popup.
    async fn error_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::ErrorMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in the status bar
    async fn status_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::StatusbarMessage,
            message.as_bytes(),
        ))
        .await
    }
}

pub type ExtcapControlSender = mpsc::Sender<ControlPacket<'static>>;

#[async_trait]
impl ExtcapControlSenderTrait for mpsc::Sender<ControlPacket<'static>> {
    /// Sends a control message to Wireshark.
    async fn send(&self, packet: ControlPacket<'static>) {
        debug!("Sending extcap control message: {packet:#?}");
        self.send(packet)
            .await
            .unwrap_or_else(|e| warn!("Failed to send control packet. {e}"));
    }
}

// Convenience impl to allow `Option::None` to be a no-op sender.
#[async_trait]
impl<T: ExtcapControlSenderTrait + Sync> ExtcapControlSenderTrait for Option<T> {
    /// Sends a control message to Wireshark.
    async fn send(&self, packet: ControlPacket<'static>) {
        if let Some(sender) = self {
            sender.send(packet).await;
        }
    }
}

#[cfg(test)]
mod test {
    use nom_derive::Parse;

    use super::ControlPacket;

    #[test]
    fn test_to_bytes() {
        let packet = ControlPacket::new(
            123,
            super::ControlCommand::InformationMessage,
            b"testing123",
        );
        let full_bytes = [&packet.to_header_bytes(), packet.payload.as_ref()].concat();
        let (rem, parsed_packet) = ControlPacket::parse(&full_bytes).unwrap();
        assert_eq!(packet, parsed_packet);
        assert!(rem.is_empty());
    }
}
