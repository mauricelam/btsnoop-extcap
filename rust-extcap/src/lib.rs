//! Utilities for working with the extcap interface. The extcap interface is a
//! versatile plugin interface used by Wireshark to allow external binaries to
//! act as capture interfaces.
//!
//! References:
//! * <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html>
//! * <https://www.wireshark.org/docs/man-pages/extcap.html>
//! * <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py>

use clap::Args;
use nom::number::complete::be_u24;
use nom_derive::Nom;
use std::{borrow::Cow, path::PathBuf};

pub mod dlt;

#[cfg(feature = "tokio")]
pub mod tokio;

pub mod config;
pub mod interface;
pub mod threaded;
pub(crate) mod util;

/// The arguments defined by extcap. These arguments are usable as a clap
/// parser.
///
/// For example, if you use `clap` with the feature `derive`:
/// ```
/// # use clap::Parser;
/// #[derive(Debug, Parser)]
/// #[command(author, version, about)]
/// pub struct ApplicationArgs {
///    #[command(flatten)]
///    extcap: rust_extcap::ExtcapArgs,
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

    /// A selector may be reloaded from the configuration dialog of the extcap
    /// application within Wireshark. With the reload argument (defaults to
    /// false), the entry can be marked as reloadable.
    ///
    /// ```text
    /// arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}{reload=true}{placeholder=Load interfaces...}
    /// ```
    ///
    /// After this has been defined, the user will get a button displayed in the
    /// configuration dialog for this extcap application, with the text "Load
    /// interfaces...​" in this case, and a generic "Reload" text if no text has
    /// been provided.
    ///
    /// The extcap utility is then called again with all filled out arguments
    /// and the additional parameter `--extcap-reload-option <option_name>`. It
    /// is expected to return a value section for this option, as it would
    /// during normal configuration. The provided option list is then presented
    /// as the selection, a previous selected option will be reselected if
    /// applicable.
    #[arg(long, requires = "extcap_interface")]
    pub extcap_reload_option: Option<String>,
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
