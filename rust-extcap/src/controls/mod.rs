//! Structus to define the controls for the extcap program. There are two
//! aspects of "controls" handled in this module:
//!
//! 1. The toolbar controls in the Wireshark interface, when the user selects
//!    `View > Interface Toolbars`. This module helps define UI elements on that
//!    toolbar and react to user interactions performed on them.
//! 2. The control packets exchanged between this extcap program and Wireshark.
//!    Besides the UI toolbar elements above, control packets are also used for
//!    things like displaying status bar and dialog messages, as well as for
//!    Wireshark to send events like `Initialized`.

use std::{borrow::Cow, fmt::Display};

use nom::number::streaming::be_u24;
use nom_derive::Nom;
use typed_builder::TypedBuilder;

use crate::{ExtcapFormatter, PrintConfig};

use {asynchronous::ExtcapControlSenderTrait as _, synchronous::ExtcapControlSenderTrait as _};

pub mod asynchronous;
pub mod synchronous;

#[derive(Clone, Debug, TypedBuilder)]
pub struct ControlValue {
    #[builder(setter(into))]
    pub value: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default)]
    pub default: bool,
}

impl ControlValue {
    pub fn print_config<C: ToolbarControl>(&self, control: &C) {
        print!(
            "value {{control={}}}{{value={}}}{{display={}}}",
            control.control_number(),
            self.value,
            self.display,
        );
        if self.default {
            print!("{{default=true}}");
        }
        println!();
    }
}

/// A `ToolbarControl` that can be enabled or disabled.
pub trait EnableableControl: ToolbarControl {
    /// Sets whether the control is enabled or disabled.
    ///
    /// Returns a `ControlPacket` that can be sent using a
    /// [`synchronous::ExtcapControlSender`] or
    /// [`asynchronous::ExtcapControlSender`].
    fn set_enabled(&self, enabled: bool) -> ControlPacket<'static> {
        ControlPacket::new_with_payload(
            self.control_number(),
            if enabled {
                ControlCommand::Enable
            } else {
                ControlCommand::Disable
            },
            &[][..],
        )
    }
}

/// A [`ToolbarControl`] that has a customizable label.
pub trait ControlWithLabel: ToolbarControl {
    /// Sets the label of this control.
    ///
    /// Returns a `ControlPacket` that can be sent using a
    /// [`synchronous::ExtcapControlSender`] or
    /// [`asynchronous::ExtcapControlSender`].
    fn set_label<'a>(&self, label: &'a str) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Set,
            label.as_bytes(),
        )
    }
}

/// A checkbox which lets the user set a true / false value.
///
/// The extcap utility can set a default value at startup, change the value
/// using [`set_checked`][Self::set_checked], and receive value changes from an
/// [`ExtcapControlReader`][asynchronous::ExtcapControlReader]. When starting a
/// capture Wireshark will send the value if different from the default value.
#[derive(Debug, TypedBuilder)]
pub struct BooleanControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    /// Tooltip shown when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    // TODO: The extcap utility can set a default value at startup???
}

impl EnableableControl for BooleanControl {}
impl ControlWithLabel for BooleanControl {}

impl BooleanControl {
    /// Set whether this checkbox is checked.
    pub fn set_checked<'a>(&self, checked: bool) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Set,
            vec![checked as u8],
        )
    }
}

impl Display for ExtcapFormatter<&BooleanControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control {{number={}}}", self.0.control_number())?;
        write!(f, "{{type=boolean}}")?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={}}}", tooltip)?;
        }
        writeln!(f)
    }
}

impl ToolbarControl for BooleanControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

/// Button that sends a signal when pressed. The button is only enabled when
/// capturing.
///
/// The extcap utility can set the button text at startup using the `display`
/// field, change the button text using
/// [`set_label`][ControlWithLabel::set_label], and receive button press signals
/// from an [`ExtcapControlReader`][asynchronous::ExtcapControlReader].
///
/// The button is disabled and the button text is restored to the default text
/// when not capturing.
#[derive(Debug, TypedBuilder)]
pub struct ButtonControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    /// Tooltip shown when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl EnableableControl for ButtonControl {}
impl ControlWithLabel for ButtonControl {}

impl ToolbarControl for ButtonControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

impl Display for ExtcapFormatter<&ButtonControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control {{number={}}}", self.0.control_number())?;
        write!(f, "{{type=button}}")?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={}}}", tooltip)?;
        }
        writeln!(f)
    }
}

/// A logger mechanism where the extcap utility can send log entries to be
/// presented in a log window. This communication is unidirectional from this
/// extcap program to Wireshark.
///
/// A button will be displayed in the toolbar which will open the log window
/// when clicked.
#[derive(Debug, TypedBuilder)]
pub struct LoggerControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    /// Label of the button that opens the log window.
    #[builder(setter(into))]
    pub display: String,
    /// Tooltip shown when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl LoggerControl {
    /// Clear the log and add the given log the entry to the window.
    pub fn clear_and_add_log<'a>(&self, log: Cow<'a, str>) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Set,
            format!("{}\n", log).into_bytes(),
        )
    }

    /// Add the log entry to the log window.
    pub fn add_log<'a>(&self, log: Cow<'a, str>) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Add,
            format!("{}\n", log).into_bytes(),
        )
    }
}

impl ToolbarControl for LoggerControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

impl Display for ExtcapFormatter<&LoggerControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control {{number={}}}", self.0.control_number())?;
        write!(f, "{{type=button}}")?;
        write!(f, "{{role=logger}}")?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        writeln!(f)
    }
}

/// This button opens the help page, if configured. This role has no
/// controls and will not be used in communication.
#[derive(Debug, TypedBuilder)]
pub struct HelpButtonControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    /// Tooltip shown when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl ToolbarControl for HelpButtonControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

impl Display for ExtcapFormatter<&HelpButtonControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control {{number={}}}", self.0.control_number())?;
        write!(f, "{{type=button}}")?;
        write!(f, "{{role=help}}")?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        writeln!(f)
    }
}

/// This button will restore all control values to default. This role has no
/// controls and will not be used in communication. The button is only
/// enabled when not capturing.
#[derive(Debug, TypedBuilder)]
pub struct RestoreButtonControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    /// Tooltip shown when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl ToolbarControl for RestoreButtonControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

impl Display for ExtcapFormatter<&RestoreButtonControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "control {{number={}}}", self.0.control_number())?;
        write!(f, "{{type=button}}")?;
        write!(f, "{{role=restore}}")?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        writeln!(f)
    }
}

/// A dropdown selector with fixed values which can be selected.
///
/// Default values can be provided using the `options` field. When starting
/// a capture, Wireshark will send the value as a command line flag if the
/// selected value is different from the default value.
#[derive(Debug, TypedBuilder)]
pub struct SelectorControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    /// Tooltip shown when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    #[builder(default, setter(into))]
    pub options: Vec<ControlValue>,
}

impl SelectorControl {
    /// Add an option to the selector dynamically.
    pub fn add_value<'a>(&self, value: &'a str, display: Option<&'a str>) -> ControlPacket<'a> {
        let payload: Cow<'a, str> = display
            .map(|d| Cow::Owned(format!("{}\0{}", value, d)))
            .unwrap_or_else(|| Cow::Borrowed(value));
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Add,
            payload.as_bytes().to_vec(),
        )
    }

    /// Removes an option from the selector.
    ///
    /// Panics: If `value` is an empty string.
    pub fn remove_value<'a>(&self, value: &'a str) -> ControlPacket<'a> {
        assert!(!value.is_empty(), "Argument to remove_value must not be empty");
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Remove,
            value.as_bytes(),
        )
    }

    /// Clears all options from the selector.
    pub fn clear(&self) -> ControlPacket<'static> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Remove,
            &[][..],
        )
    }
}

impl ToolbarControl for SelectorControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

impl Display for ExtcapFormatter<&SelectorControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "control {{number={}}}{{type=selector}}",
            self.0.control_number()
        )?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={}}}", tooltip)?;
        }
        writeln!(f)?;
        for value in self.0.options.iter() {
            value.print_config(self.0);
        }
        Ok(())
    }
}
/// A text edit line with the possibility to set a string (or any value which can
/// be represented in a string).
///
/// The extcap utility can set a default string value at startup, and can change
/// (set) and receive value changes while capturing. When starting a capture the
/// GUI will send the value if different from the default value.
///
/// The payload is a string with the value. Maximum length is 32767 bytes.
///
/// Valid Commands for control: Set value, Enable, Disable.
///
/// The element VALIDATION allows to provide a regular expression string, which
/// is used to check the user input for validity beyond normal data type or
/// range checks. Back-slashes must be escaped (as in \\b for \b).
#[derive(Debug, Default, TypedBuilder)]
pub struct StringControl {
    /// The control number, a unique identifier for this control.
    pub control_number: u8,
    pub display: String,
    pub tooltip: Option<String>,
    pub placeholder: Option<String>,
    pub validation: Option<String>,
    // TODO: Default string value?
}

impl StringControl {
    /// Sets the value of the control.
    ///
    /// Panics: If the string is longer than 32767 bytes.
    pub fn set_value<'a>(&self, message: &'a str) -> ControlPacket<'a> {
        assert!(message.as_bytes().len() <= 32767, "message must not be longer than 32767 bytes");
        ControlPacket::new_with_payload(
            self.control_number,
            ControlCommand::Set,
            message.as_bytes(),
        )
    }
}

impl ToolbarControl for StringControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }
}

impl Display for ExtcapFormatter<&StringControl> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "control {{number={}}}{{type=string}}",
            self.0.control_number()
        )?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={}}}", tooltip)?;
        }
        if let Some(placeholder) = &self.0.placeholder {
            write!(f, "{{placeholder={}}}", placeholder)?;
        }
        if let Some(validation) = &self.0.validation {
            write!(f, "{{validation={}}}", validation)?;
        }
        writeln!(f)
    }
}

/// Controls provided by this extcap utility to use in a toolbar in the UI.
/// These controls are bidirectional and can be used to control the extcap
/// utility while capturing.
///
/// This is useful in scenarios where configuration can be done based on
/// findings in the capture process, setting temporary values or give other
/// inputs without restarting the current capture.
///
/// All controls will be presented as GUI elements in a toolbar specific to the
/// extcap utility. The extcap must not rely on using those controls (they are
/// optional) because of other capturing tools not using GUI (e.g. tshark,
/// tfshark).
pub trait ToolbarControl: PrintConfig {
    /// The control number, a unique identifier for this control.
    fn control_number(&self) -> u8;
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
    /// [`--extcap-interfaces`][crate::ExtcapArgs::extcap_interfaces] phase. This
    /// number also gives the order of the controls in the interface toolbar.
    /// The control number, a unique identifier for this control.
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
    pub fn new_with_payload<CowSlice: Into<Cow<'a, [u8]>>>(
        control_number: u8,
        command: ControlCommand,
        payload: CowSlice,
    ) -> Self {
        let payload = payload.into();
        ControlPacket {
            sync_pipe_indication: b'T',
            message_length: (payload.len() + 2) as u32,
            control_number,
            command,
            payload,
        }
    }

    pub fn new(control_number: u8, command: ControlCommand) -> Self {
        let empty_slice: &'static [u8] = &[];
        Self::new_with_payload(control_number, command, empty_slice)
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
        ControlPacket {
            payload: match self.payload {
                Cow::Borrowed(v) => Cow::Owned(v.to_vec()),
                Cow::Owned(v) => Cow::Owned(v),
            },
            ..self
        }
    }

    pub fn send(self, sender: &mut synchronous::ExtcapControlSender) -> std::io::Result<()> {
        sender.send(self)
    }

    pub async fn send_async(
        self,
        sender: &mut asynchronous::ExtcapControlSender,
    ) -> tokio::io::Result<()> {
        sender.send(self).await
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
        let packet = ControlPacket::new_with_payload(
            123,
            super::ControlCommand::InformationMessage,
            &b"testing123"[..],
        );
        let full_bytes = [&packet.to_header_bytes(), packet.payload.as_ref()].concat();
        let (rem, parsed_packet) = ControlPacket::parse(&full_bytes).unwrap();
        assert_eq!(packet, parsed_packet);
        assert!(rem.is_empty());
    }
}
