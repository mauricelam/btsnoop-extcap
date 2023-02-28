use std::borrow::Cow;

use nom::number::streaming::be_u24;
use nom_derive::Nom;
use typed_builder::TypedBuilder;

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

// TODO: Support tokio sender as well
pub trait EnableableControl: ToolbarControl {
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

pub trait ControlWithLabel: ToolbarControl {
    fn set_label<'a>(&self, label: &'a str) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Set,
            label.as_bytes(),
        )
    }
}

/// This provides a checkbox which lets the user set a true/false value.
///
/// The extcap utility can set a default value at startup, and can change
/// (set) and receive value changes while capturing. When starting a capture
/// the GUI will send the value if different from the default value.
///
/// The payload is one byte with binary value 0 or 1.
///
/// Valid Commands: Set value, Enable, Disable.
#[derive(Debug, TypedBuilder)]
pub struct BooleanControl {
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl EnableableControl for BooleanControl {}
impl ControlWithLabel for BooleanControl {}

impl BooleanControl {
    pub fn set_checked<'a>(&self, checked: bool) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Set,
            vec![checked as u8],
        )
    }
}

impl ToolbarControl for BooleanControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=boolean}}");
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip);
        }
        println!()
    }
}

/// This button will send a signal when pressed. This is the default if no
/// role is configured. The button is only enabled when capturing.
///
/// The extcap utility can set the button text at startup, and can change
/// (set) the button text and receive button press signals while capturing.
/// The button is disabled and the button text is restored to the default
/// text when not capturing.
///
/// The payload is either the button text or empty (signal).
///
/// Valid Commands: Set value, Enable, Disable.
#[derive(Debug, TypedBuilder)]
pub struct ButtonControl {
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl EnableableControl for ButtonControl {}
impl ControlWithLabel for ButtonControl {}

impl ToolbarControl for ButtonControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip);
        }
        println!();
    }
}

/// This provides a logger mechanism where the extcap utility can send log
/// entries to be presented in a log window. This communication is
/// unidirectional.
///
/// The payload is the log entry, and should be ended with a newline.
/// Maximum length is 65535 bytes.
#[derive(Debug, TypedBuilder)]
pub struct LoggerControl {
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl LoggerControl {
    /// The Set command will clear the log before adding the entry.
    pub fn clear_and_add_log<'a>(&self, log: &'a str) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(self.control_number(), ControlCommand::Set, log.as_bytes())
    }

    pub fn add_log<'a>(&self, log: &'a str) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(self.control_number(), ControlCommand::Add, log.as_bytes())
    }
}

impl ToolbarControl for LoggerControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{role=logger}}");
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={tooltip}}}");
        }
        println!();
    }
}

/// This button opens the help page, if configured. This role has no
/// controls and will not be used in communication.
#[derive(Debug, TypedBuilder)]
pub struct HelpButtonControl {
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl ToolbarControl for HelpButtonControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{role=help}}");
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={tooltip}}}");
        }
        println!();
    }
}

/// This button will restore all control values to default. This role has no
/// controls and will not be used in communication. The button is only
/// enabled when not capturing.
#[derive(Debug, TypedBuilder)]
pub struct RestoreButtonControl {
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
}

impl ToolbarControl for RestoreButtonControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{role=restore}}");
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={tooltip}}}");
        }
        println!();
    }
}

/// This provides a combo box with fixed values which can be selected.
///
/// The extcap utility can set default values at startup, and add and remove
/// values and receive change in value selection while capturing. When
/// starting a capture the GUI will send the value if different from the
/// default value.
///
/// The payload is a string with the value, and optionally a string with a
/// display value if this is different from the value. This two string
/// values are separated by a null character.
///
/// Valid Commands: Set selected value, Add value, Remove value, Enable,
/// Disable.
///
/// If value is empty the Remove command will remove all entries.
#[derive(Debug, TypedBuilder)]
pub struct SelectorControl {
    pub control_number: u8,
    #[builder(setter(into))]
    pub display: String,
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    #[builder(default, setter(into))]
    pub options: Vec<ControlValue>,
}

impl SelectorControl {
    pub fn add_value<'a>(&self, value: &str, display: &'a str) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Add,
            format!("{}\0{}", value, display).as_bytes().to_vec(),
        )
    }

    pub fn remove_value<'a>(&self, value: &'a str) -> ControlPacket<'a> {
        ControlPacket::new_with_payload(
            self.control_number(),
            ControlCommand::Remove,
            value.as_bytes(),
        )
    }
}

impl ToolbarControl for SelectorControl {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!(
            "control {{number={}}}{{type=selector}}",
            self.control_number()
        );
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip);
        }
        println!();
        for value in self.options.iter() {
            value.print_config(self);
        }
    }
}
/// This provides a text edit line with the possibility to set a string or
/// any value which can be represented in a string (integer, float, date,
/// etc.).
///
/// The extcap utility can set a default string value at startup, and can
/// change (set) and receive value changes while capturing. When starting a
/// capture the GUI will send the value if different from the default value.
///
/// The payload is a string with the value. Maximum length is 32767 bytes.
///
/// Valid Commands for control: Set value, Enable, Disable.
///
/// The element VALIDATION allows to provide a regular expression string,
/// which is used to check the user input for validity beyond normal data
/// type or range checks. Back-slashes must be escaped (as in \\b for \b).
#[derive(Debug, Default, TypedBuilder)]
pub struct StringControl {
    pub control_number: u8,
    pub display: String,
    pub tooltip: Option<String>,
    pub placeholder: Option<String>,
    pub validation: Option<String>,
}

impl StringControl {
    pub fn set_value<'a>(&self, message: &'a str) -> ControlPacket<'a> {
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

    fn print_config(&self) {
        print!(
            "control {{number={}}}{{type=string}}",
            self.control_number()
        );
        print!("{{display={}}}", self.display);
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip);
        }
        if let Some(placeholder) = &self.placeholder {
            print!("{{placeholder={}}}", placeholder);
        }
        if let Some(validation) = &self.validation {
            print!("{{validation={}}}", validation);
        }
        println!();
    }
}

pub trait ToolbarControl: std::fmt::Debug {
    fn control_number(&self) -> u8;
    fn print_config(&self);
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
