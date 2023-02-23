use crate::{threaded::{ExtcapControl, ExtcapControlSenderTrait}};

pub struct Metadata<S: AsRef<str>> {
    pub version: S,
    pub help_url: S,
    pub display_description: S,
}

impl<S: AsRef<str>> Metadata<S> {
    pub fn print_config(&self) {
        println!(
            "extcap {{version={}}}{{help={}}}{{display={}}}",
            self.version.as_ref(),
            self.help_url.as_ref(),
            self.display_description.as_ref()
        );
    }
}

pub struct Interface<S: AsRef<str>> {
    pub value: S,
    pub display: S,
}

impl<S: AsRef<str>> Interface<S> {
    pub fn print_config(&self) {
        println!(
            "interface {{value={}}}{{display={}}}",
            self.value.as_ref(),
            self.display.as_ref()
        );
    }
}

#[derive(Clone)]
pub struct ControlValue<S: AsRef<str>> {
    pub value: S,
    pub display: S,
    pub default: bool,
}

impl<S: AsRef<str>> ControlValue<S> {
    pub const fn new(value: S, display: S) -> Self {
        Self {
            value,
            display,
            default: false,
        }
    }

    pub const fn new_default(value: S, display: S) -> Self {
        Self {
            value,
            display,
            default: true,
        }
    }

    pub fn print_config<C: Control>(&self, control: &C) {
        print!(
            "value {{control={}}}{{value={}}}{{display={}}}",
            control.control_number(),
            self.value.as_ref(),
            self.display.as_ref(),
        );
        if self.default {
            print!("{{default=true}}");
        }
        println!();
    }
}

pub trait EnableableControl: Control {
    fn set_enabled(&self, control_sender: &mut ExtcapControl, enabled: bool) {
        if enabled {
            control_sender.enable_button(self.control_number());
        } else {
            control_sender.disable_button(self.control_number());
        }
    }
}

pub trait ControlWithLabel: Control {
    fn set_label<S: AsRef<str>>(&self, control_sender: &mut ExtcapControl, label: S) {
        control_sender.set_value(self.control_number(), label.as_ref());
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
pub struct BooleanControl<S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
}

impl<S: AsRef<str>> EnableableControl for BooleanControl<S> {}
impl<S: AsRef<str>> ControlWithLabel for BooleanControl<S> {}

impl<S: AsRef<str>> BooleanControl<S> {
    pub fn set_checked(&self, extcap_control: &mut ExtcapControl, checked: bool) {
        extcap_control.set_value_bytes(self.control_number, &[checked as u8]);
    }
}

impl<S: AsRef<str>> Control for BooleanControl<S> {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=boolean}}");
        print!("{{display={}}}", self.display.as_ref());
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip.as_ref());
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
pub struct ButtonControl<S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
}

impl<S: AsRef<str>> EnableableControl for ButtonControl<S> {}
impl<S: AsRef<str>> ControlWithLabel for ButtonControl<S> {}

impl<S: AsRef<str>> Control for ButtonControl<S> {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{display={}}}", self.display.as_ref());
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip.as_ref());
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
pub struct LoggerControl<S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
}

impl<S: AsRef<str>> LoggerControl<S> {
    /// The Set command will clear the log before adding the entry.
    pub fn set_log_entry(&self, extcap_control: &mut ExtcapControl, log: S) {
        extcap_control.set_value(self.control_number, log.as_ref());
    }

    pub fn add_log_entry(&self, extcap_control: &mut ExtcapControl, log: S) {
        extcap_control.add_value(self.control_number, log.as_ref());
    }
}

impl<S: AsRef<str>> Control for LoggerControl<S> {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{role=logger}}");
        println!();
    }
}

/// This button opens the help page, if configured. This role has no
/// controls and will not be used in communication.
pub struct HelpControl<S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
}

impl<S: AsRef<str>> Control for HelpControl<S> {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
        print!("{{type=button}}");
        print!("{{role=help}}");
        println!();
    }
}

/// This button will restore all control values to default. This role has no
/// controls and will not be used in communication. The button is only
/// enabled when not capturing.
pub struct RestoreControl<S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
}

impl<S: AsRef<str>> Control for RestoreControl<S> {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}", self.control_number());
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
pub struct SelectorControl<'a, S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
    pub options: &'a [ControlValue<S>],
}

impl<'a, S: AsRef<str>> SelectorControl<'a, S> {
    pub fn add_value(&self, extcap_control: &mut ExtcapControl, value: S, display: S) {
        extcap_control.add_value(
            self.control_number,
            &format!("{}\0{}", value.as_ref(), display.as_ref()),
        )
    }

    pub fn remove_value(&self, extcap_control: &mut ExtcapControl, value: S) {
        extcap_control.remove_value(self.control_number, value.as_ref())
    }
}

impl<'a, S> Control for SelectorControl<'a, S>
where
    S: AsRef<str>,
{
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}{{type=selector}}", self.control_number());
        print!("{{display={}}}", self.display.as_ref());
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}}}", tooltip.as_ref());
        }
        println!();
        for value in self.options {
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
#[derive(Debug, Default)]
pub struct StringControl<S: AsRef<str>> {
    pub control_number: u8,
    pub display: S,
    pub tooltip: Option<S>,
    pub placeholder: Option<S>,
    pub validation: Option<S>,
}

impl<S: AsRef<str>> StringControl<S> {
    pub fn set_value(&self, extcap_control: &mut ExtcapControl, message: &str) {
        extcap_control.set_value(self.control_number, message);
    }
}

impl<S: AsRef<str>> Control for StringControl<S> {
    fn control_number(&self) -> u8 {
        self.control_number
    }

    fn print_config(&self) {
        print!("control {{number={}}}{{type=string}}", self.control_number());
        print!("{{display={}}}", self.display.as_ref());
        if let Some(tooltip) = &self.tooltip {
            print!("{{tooltip={}", tooltip.as_ref());
        }
        if let Some(placeholder) = &self.placeholder {
            print!("{{placeholder={}", placeholder.as_ref());
        }
        if let Some(validation) = &self.validation {
            print!("{{validation={}", validation.as_ref());
        }
        println!();
    }
}

pub trait Control {
    fn control_number(&self) -> u8;
    fn print_config(&self);
}
