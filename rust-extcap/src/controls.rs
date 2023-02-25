use typed_builder::TypedBuilder;

use crate::threaded::{ExtcapControlSender, ExtcapControlSenderTrait};


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
    fn set_enabled(&self, control_sender: &mut ExtcapControlSender, enabled: bool) {
        if enabled {
            control_sender.enable_button(self.control_number());
        } else {
            control_sender.disable_button(self.control_number());
        }
    }
}

pub trait ControlWithLabel: ToolbarControl {
    fn set_label(&self, control_sender: &mut ExtcapControlSender, label: &str) {
        control_sender.set_value(self.control_number(), label);
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
    pub fn set_checked(&self, extcap_control: &mut ExtcapControlSender, checked: bool) {
        extcap_control.set_value_bytes(self.control_number, &[checked as u8]);
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
    pub fn set_log_entry(&self, extcap_control: &mut ExtcapControlSender, log: &str) {
        extcap_control.set_value(self.control_number, log);
    }

    pub fn add_log_entry(&self, extcap_control: &mut ExtcapControlSender, log: &str) {
        extcap_control.add_value(self.control_number, log);
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
    pub fn add_value(&self, extcap_control: &mut ExtcapControlSender, value: &str, display: &str) {
        extcap_control.add_value(
            self.control_number,
            &format!("{}\0{}", value, display),
        )
    }

    pub fn remove_value(&self, extcap_control: &mut ExtcapControlSender, value: &str) {
        extcap_control.remove_value(self.control_number, value.as_ref())
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
    pub fn set_value(&self, extcap_control: &mut ExtcapControlSender, message: &str) {
        extcap_control.set_value(self.control_number, message);
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
