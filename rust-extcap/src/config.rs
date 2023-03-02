//! Module for implementing extcap config, which are UI elements shown in
//! Wireshark that allows the user to customize the capture.
//!
//! Each interface can have custom options that are valid for this interface
//! only. Those config options are specified on the command line when running
//! the actual capture.

use std::any::Any;
use std::fmt::{Debug, Display};
use std::ops::RangeInclusive;
use typed_builder::TypedBuilder;

pub use crate::{ExtcapFormatter, PrintConfig};

macro_rules! generate_config_ext {
    ($config_type:ty) => {
        impl ConfigTrait for $config_type {
            fn call(&self) -> &str {
                &self.call
            }

            fn as_any(&self) -> &dyn Any {
                self
            }
        }
    };
}

/// A functional trait for [`SelectorConfig::reload`]. Users normally do not
/// have to use this trait directly, as it is automatically implemented for all
/// `Fn() -> Vec<ConfigOptionValue> + Sync + 'static`, so callers can simply
/// pass a closure into `reload()`.
pub trait ReloadFn: Fn() -> Vec<ConfigOptionValue> + Sync + 'static {}

impl<F> ReloadFn for F where F: Fn() -> Vec<ConfigOptionValue> + Sync + 'static {}

impl std::fmt::Debug for dyn ReloadFn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReloadFn")
    }
}

/// A selector config UI element that allows the user to select an option from a
/// drop-down list.
///
/// TODO: Double check this: selector and radio values must present a default
/// value, which will be the value provided to the extcap binary for this
/// argument.
///
/// ```
/// use rust_extcap::config::*;
///
/// let selector = SelectorConfig::builder()
///     .config_number(3)
///     .call("remote")
///     .display("Remote Channel")
///     .tooltip("Remote Channel Selector")
///     .options([
///         ConfigOptionValue::builder().value("if1").display("Remote1").default(true).build(),
///         ConfigOptionValue::builder().value("if2").display("Remote2").build(),
///     ])
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&selector)),
///     concat!(
///         "arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}\n",
///         "value {arg=3}{value=if1}{display=Remote1}{default=true}\n",
///         "value {arg=3}{value=if2}{display=Remote2}{default=false}\n"
///     )
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct SelectorConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the selector.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// If this is `Some`, a refresh button will be shown next to the selector,
    /// allowing the user to refresh the list of available options to the return
    /// value of this function.
    #[builder(default, setter(strip_option))]
    pub reload: Option<Box<dyn ReloadFn>>,
    /// The placeholder string displayed if there is no value selected.
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    /// The default list of options presented by this selector.
    #[builder(setter(into))]
    pub default_options: Vec<ConfigOptionValue>,
}

impl<'a> Display for ExtcapFormatter<&'a SelectorConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        write!(f, "{{type=selector}}")?;
        if self.0.reload.is_some() {
            write!(f, "{{reload=true}}")?;
        }
        writeln!(f)?;
        for opt in self.0.default_options.iter() {
            write!(f, "{}", ExtcapFormatter(&(opt, self.0.config_number)))?;
        }
        Ok(())
    }
}

generate_config_ext!(SelectorConfig);

/// A selector config that presents a list of options in a drop-down list. With
/// edit selector, the user can also choose to enter a value not present in the
/// list
///
/// TODO: check me: selector and radio values must present a default value,
/// which will be the value provided to the extcap binary for this argument.
///
/// ```
/// use rust_extcap::config::*;
///
/// let edit_selector = EditSelectorConfig::builder()
///     .config_number(3)
///     .call("remote")
///     .display("Remote Channel")
///     .tooltip("Remote Channel Selector")
///     .options([
///         ConfigOptionValue::builder().value("if1").display("Remote1").default(true).build(),
///         ConfigOptionValue::builder().value("if2").display("Remote2").build(),
///     ])
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&edit_selector)),
///     concat!(
///         "arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=editselector}\n",
///         "value {arg=3}{value=if1}{display=Remote1}{default=true}\n",
///         "value {arg=3}{value=if2}{display=Remote2}{default=false}\n"
///     )
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct EditSelectorConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the selector.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// If this is `Some`, a refresh button will be shown next to the selector,
    /// allowing the user to refresh the list of available options to the return
    /// value of this function.
    #[builder(default)]
    pub reload: Option<Box<dyn ReloadFn>>,
    /// The placeholder string displayed if there is no value selected.
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    /// The default list of options presented by this selector.
    #[builder(setter(into))]
    pub options: Vec<ConfigOptionValue>,
}

impl<'a> Display for ExtcapFormatter<&'a EditSelectorConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(placeholder) = &self.0.placeholder {
            write!(f, "{{placeholder={}}}", placeholder)?;
        }
        write!(f, "{{type=editselector}}")?;
        if self.0.reload.is_some() {
            write!(f, "{{reload=true}}")?;
        }
        writeln!(f)?;
        for opt in self.0.options.iter() {
            write!(f, "{}", ExtcapFormatter(&(opt, self.0.config_number)))?;
        }
        Ok(())
    }
}

generate_config_ext!(EditSelectorConfig);

// TODO: Add `group` to all elements.

/// A list of radio buttons for the user to choose one value from.
///
/// TODO: check me: selector and radio values must present a default value,
/// which will be the value provided to the extcap binary for this argument.
///
/// ```
/// use rust_extcap::config::*;
///
/// let radio = RadioConfig::builder()
///     .config_number(3)
///     .call("remote")
///     .display("Remote Channel")
///     .tooltip("Remote Channel Selector")
///     .options([
///         ConfigOptionValue::builder().value("if1").display("Remote1").default(true).build(),
///         ConfigOptionValue::builder().value("if2").display("Remote2").build(),
///     ])
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&radio)),
///     concat!(
///         "arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=radio}\n",
///         "value {arg=3}{value=if1}{display=Remote1}{default=true}\n",
///         "value {arg=3}{value=if2}{display=Remote2}{default=false}\n"
///     )
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct RadioConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the radio button.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The (user-visible) name of the tab which this config belongs to.
    /// TODO: Document what happens if this is None
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// The default list of options presented by this config.
    #[builder(setter(into))]
    pub options: Vec<ConfigOptionValue>,
}

impl<'a> Display for ExtcapFormatter<&'a RadioConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.0.group {
            write!(f, "{{group={}}}", group)?;
        }
        write!(f, "{{type=radio}}")?;
        writeln!(f)?;
        for opt in self.0.options.iter() {
            write!(f, "{}", ExtcapFormatter(&(opt, self.0.config_number)))?;
        }
        Ok(())
    }
}

generate_config_ext!(RadioConfig);

/// A tree of hierarchical check boxes that the user can select.
///
/// TODO: How are multiple values passed to command line? Is the flag repeated?
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = MultiCheckConfig::builder()
///     .config_number(3)
///     .call("multi")
///     .display("Remote Channel")
///     .tooltip("Remote Channel Selector")
///     .options([
///         MultiCheckValue::builder().value("if1").display("Remote1").default_value(true).build(),
///         MultiCheckValue::builder().value("if2").display("Remote2").children([
///             MultiCheckValue::builder().value("if2a").display("Remote2A").default_value(true).build(),
///             MultiCheckValue::builder().value("if2b").display("Remote2B").default_value(true).build(),
///         ]).build(),
///     ])
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     concat!(
///         "arg {number=3}{call=--multi}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=multicheck}\n",
///         "value {arg=3}{value=if1}{display=Remote1}{default=true}{enabled=true}\n",
///         "value {arg=3}{value=if2}{display=Remote2}{default=false}{enabled=true}\n",
///         "value {arg=3}{value=if2a}{display=Remote2A}{default=true}{enabled=true}{parent=if2}\n",
///         "value {arg=3}{value=if2b}{display=Remote2B}{default=true}{enabled=true}{parent=if2}\n"
///     )
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct MultiCheckConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the tree of checkboxes.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The (user-visible) name of the tab which this config belongs to.
    /// TODO: Document what happens if this is None
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// The default list of options presented by this config. This can be refreshed by the user using via the `reload` field.
    #[builder(setter(into))]
    pub options: Vec<MultiCheckValue>,
}

impl<'a> Display for ExtcapFormatter<&'a MultiCheckConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.0.group {
            write!(f, "{{group={}}}", group)?;
        }
        write!(f, "{{type=multicheck}}")?;
        writeln!(f)?;
        for opt in self.0.options.iter() {
            write!(f, "{}", ExtcapFormatter((opt, self.0.config_number, None)))?;
        }
        Ok(())
    }
}

generate_config_ext!(MultiCheckConfig);

/// Represents a checkbox in a [`MultiCheckConfig`]. Each value is a checkbox in
/// the UI that can be nested into a hierarchy using the `children` field. See
/// the docs for [`MultiCheckConfig`] for usage details.
#[derive(Debug, Clone, TypedBuilder)]
pub struct MultiCheckValue {
    /// The value for this option, which is the value that will be passed to the
    /// extcap command line. For example, if `MultiCheckConfig.call` is `foo`,
    /// and this field is `bar`, then `--foo bar` will be passed to this extcap
    /// program during capturing.
    #[builder(setter(into))]
    value: String,
    /// The user-friendly label for this check box.
    #[builder(setter(into))]
    display: String,
    /// The default value for this check box, whether it is checked or not.
    #[builder(default = false)]
    default_value: bool,
    /// Whether this checkbox is enabled or not.
    /// TODO: Does this element support reload?
    #[builder(default = true)]
    enabled: bool,
    /// The list of children checkboxes. Children check boxes will be indented
    /// under this check box in the UI, but does not change how the value gets
    /// sent to the extcap program.
    #[builder(default, setter(into))]
    children: Vec<MultiCheckValue>,
}

impl<'a> Display for ExtcapFormatter<(&'a MultiCheckValue, u8, Option<&'a MultiCheckValue>)> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let (config, config_number, parent) = self.0;
        write!(f, "value {{arg={}}}", config_number)?;
        write!(f, "{{value={}}}", config.value)?;
        write!(f, "{{display={}}}", config.display)?;
        write!(f, "{{default={}}}", config.default_value)?;
        write!(f, "{{enabled={}}}", config.enabled)?;
        if let Some(parent) = parent {
            write!(f, "{{parent={}}}", parent.value)?;
        }
        writeln!(f)?;
        for c in config.children.iter() {
            write!(f, "{}", Self((c, config_number, Some(config))))?;
        }
        Ok(())
    }
}

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = LongConfig::builder()
///     .config_number(0)
///     .call("delay")
///     .display("Time delay")
///     .tooltip("Time delay between packages")
///     .range(-2..=15)
///     .default_value(0)
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{range=-2,15}{default=0}{type=long}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct LongConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the numeric field.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The valid range of values for this config.
    #[builder(default, setter(strip_option))]
    pub range: Option<RangeInclusive<i64>>,
    /// The default value for this config.
    pub default_value: i64,
    /// The (user-visible) name of the tab which this config belongs to.
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl<'a> Display for ExtcapFormatter<&'a LongConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.0.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.0.default_value)?;
        write!(f, "{{type=long}}")?;
        if let Some(group) = &self.0.group {
            write!(f, "{{group={}}}", group)?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(LongConfig);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = IntegerConfig::builder()
///     .config_number(0)
///     .call("delay")
///     .display("Time delay")
///     .tooltip("Time delay between packages")
///     .range(-10..=15)
///     .default_value(0)
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{range=-10,15}{default=0}{type=integer}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct IntegerConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the numeric field.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The valid range of values for this config.
    #[builder(default, setter(strip_option))]
    pub range: Option<RangeInclusive<i32>>,
    /// The default value for this config.
    pub default_value: i32,
    /// The (user-visible) name of the tab which this config belongs to.
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl<'a> Display for ExtcapFormatter<&'a IntegerConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.0.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.0.default_value)?;
        write!(f, "{{type=integer}}")?;
        if let Some(group) = &self.0.group {
            write!(f, "{{group={}}}", group)?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(IntegerConfig);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = UnsignedConfig::builder()
///     .config_number(0)
///     .call("delay")
///     .display("Time delay")
///     .tooltip("Time delay between packages")
///     .range(1..=15)
///     .default_value(0)
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{range=1,15}{default=0}{type=unsigned}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct UnsignedConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the numeric field.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The valid range of values for this config.
    #[builder(default, setter(strip_option, into))]
    pub range: Option<RangeInclusive<u32>>,
    /// The default value for this config.
    pub default_value: u32,
    /// The (user-visible) name of the tab which this config belongs to.
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl<'a> Display for ExtcapFormatter<&'a UnsignedConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.0.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.0.default_value)?;
        write!(f, "{{type=unsigned}}")?;
        if let Some(group) = &self.0.group {
            write!(f, "{{group={}}}", group)?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(UnsignedConfig);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = DoubleConfig::builder()
///     .config_number(0)
///     .call("delay")
///     .display("Time delay")
///     .tooltip("Time delay between packages")
///     .range(-2.6..=8.2)
///     .default_value(3.3)
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{range=-2.6,8.2}{default=3.3}{type=double}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct DoubleConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the numeric field.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The valid range of values for this config.
    #[builder(default, setter(strip_option))]
    pub range: Option<RangeInclusive<f64>>,
    /// The default value for this config.
    pub default_value: f64,
    /// The (user-visible) name of the tab which this config belongs to.
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl<'a> Display for ExtcapFormatter<&'a DoubleConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.0.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.0.default_value)?;
        write!(f, "{{type=double}}")?;
        if let Some(group) = &self.0.group {
            write!(f, "{{group={}}}", group)?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(DoubleConfig);

/// A field for entering a text value.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = StringConfig::builder()
///     .config_number(1)
///     .call("server")
///     .display("IP Address")
///     .tooltip("IP Address for log server")
///     .validation(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     concat!(
///         r"arg {number=1}{call=--server}{display=IP Address}{tooltip=IP Address for log server}{validation=\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b}{type=string}",
///         "\n"
///     )
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct StringConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the text field.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The placeholder string displayed if there is no value in the text field.
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    /// Whether a value is required for this config.
    ///
    /// TODO: is required available for other fields?
    #[builder(default = false)]
    pub required: bool,

    /// A regular expression string used to check the user input for validity.
    /// Despite what the Wireshark documentation says, back-slashes in this
    /// string do not need to be escaped. Just remember to use a Rust raw string
    /// (e.g. `r"\d\d\d\d"`).
    #[builder(default, setter(strip_option, into))]
    pub validation: Option<String>,
    /// Whether to save the value of this config. If true, the value will be
    /// saved by Wireshark, and will be automatically populated next time that
    /// interface is selected by the user.
    ///
    /// TODO: Check whether the default value for this is true or false TODO:
    /// Check whether other configs support this as well.
    #[builder(default = false)]
    pub save: bool,
}

impl<'a> Display for ExtcapFormatter<&'a StringConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(placeholder) = &self.0.placeholder {
            write!(f, "{{placeholder={}}}", placeholder)?;
        }
        if self.0.required {
            write!(f, "{{required=true}}")?;
        }
        if let Some(validation) = &self.0.validation {
            write!(f, "{{validation={}}}", validation)?;
        }
        if !self.0.save {
            write!(f, "{{save=false}}")?;
        }
        write!(f, "{{type=string}}")?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(StringConfig);

/// A field for entering text value, but with its value masked in the user
/// interface. The value of a password field is not saved by Wireshark.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = PasswordConfig::builder()
///     .config_number(0)
///     .call("password")
///     .display("The user password")
///     .tooltip("The password for the connection")
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=0}{call=--password}{display=The user password}{tooltip=The password for the connection}{type=password}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct PasswordConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the password field.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The placeholder string displayed if there is no value in the text field.
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    /// Whether a value is required for this config.
    #[builder(default = false)]
    pub required: bool,
    /// A regular expression string used to check the user input for validity.
    /// Despite what the Wireshark documentation says, back-slashes in this
    /// string do not need to be escaped. Just remember to use a Rust raw string
    /// (e.g. `r"\d\d\d\d"`).
    #[builder(default, setter(strip_option, into))]
    pub validation: Option<String>,
}

impl<'a> Display for ExtcapFormatter<&'a PasswordConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(placeholder) = &self.0.placeholder {
            write!(f, "{{placeholder={}}}", placeholder)?;
        }
        if self.0.required {
            write!(f, "{{required=true}}")?;
        }
        if let Some(validation) = &self.0.validation {
            write!(f, "{{validation={}}}", validation)?;
        }
        write!(f, "{{type=password}}")?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(PasswordConfig);

/// A config that is displayed as a date/time editor.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = TimestampConfig::builder()
///     .config_number(9)
///     .call("ts")
///     .display("Start Time")
///     .tooltip("Capture start time")
///     .group("Time / Log")
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=9}{call=--ts}{display=Start Time}{tooltip=Capture start time}{group=Time / Log}{type=timestamp}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct TimestampConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the config.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The (user-visible) name of the tab which this config belongs to.
    #[builder(setter(into))]
    pub group: String,
}

impl<'a> Display for ExtcapFormatter<&'a TimestampConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        write!(f, "{{group={}}}", self.0.group)?;
        write!(f, "{{type=timestamp}}")?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(TimestampConfig);

/// Lets the user provide a file path.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = FileSelectConfig::builder()
///     .config_number(3)
///     .call("logfile")
///     .display("Logfile")
///     .tooltip("A file for log messages")
///     .must_exist(false)
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=3}{call=--logfile}{display=Logfile}{tooltip=A file for log messages}{type=fileselect}{mustexist=false}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct FileSelectConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the file selector.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The (user-visible) name of the tab which this config belongs to.
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// If true is provided, the GUI shows the user a dialog for selecting an
    /// existing file. If false, the GUI shows a file dialog for saving a file.
    #[builder(default = true)]
    pub must_exist: bool,
}

impl<'a> Display for ExtcapFormatter<&'a FileSelectConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.0.group {
            write!(f, "{{group={group}}}")?;
        }
        write!(f, "{{type=fileselect}}")?;
        write!(f, "{{mustexist={}}}", self.0.must_exist)?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(FileSelectConfig);

/// A checkbox configuration with a true/false value.
///
/// ```
/// use rust_extcap::config::*;
///
/// let config = BooleanConfig::builder()
///     .config_number(2)
///     .call("verify")
///     .display("Verify")
///     .tooltip("Verify package content")
///     .build();
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&config)),
///     "arg {number=2}{call=--verify}{display=Verify}{tooltip=Verify package content}{type=boolean}\n"
/// );
/// ```
#[derive(Debug, TypedBuilder)]
pub struct BooleanConfig {
    /// The config number, a unique identifier for this config.
    pub config_number: u8,
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    #[builder(setter(into))]
    pub call: String,
    /// The user-friendly label for the check box.
    #[builder(setter(into))]
    pub display: String,
    /// The tooltip shown on when hovering over the UI element.
    #[builder(default, setter(strip_option, into))]
    pub tooltip: Option<String>,
    /// The default value for this config.
    #[builder(default = false)]
    pub default_value: bool,
    /// If true, always include the command line flag (e.g. either `--foo true`
    /// or `--foo false`). If false (the default), the flag is provided to the
    /// command without a value if this is checked (`--foo`), or omitted from
    /// the command line arguments if unchecked.
    #[builder(default = false)]
    pub always_include_option: bool,
}

impl<'a> Display for ExtcapFormatter<&'a BooleanConfig> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.0.config_number)?;
        write!(f, "{{call=--{}}}", self.0.call)?;
        write!(f, "{{display={}}}", self.0.display)?;
        if let Some(tooltip) = &self.0.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if self.0.default_value {
            write!(f, "{{default=true}}")?;
        }
        if self.0.always_include_option {
            write!(f, "{{type=boolean}}")?;
        } else {
            write!(f, "{{type=boolflag}}")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(BooleanConfig);

/// An option for [`SelectorConfig`], [`EditSelectorConfig`], and
/// [`RadioConfig`].
#[derive(Clone, Debug, TypedBuilder)]
pub struct ConfigOptionValue {
    /// The value of this option. If this option is selected, the value will be
    /// passed to the command line. For example, if [`SelectorConfig.call`] is
    /// `foo`, and this field is `bar`, then `--foo bar` will be passed to this
    /// extcap program.
    #[builder(setter(into))]
    value: String,
    /// The user-friendly label for this option.
    #[builder(setter(into))]
    display: String,
    /// Whether this option is selected as the default. For each config there
    /// should only be one selected default.
    #[builder(default = false)]
    default: bool,
}

impl ConfigOptionValue {
    /// Prints out the config to stdout for Wireshark's consumption.
    pub fn print_config(&self, number: u8) {
        (self, number).print_config()
    }
}

impl<'a> Display for ExtcapFormatter<&'a (&ConfigOptionValue, u8)> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let (config, arg_number) = self.0;
        write!(f, "value {{arg={}}}", arg_number)?;
        write!(f, "{{value={}}}", config.value)?;
        write!(f, "{{display={}}}", config.display)?;
        write!(f, "{{default={}}}", config.default)?;
        writeln!(f)?;
        Ok(())
    }
}

/// Represents a config, which is a UI element shown in Wireshark that allows
/// the user to customize the capture.
pub trait ConfigTrait: PrintConfig + Any {
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    fn call(&self) -> &str;

    /// Returns this trait as an `Any` type.
    fn as_any(&self) -> &dyn Any;
}
