//! Module for implementing extcap config (also known as `arg`), which are UI
//! elements shown in Wireshark that allows the user to customize the capture.
//!
//! Each interface can have custom options that are valid for this interface
//! only. Those config options are specified on the command line when running
//! the actual capture.

use std::any::Any;
use std::fmt::Debug;
use std::ops::RangeInclusive;
use typed_builder::TypedBuilder;

pub use crate::{ExtcapFormatter, PrintSentence};

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

/// Defines a reload operation for [`SelectorConfig`].
pub struct Reload {
    /// The label for the reload button displayed next to the selector config.
    pub label: String,
    /// The reload function executed when the reload button is pressed. Note
    /// that this reload operation is run in a separate invocation of the
    /// program, meaning it should not rely on any in-memory state.
    pub reload_fn: fn() -> Vec<ConfigOptionValue>,
}

impl std::fmt::Debug for Reload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Reload(label={})", self.label)
    }
}

/// A selector config UI element that allows the user to select an option from a
/// drop-down list. The list of options should have default=true on exactly one
/// item.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// value of this function. The first element of the pair is the label of
    /// the button, and the second element is the function that will be invoked
    /// on click.
    ///
    /// Note: In extcap, the key for the button label is called `placeholder`,
    /// for some reason.
    #[builder(default, setter(strip_option))]
    pub reload: Option<Reload>,
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// The default list of options presented by this selector.
    #[builder(setter(into))]
    pub default_options: Vec<ConfigOptionValue>,
}

impl PrintSentence for SelectorConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        write!(f, "{{type=selector}}")?;
        if let Some(Reload { label, .. }) = &self.reload {
            write!(f, "{{reload=true}}")?;
            write!(f, "{{placeholder={label}}}")?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        writeln!(f)?;
        for opt in self.default_options.iter() {
            write!(f, "{}", ExtcapFormatter(&(opt, self.config_number)))?;
        }
        Ok(())
    }
}

generate_config_ext!(SelectorConfig);

/// A list of radio buttons for the user to choose one value from. The list of
/// options should have exactly one item with default=true.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// The default list of options presented by this config.
    #[builder(setter(into))]
    pub options: Vec<ConfigOptionValue>,
}

impl PrintSentence for RadioConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={}}}", group)?;
        }
        write!(f, "{{type=radio}}")?;
        writeln!(f)?;
        for opt in self.options.iter() {
            write!(f, "{}", ExtcapFormatter(&(opt, self.config_number)))?;
        }
        Ok(())
    }
}

generate_config_ext!(RadioConfig);

/// A tree of hierarchical check boxes that the user can select.
///
/// The values are passed comma-separated into the extcap command line. For
/// example, if the check boxes for `if1`, `if2a`, and `if2b` are checked in the
/// example below, then `--multi if1,if2a,if2b` will be passed in the command
/// line.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
///
/// To parse those values as a `vec`, you can use the `value_delimiter` option
/// in `clap`.
///
/// ```ignore
/// #[arg(long, value_delimiter = ',')]
/// multi: Vec<String>,
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// The default list of options presented by this config. This can be refreshed by the user using via the `reload` field.
    #[builder(setter(into))]
    pub options: Vec<MultiCheckValue>,
}

impl PrintSentence for MultiCheckConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={}}}", group)?;
        }
        write!(f, "{{type=multicheck}}")?;
        writeln!(f)?;
        for opt in self.options.iter() {
            write!(f, "{}", ExtcapFormatter(&(opt, self.config_number, None)))?;
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
    pub value: String,
    /// The user-friendly label for this check box.
    #[builder(setter(into))]
    pub display: String,
    /// The default value for this check box, whether it is checked or not.
    #[builder(default = false)]
    pub default_value: bool,
    /// Whether this checkbox is enabled or not.
    #[builder(default = true)]
    pub enabled: bool,
    /// The list of children checkboxes. Children check boxes will be indented
    /// under this check box in the UI, but does not change how the value gets
    /// sent to the extcap program.
    #[builder(default, setter(into))]
    pub children: Vec<MultiCheckValue>,
}

impl PrintSentence for (&MultiCheckValue, u8, Option<&MultiCheckValue>) {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let (config, config_number, parent) = self;
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
            write!(
                f,
                "{}",
                ExtcapFormatter(&(c, *config_number, Some(*config)))
            )?;
        }
        Ok(())
    }
}

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl PrintSentence for LongConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.default_value)?;
        write!(f, "{{type=long}}")?;
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(LongConfig);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl PrintSentence for IntegerConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.default_value)?;
        write!(f, "{{type=integer}}")?;
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(IntegerConfig);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl PrintSentence for UnsignedConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.default_value)?;
        write!(f, "{{type=unsigned}}")?;
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(UnsignedConfig);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl PrintSentence for DoubleConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(range) = &self.range {
            write!(f, "{{range={},{}}}", range.start(), range.end())?;
        }
        write!(f, "{{default={}}}", self.default_value)?;
        write!(f, "{{type=double}}")?;
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(DoubleConfig);

/// A field for entering a text value.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
#[allow(deprecated)]
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
    #[builder(default = false)]
    pub required: bool,
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
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
    /// This option is undocumented, and does not behave correctly when set to
    /// false in my testing. Perhaps related to
    /// <https://gitlab.com/wireshark/wireshark/-/issues/18487>.
    #[deprecated(
        note = "This is undocumented, and does not behave correctly when set to false in my testing."
    )]
    #[builder(default = true)]
    pub save: bool,
}

impl PrintSentence for StringConfig {
    #[allow(deprecated)]
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(placeholder) = &self.placeholder {
            write!(f, "{{placeholder={}}}", placeholder)?;
        }
        if self.required {
            write!(f, "{{required=true}}")?;
        }
        if let Some(validation) = &self.validation {
            write!(f, "{{validation={}}}", validation)?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        write!(f, "{{save={}}}", self.save)?;
        write!(f, "{{type=string}}")?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(StringConfig);

/// A field for entering text value, but with its value masked in the user
/// interface. The value of a password field is not saved by Wireshark.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl PrintSentence for PasswordConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(placeholder) = &self.placeholder {
            write!(f, "{{placeholder={}}}", placeholder)?;
        }
        if self.required {
            write!(f, "{{required=true}}")?;
        }
        if let Some(validation) = &self.validation {
            write!(f, "{{validation={}}}", validation)?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        write!(f, "{{type=password}}")?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(PasswordConfig);

/// A config that is displayed as a date/time editor.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl PrintSentence for TimestampConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        write!(f, "{{type=timestamp}}")?;
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(TimestampConfig);

/// Lets the user provide a file path.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// If true is provided, the GUI shows the user a dialog for selecting an
    /// existing file. If false, the GUI shows a file dialog for saving a file.
    #[builder(default = true)]
    pub must_exist: bool,
    /// If set, provide a filter for the file extension selectable by this
    /// config. The format of the filter string is the same as qt's
    /// [`QFileDialog`](https://doc.qt.io/qt-6/qfiledialog.html).
    ///
    /// For example, the filter `Text files (*.txt);;XML files (*.xml)` will
    /// limit to `.txt` and `.xml` files:
    ///
    /// If `None`, any file can be selected (equivalent to `All Files (*)`).
    ///
    /// This feature is currnetly not documented in the Wireshark docs, but a
    /// high level detail can be found in this commit:
    /// <https://gitlab.com/wireshark/wireshark/-/commit/0d47113ddc53714ecd6d3c1b58b694321649d89e>
    #[builder(default, setter(into, strip_option))]
    pub file_extension_filter: Option<String>,
}

impl PrintSentence for FileSelectConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        write!(f, "{{type=fileselect}}")?;
        write!(f, "{{mustexist={}}}", self.must_exist)?;
        if let Some(file_extension_filter) = &self.file_extension_filter {
            write!(f, "{{fileext={}}}", file_extension_filter)?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(FileSelectConfig);

/// A checkbox configuration with a true/false value.
///
/// Typically, these configs are created in a `lazy_static`, either as their own
/// static refs, or as fields of your `ExtcapApplication` implementation, and
/// then returned from
/// [`ExtcapApplication::configs`][crate::ExtcapApplication::configs].
///
/// ## Example
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
    /// The (user-visible) name of the tab which this config belongs to. If this
    /// is `None`, the config will be placed in a tab called "Default".
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    /// If true, always include the command line flag (e.g. either `--foo true`
    /// or `--foo false`). If false (the default), the flag is provided to the
    /// command without a value if this is checked (`--foo`), or omitted from
    /// the command line arguments if unchecked.
    #[builder(default = false)]
    pub always_include_option: bool,
}

impl PrintSentence for BooleanConfig {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "arg {{number={}}}", self.config_number)?;
        write!(f, "{{call=--{}}}", self.call)?;
        write!(f, "{{display={}}}", self.display)?;
        if let Some(tooltip) = &self.tooltip {
            write!(f, "{{tooltip={tooltip}}}")?;
        }
        if self.default_value {
            write!(f, "{{default=true}}")?;
        }
        if self.always_include_option {
            write!(f, "{{type=boolean}}")?;
        } else {
            write!(f, "{{type=boolflag}}")?;
        }
        if let Some(group) = &self.group {
            write!(f, "{{group={group}}}")?;
        }
        writeln!(f)?;
        Ok(())
    }
}

generate_config_ext!(BooleanConfig);

/// An option for [`SelectorConfig`] and [`RadioConfig`].
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
    /// Prints out the extcap sentence to stdout for Wireshark's consumption.
    pub fn print_sentence(&self, number: u8) {
        (self, number).print_sentence()
    }
}

impl PrintSentence for (&ConfigOptionValue, u8) {
    fn format_sentence(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let (config, arg_number) = self;
        write!(f, "value {{arg={}}}", arg_number)?;
        write!(f, "{{value={}}}", config.value)?;
        write!(f, "{{display={}}}", config.display)?;
        write!(f, "{{default={}}}", config.default)?;
        writeln!(f)?;
        Ok(())
    }
}

/// Represents a config, also known as `arg` in an extcap sentence`, which is a
/// UI element shown in Wireshark that allows the user to customize the capture.
pub trait ConfigTrait: PrintSentence + Any {
    /// The command line option that will be sent to this extcap program. For
    /// example, if this field is `foobar`, and the corresponding value is `42`,
    /// then `--foobar 42` will be sent to this program during the extcap
    /// capture.
    fn call(&self) -> &str;

    /// Returns this trait as an `Any` type.
    fn as_any(&self) -> &dyn Any;
}
