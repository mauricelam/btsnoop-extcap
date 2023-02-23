use derive_builder::Builder;
use std::{
    any::Any,
    ops::{DerefMut, Range},
};
use typed_builder::TypedBuilder;

macro_rules! config_builder {
    ($config_type:ty, $builder_type:ty, $fnname:ident) => {
        impl ConfigContainer {
            pub fn $fnname<Complete: Into<$config_type>>(
                &mut self,
                f: impl Fn(<$config_type as ConfigTrait>::Builder) -> Complete,
            ) -> u8 {
                self.push_config::<$config_type, _>(f)
            }
        }

        impl ConfigTrait for $config_type {
            type Builder = $builder_type;

            fn builder(number: u8) -> Self::Builder
            where
                Self: Sized,
            {
                Self::builder().number(number)
            }
        }
    };
}

// TODO: Consistent naming: Either Control or Arg or Config.
/// Option fields where the user may choose from one or more options. If parent
/// is provided for the value items, the option fields for multicheck and
/// selector are presented in a tree-like structure. selector and radio values
/// must present a default value, which will be the value provided to the extcap
/// binary for this argument. editselector option fields let the user select
/// from a list of items or enter a custom value.
/// ```text
/// arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}
/// value {arg=3}{value=if1}{display=Remote1}{default=true}
/// value {arg=3}{value=if2}{display=Remote2}{default=false}
/// ```
#[derive(TypedBuilder)]
pub struct SelectorConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default)]
    pub reload: bool,
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    #[builder(setter(into))]
    pub options: Vec<ArgValue>,
}

impl WithConfig for SelectorConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(placeholder) = &self.placeholder {
            print!("{{placeholder={}}}", placeholder);
        }
        print!("{{type=selector}}");
        print!("{{reload={}}}", self.reload);
        println!();
        for opt in self.options.iter() {
            opt.print_config(self.number);
        }
    }
}

config_builder!(
    SelectorConfig,
    SelectorConfigBuilder<((u8,), (), (), (), (), (), ())>,
    selector
);

/// Option fields where the user may choose from one or more options. If parent
/// is provided for the value items, the option fields for multicheck and
/// selector are presented in a tree-like structure. selector and radio values
/// must present a default value, which will be the value provided to the extcap
/// binary for this argument. editselector option fields let the user select
/// from a list of items or enter a custom value.
/// ```text
/// arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}
/// value {arg=3}{value=if1}{display=Remote1}{default=true}
/// value {arg=3}{value=if2}{display=Remote2}{default=false}
/// ```
#[derive(TypedBuilder)]
pub struct EditSelectorConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default)]
    pub reload: bool,
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    #[builder(setter(into))]
    pub options: Vec<ArgValue>,
}

impl WithConfig for EditSelectorConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(placeholder) = &self.placeholder {
            print!("{{placeholder={}}}", placeholder);
        }
        print!("{{type=editselector}}");
        print!("{{reload={}}}", self.reload);
        println!();
        for opt in self.options.iter() {
            opt.print_config(self.number);
        }
    }
}

impl ConfigTrait for EditSelectorConfig {
    type Builder = EditSelectorConfigBuilder<((u8,), (), (), (), (), (), ())>;

    fn builder(number: u8) -> Self::Builder
    where
        Self: Sized,
    {
        Self::builder().number(number)
    }
}

/// Option fields where the user may choose from one or more options. If parent
/// is provided for the value items, the option fields for multicheck and
/// selector are presented in a tree-like structure. selector and radio values
/// must present a default value, which will be the value provided to the extcap
/// binary for this argument. editselector option fields let the user select
/// from a list of items or enter a custom value.
/// ```text
/// arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}
/// value {arg=3}{value=if1}{display=Remote1}{default=true}
/// value {arg=3}{value=if2}{display=Remote2}{default=false}
/// ```
#[derive(TypedBuilder)]
pub struct RadioConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    #[builder(setter(into))]
    pub options: Vec<ArgValue>,
}

impl WithConfig for RadioConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(group) = &self.group {
            print!("{{group={}}}", group);
        }
        print!("{{type=radio}}");
        println!();
        for opt in self.options.iter() {
            opt.print_config(self.number);
        }
    }
}

config_builder!(
    RadioConfig,
    RadioConfigBuilder<((u8,), (), (), (), (), ())>,
    radio
);

/// Option fields where the user may choose from one or more options. If parent
/// is provided for the value items, the option fields for multicheck and
/// selector are presented in a tree-like structure. selector and radio values
/// must present a default value, which will be the value provided to the extcap
/// binary for this argument. editselector option fields let the user select
/// from a list of items or enter a custom value.
/// ```text
/// arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}
/// value {arg=3}{value=if1}{display=Remote1}{default=true}
/// value {arg=3}{value=if2}{display=Remote2}{default=false}
/// ```
#[derive(TypedBuilder)]
pub struct MultiCheckConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
    #[builder(setter(into))]
    pub options: Vec<MultiCheckValue>,
}

impl WithConfig for MultiCheckConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(group) = &self.group {
            print!("{{group={}}}", group);
        }
        print!("{{type=multicheck}}");
        println!();
        for opt in self.options.iter() {
            opt.print_config(self.number, None);
        }
    }
}

config_builder!(
    MultiCheckConfig,
    MultiCheckConfigBuilder<((u8,), (), (), (), (), ())>,
    multi_check
);

#[derive(TypedBuilder, Clone)]
pub struct MultiCheckValue {
    #[builder(setter(into))]
    value: String,
    #[builder(setter(into))]
    display: String,
    #[builder(default)]
    default_value: bool,
    #[builder(default = true)]
    enabled: bool,
    #[builder(default, setter(into))]
    children: Vec<MultiCheckValue>,
}

impl MultiCheckValue {
    fn print_config(&self, arg_number: u8, parent: Option<&Self>) {
        print!("value {{arg={}}}", arg_number);
        print!("{{value={}}}", self.value);
        print!("{{display={}}}", self.display);
        print!("{{default={}}}", self.default_value);
        print!("{{enabled={}}}", self.enabled);
        if let Some(parent) = parent {
            print!("{{parent={}}}", parent.value);
        }
        println!();
        for c in self.children.iter() {
            c.print_config(arg_number, Some(self));
        }
    }
}

// impl MultiCheckValueBuilder {
//     pub fn new(value: &str, display: &str) -> Self {
//         let mut builder = Self::default();
//         builder.value(value).display(display);
//         builder
//     }
// }

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
/// ```text
/// arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{type=integer}{range=1,15}{default=0}
/// ```
#[derive(TypedBuilder)]
pub struct LongConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option))]
    pub range: Option<Range<i64>>,
    pub default_value: i64,
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl WithConfig for LongConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(Range { start, end }) = self.range {
            print!("{{range={start},{end}}}");
        }
        print!("{{default={}", self.default_value);
        print!("{{type=long}}");
        if let Some(group) = &self.group {
            print!("{{group={}}}", group);
        }
        println!();
    }
}

config_builder!(
    LongConfig,
    LongConfigBuilder<((u8,), (), (), (), (), (), ())>,
    long
);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
/// ```text
/// arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{type=integer}{range=1,15}{default=0}
/// ```
#[derive(TypedBuilder)]
pub struct IntegerConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option))]
    pub range: Option<Range<i32>>,
    pub default_value: i32,
}

impl WithConfig for IntegerConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(Range { start, end }) = self.range {
            print!("{{range={start},{end}}}");
        }
        print!("{{default={}}}", self.default_value);
        print!("{{type=integer}}");
        println!();
    }
}

config_builder!(
    IntegerConfig,
    IntegerConfigBuilder<((u8,), (), (), (), (), ())>,
    integer
);

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
/// ```text
/// arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{type=unsigned}{range=1,15}{default=0}
/// ```
#[derive(TypedBuilder)]
pub struct UnsignedConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option, into))]
    pub range: Option<Range<u32>>,
    pub default_value: u32,
}

impl ConfigTrait for UnsignedConfig {
    type Builder = UnsignedConfigBuilder<((u8,), (), (), (), (), ())>;

    fn builder(number: u8) -> Self::Builder
    where
        Self: Sized,
    {
        Self::builder().number(number)
    }
}

impl WithConfig for UnsignedConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(Range { start, end }) = self.range {
            print!("{{range={start},{end}}}");
        }
        print!("{{default={}}}", self.default_value);
        print!("{{type=unsigned}}");
        println!();
    }
}

/// This provides a field for entering a numeric value of the given data type. A
/// default value may be provided, as well as a range.
/// ```text
/// arg {number=0}{call=--delay}{display=Time delay}{tooltip=Time delay between packages}{type=integer}{range=1,15}{default=0}
/// ```
#[derive(TypedBuilder)]
pub struct DoubleConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option))]
    pub range: Option<Range<f64>>,
    pub default_value: f64,
    #[builder(default, setter(strip_option, into))]
    pub group: Option<String>,
}

impl WithConfig for DoubleConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(Range { start, end }) = self.range {
            print!("{{range={start},{end}}}");
        }
        print!("{{default={}", self.default_value);
        print!("{{type=double}}");
        if let Some(group) = &self.group {
            print!("{{group={}}}", group);
        }
        println!();
    }
}

config_builder!(
    DoubleConfig,
    DoubleConfigBuilder<((u8,), (), (), (), (), (), ())>,
    double
);

/// This provides a field for entering a text value.
/// ```text
/// arg {number=1}{call=--server}{display=IP Address}{tooltip=IP Address for log server}{type=string}{validation=\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b}
/// ```
/// validation allows to provide a regular expression string, which is used to
/// check the user input for validity beyond normal data type or range checks.
/// Back-slashes must be escaped (as in \\b for \b)
#[derive(TypedBuilder)]
pub struct StringConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    #[builder(default)]
    pub required: bool,
    #[builder(default, setter(strip_option, into))]
    pub validation: Option<String>,
    #[builder(default)]
    pub save: bool,
}

impl WithConfig for StringConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(placeholder) = &self.placeholder {
            print!("{{placeholder={}}}", placeholder);
        }
        print!("{{required={}}}", self.required);
        if let Some(validation) = &self.validation {
            print!("{{validation={}}}", validation);
        }
        print!("{{save={}}}", self.save);
        print!("{{type=string}}");
        println!();
    }
}

config_builder!(
    StringConfig,
    StringConfigBuilder<((u8,), (), (), (), (), (), (), ())>,
    string
);

/// Lets the user provide a masked string to the capture. Password strings are
/// not saved with other capture settings.
/// ```text
/// arg {number=0}{call=--password}{display=The user password}{tooltip=The password for the connection}{type=password}
/// ```
#[derive(TypedBuilder)]
pub struct PasswordConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(default, setter(strip_option, into))]
    pub placeholder: Option<String>,
    #[builder(default)]
    pub required: bool,
    #[builder(default, setter(strip_option, into))]
    pub validation: Option<String>,
}

impl WithConfig for PasswordConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        if let Some(placeholder) = &self.placeholder {
            print!("{{placeholder={}}}", placeholder);
        }
        print!("{{required={}}}", self.required);
        if let Some(validation) = &self.validation {
            print!("{{validation={}}}", validation);
        }
        print!("{{type=password}}");
        println!();
    }
}

config_builder!(
    PasswordConfig,
    PasswordConfigBuilder<((u8,), (), (), (), (), (), ())>,
    password
);

/// A time value displayed as a date/time editor.
#[derive(TypedBuilder)]
pub struct TimestampConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(setter(into))]
    pub group: String,
}

impl WithConfig for TimestampConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        print!("{{group={}}}", self.group);
        print!("{{type=timestamp}}");
        println!();
    }
}

config_builder!(
    TimestampConfig,
    TimestampConfigBuilder<((u8,), (), (), (), ())>,
    timestamp
);

/// Lets the user provide a file path. If mustexist=true is provided, the GUI
/// shows the user a dialog for selecting a file. When mustexist=false is used,
/// the GUI shows the user a file dialog for saving a file.
/// ```text
/// arg {number=3}{call=--logfile}{display=Logfile}{tooltip=A file for log messages}{type=fileselect}{mustexist=false}
/// ```
#[derive(TypedBuilder)]
pub struct FileSelectConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    #[builder(setter(into))]
    pub group: String,
}

impl WithConfig for FileSelectConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        print!("{{group={}}}", self.group);
        print!("{{type=fileselect}}");
        println!();
    }
}

config_builder!(
    FileSelectConfig,
    FileSelectConfigBuilder<((u8,), (), (), (), ())>,
    file_select
);

/// This provides the possibility to set a true/false value.
/// ```text
/// arg {number=2}{call=--verify}{display=Verify}{tooltip=Verify package content}{type=boolflag}
/// ```
#[derive(TypedBuilder)]
pub struct BoolConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    pub default_value: bool,
}

impl ConfigTrait for BoolConfig {
    type Builder = BoolConfigBuilder<((u8,), (), (), (), ())>;

    fn builder(number: u8) -> Self::Builder
    where
        Self: Sized,
    {
        Self::builder().number(number)
    }
}

impl WithConfig for BoolConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        print!(
            "{{default={}}}",
            if self.default_value { "yes" } else { "no" }
        );
        print!("{{type=bool}}");
        println!();
    }
}

pub trait WithConfig {
    fn print_config(&self);
}

pub trait ConfigTrait: WithConfig {
    type Builder;

    fn builder(number: u8) -> Self::Builder
    where
        Self: Sized;
}

#[derive(Default)]
pub struct ConfigContainer {
    next_number: u8,
    configs: Vec<Box<dyn WithConfig>>,
}

impl ConfigContainer {
    pub fn next_number(&mut self) -> u8 {
        let num = self.next_number;
        self.next_number += 1;
        num
    }

    fn push_config<V, CompleteBuilder>(
        &mut self,
        f: impl FnOnce(V::Builder) -> CompleteBuilder,
    ) -> u8
    where
        V: ConfigTrait + 'static,
        CompleteBuilder: Into<V>,
    {
        let next_number = self.next_number();
        let builder = V::builder(next_number);
        let complete = f(builder).into();
        self.configs.push(Box::new(complete));
        next_number
    }

    pub fn print_configs(&self) {
        for config in self.configs.iter() {
            config.print_config();
        }
    }
}

/// This provides the possibility to set a true/false value. boolflag values
/// will only appear in the command line if set to true, otherwise they will not
/// be added to the command-line call for the extcap interface.
#[derive(TypedBuilder)]
pub struct BoolFlagConfig {
    pub number: u8,
    #[builder(setter(into))]
    pub call: String,
    #[builder(setter(into))]
    pub display: String,
    #[builder(setter(into))]
    pub tooltip: String,
    pub default_value: bool,
}

impl WithConfig for BoolFlagConfig {
    fn print_config(&self) {
        print!("arg {{number={}}}", self.number);
        print!("{{call={}}}", self.call);
        print!("{{display={}}}", self.display);
        print!("{{tooltip={}}}", self.tooltip);
        print!(
            "{{default={}}}",
            if self.default_value { "yes" } else { "no" }
        );
        print!("{{type=boolflag}}");
        println!();
    }
}

config_builder!(
    BoolFlagConfig,
    BoolFlagConfigBuilder<((u8,), (), (), (), ())>,
    bool_flag
);

#[derive(TypedBuilder, Clone)]
pub struct ArgValue {
    #[builder(setter(into))]
    value: String,
    #[builder(setter(into))]
    display: String,
    #[builder(default = false)]
    default: bool,
}

impl ArgValue {
    pub fn print_config(&self, arg_number: u8) {
        print!("value {{arg={}}}", arg_number);
        print!("{{value={}}}", self.value);
        print!("{{display={}}}", self.display);
        print!("{{default={}}}", self.default);
        println!();
    }
}
