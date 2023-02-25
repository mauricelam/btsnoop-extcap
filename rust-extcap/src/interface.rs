use std::borrow::Cow;

use crate::dlt::Dlt;

pub struct Metadata {
    pub version: Cow<'static, str>,
    pub help_url: Cow<'static, str>,
    pub display_description: Cow<'static, str>,
}

impl Metadata {
    pub fn print_config(&self) {
        println!(
            "extcap {{version={}}}{{help={}}}{{display={}}}",
            self.version, self.help_url, self.display_description
        );
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").into(),
            help_url: env!("CARGO_PKG_HOMEPAGE").into(),
            display_description: env!("CARGO_PKG_DESCRIPTION").into(),
        }
    }
}

#[derive(Debug)]
pub struct Interface {
    pub value: String,
    pub display: String,
    // Note: While the extcap-example and documentation chapter 8.2 says this is
    // a list of DLTs, in reality only one DLT per interface is supported
    // https://www.wireshark.org/lists/wireshark-dev/201511/msg00143.html
    pub dlt: Dlt,
}

impl Interface {
    pub fn print_config(&self) {
        println!(
            "interface {{value={}}}{{display={}}}",
            self.value, self.display,
        );
    }
}
