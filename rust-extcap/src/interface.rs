use std::{borrow::Cow, fmt::Display};

use crate::{dlt::Dlt, ExtcapFormatter};

pub struct Metadata {
    pub version: Cow<'static, str>,
    pub help_url: Cow<'static, str>,
    pub display_description: Cow<'static, str>,
}

impl Display for ExtcapFormatter<&Metadata> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "extcap {{version={}}}{{help={}}}{{display={}}}",
            self.0.version, self.0.help_url, self.0.display_description
        )
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

impl Display for ExtcapFormatter<&Interface> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "interface {{value={}}}{{display={}}}",
            self.0.value, self.0.display,
        )
    }
}
