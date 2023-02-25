use typed_builder::TypedBuilder;

use crate::{threaded::{ExtcapControlSender, ExtcapControlSenderTrait}, dlt::Dlt};

pub struct Metadata {
    pub version: String,
    pub help_url: String,
    pub display_description: String,
}

impl Metadata {
    pub fn print_config(&self) {
        println!(
            "extcap {{version={}}}{{help={}}}{{display={}}}",
            self.version,
            self.help_url,
            self.display_description
        );
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
            self.value,
            self.display,
        );
    }
}
