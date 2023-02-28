use crate::config::ExtcapFormatter;
use std::fmt::Display;
use typed_builder::TypedBuilder;

/// Enum defining the data link types.
pub use pcap_file::DataLink;

/// Struct defining the DLT to be used for this extcap. Typically the DLT is
/// defined together with the [`Interface`][crate::interface::Interface] and
/// used in the [`ExtcapApplication`][crate::ExtcapApplication]. But you can
/// also use this class standalone and print out the resulting config using the
/// [`print_config`][Self::print_config] method.
#[derive(Clone, Debug, TypedBuilder)]
pub struct Dlt {
    /// The data link type this packet should be analyzed as.
    ///
    /// See: <http://www.tcpdump.org/linktypes.html> for the list of DLTs.
    pub data_link_type: DataLink,

    /// The name of this DLT. Typically this is the same as the name in
    /// <http://www.tcpdump.org/linktypes.html> without the `LINKTYPE_` prefix.
    pub name: String,

    /// A user-friendly string describing this DLT.
    pub display: String,
}

impl Display for ExtcapFormatter<&Dlt> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "dlt {{number={}}}{{name={}}}{{display={}}}",
            <u32>::from(self.0.data_link_type),
            self.0.name,
            self.0.display
        )
    }
}

impl Dlt {
    /// Print the configuration line suitable for use with `--extcap-dlts`.
    ///
    /// ```
    /// use rust_extcap::config::ExtcapFormatter;
    /// use rust_extcap::dlt::{DataLink, Dlt};
    ///
    /// let dlt = Dlt {
    ///     data_link_type: DataLink::ETHERNET,
    ///     name: String::from("ETHERNET"),
    ///     display: String::from("IEEE 802.3 Ethernet"),
    /// };
    /// assert_eq!(
    ///     ExtcapFormatter(&dlt).to_string(),
    ///     "dlt {number=1}{name=ETHERNET}{display=IEEE 802.3 Ethernet}\n",
    /// );
    /// ```
    pub fn print_config(&self) {
        print!("{}", ExtcapFormatter(self))
    }
}
