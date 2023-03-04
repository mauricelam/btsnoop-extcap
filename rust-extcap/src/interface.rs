//! Module containg code to define the extcap interfaces. These are data used to
//! popuplate the `Capture` or interface list in the main page of Wireshark.

use crate::PrintSentence;
use std::borrow::Cow;
use typed_builder::TypedBuilder;

/// Enum defining the data link types.
pub use pcap_file::DataLink;

/// Metadata for this extcap program. The version will be used for displaying
/// the version information of the extcap interface in the about dialog of
/// Wireshark.
///
/// A default implementation of `Metadata` is provided as `Metadata::default()`,
/// which extracts these information from the `version`, `homepage`, and
/// `description` attributes in the cargo manifest.
pub struct Metadata {
    /// The version of this extcap program, displayed in the about dialog of
    /// Wireshark.
    pub version: Cow<'static, str>,
    /// A URL linking to more details about this extcap program. This is the URL
    /// opened when the help button in the config dialog, or a
    /// [`HelpButtonControl`][crate::controls::HelpButtonControl] is clicked.
    pub help_url: Cow<'static, str>,
    /// A user-friendly description of the extcap program.
    pub display_description: Cow<'static, str>,
}

/// ## Example
///
/// ```
/// # use rust_extcap::ExtcapFormatter;
/// use rust_extcap::interface::Metadata;
///
/// let metadata = Metadata {
///     version: "3.2.1-test".into(),
///     help_url: "http://www.wireshark.org".into(),
///     display_description: "Just for testing".into(),
/// };
/// assert_eq!(
///     format!("{}", ExtcapFormatter(&metadata)),
///     "extcap {version=3.2.1-test}{help=http://www.wireshark.org}{display=Just for testing}\n"
/// )
/// ```
impl PrintSentence for Metadata {
    fn format_sentence(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "extcap {{version={}}}{{help={}}}{{display={}}}",
            self.version, self.help_url, self.display_description
        )
    }
}

/// Definition of an interface for this extcap program. An interface is an entry
/// in the Wireshark homepage, similar to `Wi-Fi: en0`. Instances of this should
/// be returned in
/// [`ExtcapApplication::interfaces`][crate::ExtcapApplication::interfaces].
#[derive(Debug)]
pub struct Interface {
    /// A unique identifier for this interface. This value will be passed back
    /// from Wireshark in the `--extcap-interface` argument in subsequent calls
    /// to indicate which interface the user is working with. (When using
    /// [`ExtcapApplication`][crate::ExtcapApplication], the corresponding
    /// interface is resolved for you using this `value` as the key).
    pub value: Cow<'static, str>,
    /// A user-readable string describing this interface, which is shown in the
    /// Wireshark UI.
    pub display: Cow<'static, str>,
    /// The DLT associated with this interface. The DLT is used by Wireshark to
    /// determine how to dissect the packet data given by this extcap program.
    ///
    /// Note: While the extcap-example and documentation chapter 8.2 says this
    /// is a list of DLTs, in reality only one DLT per interface is supported,
    /// per [this
    /// thread](https://www.wireshark.org/lists/wireshark-dev/201511/msg00143.html).
    pub dlt: Dlt,
}

/// ```
/// use rust_extcap::config::ExtcapFormatter;
/// use rust_extcap::interface::{DataLink, Dlt, Interface};
/// # let dlt = Dlt {
/// #     data_link_type: DataLink::ETHERNET,
/// #     name: "ETHERNET".into(),
/// #     display: "IEEE 802.3 Ethernet".into(),
/// # };
/// assert_eq!(
///     ExtcapFormatter(&Interface{ value: "MyInterface".into(), display: "My interface".into(), dlt }).to_string(),
///     "interface {value=MyInterface}{display=My interface}\n",
/// );
/// ```
impl PrintSentence for Interface {
    fn format_sentence(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "interface {{value={}}}{{display={}}}",
            self.value, self.display,
        )
    }
}

/// Struct defining the DLT to be used for this extcap. Typically the DLT is
/// defined together with the [`Interface`][crate::interface::Interface] and
/// used in the [`ExtcapApplication`][crate::ExtcapApplication]. But you can
/// also use this class standalone and print out the resulting config using the
/// [`print_sentence`][crate::PrintSentence::print_sentence] method.
#[derive(Clone, Debug, TypedBuilder)]
pub struct Dlt {
    /// The data link type this packet should be analyzed as.
    ///
    /// See: <http://www.tcpdump.org/linktypes.html> for the list of DLTs.
    pub data_link_type: DataLink,

    /// The name of this DLT. Typically this is the same as the name in
    /// <http://www.tcpdump.org/linktypes.html> without the `LINKTYPE_` prefix.
    pub name: Cow<'static, str>,

    /// A user-friendly string describing this DLT.
    pub display: Cow<'static, str>,
}

/// Print the configuration line suitable for use with `--extcap-dlts`.
///
/// ## Example
/// ```
/// use rust_extcap::config::ExtcapFormatter;
/// use rust_extcap::interface::{DataLink, Dlt};
///
/// let dlt = Dlt {
///     data_link_type: DataLink::ETHERNET,
///     name: "ETHERNET".into(),
///     display: "IEEE 802.3 Ethernet".into(),
/// };
/// assert_eq!(
///     ExtcapFormatter(&dlt).to_string(),
///     "dlt {number=1}{name=ETHERNET}{display=IEEE 802.3 Ethernet}\n",
/// );
/// ```
impl PrintSentence for Dlt {
    fn format_sentence(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "dlt {{number={}}}{{name={}}}{{display={}}}",
            <u32>::from(self.data_link_type),
            self.name,
            self.display
        )
    }
}
