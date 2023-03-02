//! Utilities for working with the extcap interface. The extcap interface is a
//! versatile plugin interface used by Wireshark to allow external binaries to
//! act as capture interfaces.
//!
//! References:
//! * <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html>
//! * <https://www.wireshark.org/docs/man-pages/extcap.html>
//! * <https://gitlab.com/wireshark/wireshark/-/blob/master/doc/extcap_example.py>

#![deny(missing_docs)]

use clap::Args;
use config::{ConfigTrait, SelectorConfig};
use controls::ToolbarControl;
use interface::{Interface, Metadata};
use std::{fmt::Display, path::PathBuf};
use thiserror::Error;

pub mod config;
pub mod controls;
pub mod interface;

/// The arguments defined by extcap. These arguments are usable as a clap
/// parser.
///
/// For example, if you use `clap` with the feature `derive`:
/// ```
/// # use clap::Parser;
/// #[derive(Debug, Parser)]
/// #[command(author, version, about)]
/// pub struct ApplicationArgs {
///    #[command(flatten)]
///    extcap: rust_extcap::ExtcapArgs,
///
///    // Other application args
/// }
/// ```
///
/// Wireshark will call extcap in 4 phases:
///
/// 1. [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces]: Declare all
///    supported interfaces and controls.
/// 2. [`--extcap-config`][ExtcapArgs::extcap_config]: Called for each interface
///    to declare configuration options that can be changed by the user in the
///    UI. (This is used only in Wireshark, not available in tshark).
/// 3. [`--extcap-dlts`][ExtcapArgs::extcap_dlts]: Called for each interface
///    returned in `--extcap-interfaces` to specify which Data Link Type is
///    being captured.
/// 4. [`--capture`][ExtcapArgs::capture]: Called to initiate capture of the
///    packets. See the documentation on the field for details.
///
/// When the capturing stops (i.e. the user presses the red Stop button),
/// `SIGTERM` is sent by Wireshark.
#[derive(Debug, Args)]
pub struct ExtcapArgs {
    /// First step in the extcap exchange: this program is queried for its
    /// interfaces.
    /// ```sh
    /// $ extcapbin --extcap-interfaces
    /// ```
    /// This call must print the existing interfaces for this extcap and must
    /// return 0. The output must conform to the grammar specified in the
    /// [doc/extcap.4](https://www.wireshark.org/docs/man-pages/extcap.html)
    /// man pages.
    #[arg(long, verbatim_doc_comment)]
    pub extcap_interfaces: bool,

    /// The version of Wireshark (or tshark) calling into this extcap.
    ///
    /// Wireshark 2.9 and later pass `--extcap-version=x.x` when querying for
    /// the list of interfaces, which provides the calling Wireshark's major and
    /// minor version. This can be used to change behavior depending on the
    /// Wireshark version in question.
    ///
    /// This argument is passed during the
    /// [`--extcap-interfaces`][ExtcapArgs::extcap_interfaces] call.
    #[arg(long)]
    pub extcap_version: Option<String>,

    /// Second step in the extcap exchange: this program is asked for the configuration of each
    /// specific interface
    /// ```sh
    /// $ extcap_example.py --extcap-interface <iface> --extcap-config
    /// ```
    ///
    /// Each interface can have custom options that are valid for this interface only. Those config
    /// options are specified on the command line when running the actual capture. To allow an
    /// end-user to specify certain options, such options may be provided using the extcap config
    /// argument.
    ///
    /// To share which options are available for an interface, the extcap responds to the command
    /// `--extcap-config`, which shows all the available options (aka additional command line
    /// options).
    ///
    /// Those options are used to build a configuration dialog for the interface.
    #[arg(long, verbatim_doc_comment)]
    pub extcap_config: bool,

    /// Third step in the extcap exchange: the extcap binary is queried for all valid DLTs for all
    /// the interfaces returned during [`--extcap-interfaces`][Self::extcap_interfaces]).
    ///
    /// ```sh
    /// $ extcap_example.py --extcap-dlts --extcap-interface <iface>
    /// ```
    ///
    /// This call must print the valid DLTs for the interface specified. This call is made for all
    /// the interfaces and must return exit code 0.
    ///
    /// Example for the DLT query.
    /// ```sh
    /// $ extcap_example.py --extcap-interface IFACE --extcap-dlts
    /// dlt {number=147}{name=USER1}{display=Demo Implementation for Extcap}
    /// ```
    ///
    /// A binary or script which neither provides an interface list or a DLT list will not show up
    /// in the extcap interfaces list.
    #[arg(long, requires = "extcap_interface", verbatim_doc_comment)]
    pub extcap_dlts: bool,

    /// Start the capturing phase.
    ///
    /// In addition to `--capture`, the
    /// [`--extcap-capture-filter`][ExtcapArgs::extcap_capture_filter] and
    /// [`--fifo`][ExtcapArgs::fifo] options are also required in this phase.
    ///
    /// Additionally, if `{config}` entries were returned during the
    /// `--extcap-interfaces` phase, then
    /// [`--extcap-control-in`][ExtcapArgs::extcap_control_in] and
    /// [`--extcap-control-out`][ExtcapArgs::extcap_control_out] will be passed,
    /// which are a pair of fifos in which [control
    /// messages](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#_messages)
    /// are sent.
    #[arg(long, requires = "fifo", requires = "extcap_interface")]
    pub capture: bool,

    /// The extcap interface to perform the operation on.
    ///
    /// This should match one of the values returned earlier in
    /// [`extcap_interfaces`][Self::extcap_interfaces], and is used in the
    /// [`capture`][Self::capture], [`extcap_config`][Self::extcap_config], and
    /// [`extcap_dlts`][Self::extcap_dlts] phases.
    #[arg(long)]
    pub extcap_interface: Option<String>,

    /// Specifies the fifo for the packet captures. The extcap implementation
    /// should write the captured packets to this fifo in pcap or pcapng format.
    #[arg(long, requires = "capture")]
    pub fifo: Option<PathBuf>,

    /// The capture filter provided by wireshark. This extcap should avoid capturing packets that do
    /// not match this filter. Used during the `--capture` phase.
    #[arg(long, requires = "capture")]
    pub extcap_capture_filter: Option<String>,

    /// Used to get control messages from toolbar. Control messages are in the
    /// format documented in [`ControlPacket`][controls::ControlPacket].
    #[arg(long, requires = "capture")]
    pub extcap_control_in: Option<PathBuf>,

    /// Used to send control messages to toolbar. Control messages are in the
    /// format documented in [`ControlPacket`][controls::ControlPacket].
    #[arg(long, requires = "capture")]
    pub extcap_control_out: Option<PathBuf>,

    /// A selector may be reloaded from the configuration dialog of the extcap
    /// application within Wireshark. With the reload argument (defaults to
    /// false), the entry can be marked as reloadable.
    ///
    /// ```text
    /// arg {number=3}{call=--remote}{display=Remote Channel}{tooltip=Remote Channel Selector}{type=selector}{reload=true}{placeholder=Load interfaces...}
    /// ```
    ///
    /// After this has been defined, the user will get a button displayed in the
    /// configuration dialog for this extcap application, with the text "Load
    /// interfaces...​" in this case, and a generic "Reload" text if no text has
    /// been provided.
    ///
    /// The extcap utility is then called again with all filled out arguments
    /// and the additional parameter `--extcap-reload-option <option_name>`. It
    /// is expected to return a value section for this option, as it would
    /// during normal configuration. The provided option list is then presented
    /// as the selection, a previous selected option will be reselected if
    /// applicable.
    #[arg(long, requires = "extcap_interface")]
    pub extcap_reload_option: Option<String>,
}

impl ExtcapArgs {
    /// Runs the extcap program with the parsed arguments. This is the main
    /// entry point for the extcap program. Implementations should call this
    /// from their `main` function.
    ///
    /// ```
    /// use clap::Parser;
    ///
    /// #[derive(Debug, Parser)]
    /// struct AppArgs {
    ///     #[command(flatten)]
    ///     extcap: rust_extcap::ExtcapArgs,
    /// }
    ///
    /// fn main() -> anyhow::Result<()> {
    ///     AppArgs::parse().extcap.run(extcap_app)
    /// }
    /// ```
    pub fn run<App: ExtcapApplication>(&self, app: &App) -> Result<(), ExtcapError> {
        if self.extcap_interfaces {
            app.list_interfaces();
            Ok(())
        } else if let Some(interface) = &self.extcap_interface {
            if self.extcap_config {
                if let Some(reload_config) = &self.extcap_reload_option {
                    app.reload_config(interface, reload_config)?;
                } else {
                    app.list_configs(interface)?;
                }
                Ok(())
            } else if self.extcap_dlts {
                app.print_dlt(interface)?;
                Ok(())
            } else {
                Err(ExtcapError::NotExtcapInput)
            }
        } else {
            Err(ExtcapError::NotExtcapInput)
        }
    }
}

/// Error reported when running the [`ExtcapApplication`].
#[derive(Debug, Error)]
pub enum ExtcapError {
    /// The inputs given are not expected input from Wireshark. This can happen
    /// for example, when the user tries to run the application directly from
    /// command line. When this happens, you can print the installation
    /// instructions using the [`print_installation_instructions`] function,
    /// which will tell the user create a symlink from the Wireshark extcap
    /// directory to the installed binary location.
    #[error("Missing input extcap command. Maybe you need to install this with Wireshark instead?")]
    NotExtcapInput,

    /// Error when listing config. See [`ListConfigError`].
    #[error(transparent)]
    ListConfigError(#[from] ListConfigError),

    /// Error when reloading config. See [`ReloadConfigError`].
    #[error(transparent)]
    ReloadConfigError(#[from] ReloadConfigError),

    /// Error when printlng DLTs. See [`PrintDltError`].
    #[error(transparent)]
    PrintDltError(#[from] PrintDltError),
}

/// Prints the installation instructions to stdout. This is useful to show if
/// the program is used in unexpected ways (e.g. not as an extcap program), so
/// users can easily install with a copy-pastable command.
///
/// TODO: Include the printed message in the docs.
pub fn print_installation_instructions() {
    // TODO
}

/// Error printing DLTs to Wireshark.
#[derive(Debug, Error)]
pub enum PrintDltError {
    /// The interface string value given from Wireshark is not found. Wireshark
    /// invokes the extcap program multiple times, first to get the list of
    /// interfaces, then multiple times to get the DLTs. Therefore,
    /// implementations should make sure that the interfaces returned from
    /// [`ExtcapApplication::interfaces`] are deterministic and doesn't change
    /// across invocations of the program.
    #[error("Cannot list DLT for unknown interface \"{0}\".")]
    UnknownInterface(String),
}

/// Error when reloading configs. Config reload happens when a config, like
/// [`crate::config::SelectorConfig`] specifics the `reload` field and the user
/// clicks on the created reload button.
#[derive(Debug, Error)]
pub enum ReloadConfigError {
    /// The interface string value given from Wireshark is not found. Wireshark
    /// makes separate invocations to get the initial list of interfaces, and
    /// when the user subsequently hits reload on a config. Therefore,
    /// implementations should make sure that the interfaces returned from
    /// [`ExtcapApplication::interfaces`] are deterministic and doesn't change
    /// across invocations of the program.
    #[error("Cannot reload config options for unknown interface \"{0}\".")]
    UnknownInterface(String),

    /// The config `call` value given from Wireshark is not found in the configs
    /// defined for this [`ExtcapApplication`]. Wireshark makes separate
    /// invocations to get the initial list of interfaces, and when the user
    /// subsequently hits reload on a config. Therefore, implementations should
    /// make sure that the configs returned from
    /// [`ExtcapApplication::configs`] are deterministic and doesn't change
    /// across invocations of the program.
    #[error("Cannot reload options for unknown config \"{0}\".")]
    UnknownConfig(String),

    /// The config given by Wireshark is found, but it is not a
    /// [`SelectorConfig`] or
    /// [`EditSelectorConfig`][config::EditSelectorConfig]. This configuration
    /// is not expected to be invoked by Wireshark, as the
    /// [`SelectorConfig::reload`] field only exists for the appropriate types.
    #[error("Cannot reload config options for \"{0}\", which is not of type \"selector\".")]
    UnsupportedConfig(String),
}

/// Error listing configs.
#[derive(Debug, Error)]
pub enum ListConfigError {
    /// The interface string value given from Wireshark is not found. Wireshark
    /// makes separate invocations to get the initial list of interfaces, and
    /// when the user subsequently opens the config dialog. Therefore,
    /// implementations should make sure that the interfaces returned from
    /// [`ExtcapApplication::interfaces`] are deterministic and doesn't change
    /// across invocations of the program.
    #[error("Cannot reload config options for unknown interface \"{0}\".")]
    UnknownInterface(String),
}

/// Trait to help implement an extcap program. This application can be run by
/// passing it into [`ExtcapArgs::run`]. Since during a capture session,
/// Wireshark can call the extcap program multiple times (e.g. to get the list
/// of interfaces, configs, and DLTs), implementations of the application should
/// be consistent across multiple invocations. So it is recommended to put the
/// application in a `lazy_static` to make sure that the application
/// initialization doesn't depend on program state or command line arguments.
///
/// There 4 things need to be provided for an extcap implementation:
/// 1. [`metadata`][Self::metadata]: The version information and metadata for
///        this program, used by Wireshark to display in the UI.
/// 2. [`interfaces`][Self::interfaces]: The list of interfaces that can be
///        captured by this program.
/// 3. [`toolbar_controls`][Self::toolbar_controls]: Optional, a list of toolbar
///        controls shown in the Wireshark UI.
/// 4. [`configs`][Self::configs]: Optional, a list of UI configuration options
///        that the user can change.
/// ```
/// #use lazy_static::lazy_static;
/// use clap::Parser;
///
/// lazy_static! {
///     static ref APPLICATION: ExtcapApplication = ExtcapApplication {
///         // ...
///     }
/// }
///
/// #[derive(Debug, Parser)]
/// struct AppArgs {
///     #[command(flatten)]
///     extcap: rust_extcap::ExtcapArgs,
/// }
///
/// fn main() -> anyhow::Result<()> {
///     AppArgs::parse().extcap.run(extcap_app)
/// }
/// ```
pub trait ExtcapApplication {
    /// Returns the metadata like version info and help URL for this program.
    /// This is used by Wireshark to display in the UI.
    ///
    /// The [`cargo_metadata`] macro can be used to create this from data in
    /// `Cargo.toml`.
    fn metadata(&self) -> &Metadata;

    /// List the interfaces supported by this application. Wireshark calls this
    /// when the application starts up to populate the list of available
    /// interfaces. Since that interface list is cached and the interface names
    /// can be used later when the user tries to start a capture session, the
    /// interface list should stay as consistent as possible. If the list of
    /// interfaces can change, the extcap program must be prepared to handle
    /// `UnknownInterface` from the result.
    fn interfaces(&self) -> &[Interface];

    /// List the toolbar controls for this interface. In Wireshark, this is
    /// presented to the user in View > Interface Toolbars. See the
    /// documentation in [`controls`] for details.
    fn toolbar_controls(&self) -> Vec<&dyn ToolbarControl>;

    /// List the configurable UI elements for this interface. This is presented
    /// to the user when they click on the gear icon next to the capture
    /// interface name, or if they try to start a capture that is lacking a
    /// required config value.
    fn configs(&self, interface: &Interface) -> Vec<&dyn ConfigTrait>;

    /// List the interfaces and toolbar controls supported by this extcap
    /// implementation in stdout for Wireshark's consumption. Corresponds to the
    /// `--extcap-interfaces` argument in extcap.
    fn list_interfaces(&self) {
        self.metadata().print_config();
        for interface in self.interfaces() {
            interface.print_config();
        }
        for control in self.toolbar_controls() {
            control.print_config();
        }
    }

    /// List the configs available for the given interface in stdout for
    /// Wireshark's consumption. Corresponds to the `--extcap-config` argument
    /// in extcap.
    fn list_configs(&self, interface: &str) -> Result<(), ListConfigError> {
        let interface_obj = self
            .interfaces()
            .iter()
            .find(|i| i.value == interface)
            .ok_or_else(|| ListConfigError::UnknownInterface(String::from(interface)))?;
        for config in self.configs(interface_obj) {
            config.print_config();
        }
        Ok(())
    }

    /// Reloads the available options for a given config and prints them out for
    /// Wireshark's consumption. The default implementation looks up config returned from `configs` and calls its reload function. Corresponds to the `--extcap-reload-option`
    /// argument in extcap.
    fn reload_config(&self, interface: &str, config: &str) -> Result<(), ReloadConfigError> {
        let i = self
            .interfaces()
            .iter()
            .find(|i| i.value == interface)
            .ok_or_else(|| ReloadConfigError::UnknownInterface(String::from(interface)))?;
        let selector_config = self
            .configs(i)
            .into_iter()
            .find(|c| c.call() == config)
            .ok_or_else(|| ReloadConfigError::UnknownConfig(String::from(config)))?
            .as_any()
            .downcast_ref::<SelectorConfig>()
            .ok_or_else(|| ReloadConfigError::UnsupportedConfig(String::from(config)))?;
        let reload_fn = selector_config.reload.as_ref().ok_or_else(|| ReloadConfigError::UnsupportedConfig(String::from(config)))?;
        for opt in reload_fn() {
            opt.print_config(selector_config.config_number);
        }
        Ok(())
    }

    /// Prints the DLT to stdout for consumption by Wireshark. The default
    /// implementation provided takes the DLT from the interfaces returned from
    /// [`interfaces`][Self::interfaces] and prints out the correct one.
    /// Corresponds to the `--extcap-dlts` argument in extcap.
    fn print_dlt(&self, interface: &str) -> Result<(), PrintDltError> {
        self.interfaces()
            .iter()
            .find(|i| i.value == interface)
            .ok_or_else(|| PrintDltError::UnknownInterface(String::from(interface)))?
            .dlt
            .print_config();
        Ok(())
    }
}

/// The extcap interface expects certain outputs to stdout to communicate with
/// Wireshark, like
///
/// ```text
/// extcap {version=1.0}{help=Some help url}
/// ```
///
/// This formatter serves as a wrapper to implement that format via the
/// `Display` trait, and the Extcap output can be printed out like this:
///
/// ```
/// use rust_extcap::interface::Metadata;
/// # use rust_extcap::ExtcapFormatter;
///
/// print!("{}", ExtcapFormatter(&Metadata {
///     version: "1.0".into(),
///     help_url: "Some help url".into(),
///     display_description: "Example extcap".into(),
/// }));
/// // Output: extcap {version=1.0}{help=Some help url}{display=Example extcap}
/// ```
pub struct ExtcapFormatter<T>(pub T)
where
    Self: Display;

/// Elements that has a printable extcap config. See the documentation for
/// [`ExtcapFormatter`] for details.
pub trait PrintConfig {
    // TODO: fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

    /// Prints the configuration to stdout.
    fn print_config(&self);
}

impl<T> PrintConfig for T
where
    for<'a> ExtcapFormatter<&'a T>: Display,
{
    fn print_config(&self) {
        print!("{}", ExtcapFormatter(self));
    }
}

/// Creates a [`Metadata`] from information in `Cargo.toml`.
///
/// ----------------------------------------
/// | Metadata field       | Cargo.toml    |
/// ----------------------------------------
/// |`version`             | `version`     |
/// |`help_url`            | `homepage`    |
/// |`display_description` | `description` |
/// ----------------------------------------
#[macro_export]
macro_rules! cargo_metadata {
    () => {
        $crate::interface::Metadata {
            version: env!("CARGO_PKG_VERSION").into(),
            help_url: env!("CARGO_PKG_HOMEPAGE").into(),
            display_description: env!("CARGO_PKG_DESCRIPTION").into(),
        }
    };
}

#[cfg(test)]
mod test {
    use clap::Args;

    use super::ExtcapArgs;

    #[test]
    fn assert_args() {
        let cmd = clap::Command::new("test");
        let augmented_cmd = ExtcapArgs::augment_args(cmd);
        augmented_cmd.debug_assert();
    }
}