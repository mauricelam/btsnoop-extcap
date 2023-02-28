//! Tools for handling the Control Pipe with `async` (`tokio`).
//!
//! There are three main classes provided in this module:
//!
//! * [`ExtcapControlSender`] – Implements the sender side for sending control
//!   packets from the extcap program you are implementing to Wireshark.
//! * [`ExtcapControlReader`] – Implements the reader side that receives control
//!   packets sent from Wireshark.
//! * [`ChannelExtcapControlReader`] – A wrapper around `ExtcapControlReader`
//!   that provides simpler, but less flexible, handling of the communication
//!   using a Tokio channel.
//!
//! See Wireshark's [Adding Capture Interfaces And Log Sources Using
//! Extcap](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html#_messages)
//! section 8.2.3.2.1 for a description of the protocol format.

use async_trait::async_trait;
use log::debug;
use nom_derive::Parse;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

pub mod util;
use util::AsyncReadExt as _;

use crate::controls::{ControlCommand, ControlPacket};

/// Error type returned for control packet read operations.
#[derive(Debug, Error)]
pub enum ReadControlError {
    /// Error reading the incoming control pipe.
    #[error(transparent)]
    IoError(#[from] tokio::io::Error),

    /// Error parsing the incoming data into the [`ControlPacket`] format.
    #[error("Error parsing control packet: {0}")]
    ParseError(String),
}

/// A reader for an Extcap Control using a [`Channel`][mpsc::channel]. This is
/// the easier to use, but higher overhead way to read control packets. When the
/// reader is spawned, a thread is spawned to continuously read messages and
/// writes them into a bounded `channel`. This allows reading the control
/// messages without worrying about spawning async tasks, by calling
/// [`try_read_packet`][Self::try_read_packet] every once in a while.
///
/// Assuming the extcap `capture` implementation uses a loop to read or generate
/// the packets, it can repeatedly call `try_read_packet` to read and handle the
/// control packets until there are no more buffered messages before starting
/// the main capturing logic.
///
/// For example:
/// ```ignore
/// fn capture(reader: &ChannelExtcapControlReader) -> Result<()> {
///     let pcap_header = ...;
///     let mut pcap_writer = PcapWriter::with_header(fifo, pcap_header)?;
///     loop {
///         while let Some(packet) = reader.try_read_packet().await {
///             // Handle the control packet
///         }
///         pcap_writer.write_packet(...)?;
///     }
///     Ok(())
/// }
pub struct ChannelExtcapControlReader {
    /// The join handle for the spawned thread. In most cases there is no need
    /// to use this, as the control fifo is expected to run for the whole
    /// duration of the capture.
    pub join_handle: JoinHandle<()>,
    /// The channel to receive control packets from.
    pub read_channel: mpsc::Receiver<ControlPacket<'static>>,
}

impl ChannelExtcapControlReader {
    /// Create a `ChannelExtcapControlReader` and spawns the underlying thread
    /// it uses to start reading the control packets from the pipe given in
    /// `in_path`.
    pub fn spawn(in_path: PathBuf) -> Self {
        let (tx, rx) = mpsc::channel::<ControlPacket<'static>>(10);
        let join_handle = tokio::task::spawn(async move {
            let mut reader = ExtcapControlReader::new(&in_path).await;
            loop {
                tx.send(reader.read_control_packet().await.unwrap())
                    .await
                    .unwrap();
            }
        });
        Self {
            join_handle,
            read_channel: rx,
        }
    }

    /// Try to read a buffered control packet, or return `None` if there are no
    /// incoming control packets.
    pub async fn try_read_packet(&mut self) -> Option<ControlPacket<'static>> {
        self.read_channel.try_recv().ok()
    }

    /// Reads a control packet. If the incoming channel is empty, this will
    /// block and wait until an incoming packet comes in. This is typically used
    /// when the extcap capture starts to wait for the `Initialized` packet from
    /// the control channel.
    ///
    /// If you are only using this method and not using `try_read_packet`,
    /// consider whether you can use [`ExtcapControlReader`] directly for lower
    /// overhead.
    pub async fn read_packet(&mut self) -> Option<ControlPacket<'static>> {
        self.read_channel.recv().await
    }
}

/// A reader for the Extcap control pipe.
pub struct ExtcapControlReader {
    /// The file to read the control packets from. This is the fifo passed with
    /// the `--extcap-control-in` flag.
    in_file: File,
}

impl ExtcapControlReader {
    /// Creates a new instance of [`ExtcapControlReader`].
    ///
    /// * `in_path`: The path of the extcap control pipe passed with
    ///   `--extcap-control-in`.
    pub async fn new(in_path: &Path) -> Self {
        Self {
            in_file: File::open(in_path).await.unwrap(),
        }
    }

    /// Read one control packet, awaiting until the packet arrives. Since the
    /// control packet pipe is expected to stay open for the entire duration of
    /// the extcap program, if the pipe is closed prematurely in this function
    /// here, `UnexpectedEof` will be returned.
    pub async fn read_control_packet(
        &mut self,
    ) -> Result<ControlPacket<'static>, ReadControlError> {
        let header_bytes = self
            .in_file
            .try_read_exact::<6>()
            .await?
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        debug!(
            "Read header bytes from incoming control message, now parsing... {:?}",
            header_bytes
        );
        let (_rem, packet) = match ControlPacket::parse(&header_bytes) {
            Ok((rem, packet)) => (rem, packet.into_owned()),
            Err(nom::Err::Incomplete(nom::Needed::Size(size))) => {
                let mut payload_bytes = vec![0_u8; size.get()];
                self.in_file.read_exact(&mut payload_bytes).await?;
                let all_bytes = [header_bytes.as_slice(), payload_bytes.as_slice()].concat();
                ControlPacket::parse(&all_bytes)
                    .map(|(_, packet)| (&[][..], packet.into_owned()))
                    .unwrap_or_else(|e| panic!("Unable to parse header packet: {e}"))
            }
            Err(e) => Err(ReadControlError::ParseError(e.to_string()))?,
        };
        debug!("Parsed incoming control message: {packet:?}");
        Ok(packet)
    }
}

const UNUSED_CONTROL_NUMBER: u8 = 255;

/// Sender for extcap control packets. These control packets controls the UI
/// generated by Wireshark. This trait also provides convenience functions for
/// sending control packets formatted for particular usages like `info_message`
/// and `status_message`. For other functions controlling various toolbar
/// controls, see the methods in the [`control`][crate::controls] module instead.
#[async_trait]
pub trait ExtcapControlSenderTrait: Send + Sync + Sized {
    async fn send(self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error>;

    /// Shows a message in an information dialog popup. The message will show on
    /// the screen until the user dismisses the popup.
    async fn info_message(self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::InformationMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in a warning dialog popup. The message will show on the
    /// screen until the user dismisses the popup.
    async fn warning_message(self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::WarningMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in an error dialog popup. The message will show on the
    /// screen until the user dismisses the popup.
    async fn error_message(self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::ErrorMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in the status bar at the bottom of the Wireshark window.
    /// When the message is shown, the status bar will also flash yellow to
    /// bring it to the user's attention. The message will stay on the status
    /// bar for a few seconds, or until another message overwrites it.
    async fn status_message(self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::StatusbarMessage,
            message.as_bytes(),
        ))
        .await
    }
}

/// A sender for the extcap control packets. `out_file` should be the file given
/// by the `--extcap-control-out` flag.
pub struct ExtcapControlSender {
    out_file: File,
}

impl ExtcapControlSender {
    /// Creates a new instance of [`ExtcapControlSender`].
    ///
    /// * `out_path`: The path specified by the `--extcap-control-out` flag.
    pub async fn new(out_path: &Path) -> Self {
        Self {
            out_file: File::create(out_path).await.unwrap(),
        }
    }
}

#[async_trait]
impl<'a> ExtcapControlSenderTrait for &'a mut ExtcapControlSender {
    async fn send(self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error> {
        debug!("Sending extcap control message: {packet:#?}");
        self.out_file.write_all(&packet.to_header_bytes()).await?;
        self.out_file.write_all(&packet.payload).await?;
        self.out_file.flush().await?;
        Ok(())
    }
}

/// An implementation of ExtcapControlSenderTrait that is no-op when the
/// `Option` is `None`. Since Wireshark may not include the
/// `--extcap-control-out` flag (e.g. when no controls are returned during
/// `--extcap-interfaces`, or when running in tshark), this allows an easier but
/// less efficient way to say `option_extcap_sender.status_message(...)` without
/// constantly checking for the option.
#[async_trait]
impl<T> ExtcapControlSenderTrait for &mut Option<T>
where
    T: Send + Sync,
    for<'a> &'a mut T: ExtcapControlSenderTrait,
{
    async fn send(self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error> {
        if let Some(s) = self {
            s.send(packet).await
        } else {
            Ok(())
        }
    }
}

/// Just for syntactic niceness when working with a control sender behind a
/// mutex. This usage allows the sender to be locked only for the duration of
/// that one control packet, so it can be interleaved in between other async
/// function calls.
#[async_trait]
impl<T> ExtcapControlSenderTrait for &Mutex<T>
where
    T: Send,
    for<'a> &'a mut T: ExtcapControlSenderTrait,
{
    /// Sends a control message to Wireshark.
    async fn send(self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error> {
        self.lock().await.send(packet).await
    }
}
