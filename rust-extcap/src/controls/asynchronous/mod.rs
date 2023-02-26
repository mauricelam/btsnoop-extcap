use async_trait::async_trait;
use log::debug;
use nom_derive::Parse;
use thiserror::Error;
use std::path::{Path, PathBuf};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, mpsc}, task::JoinHandle,
};

pub mod util;
use util::AsyncReadExt as _;

use crate::controls::{ControlCommand, ControlPacket};

#[derive(Debug, Error)]
pub enum ReadControlError {
    #[error(transparent)]
    IoError(#[from] tokio::io::Error),
    #[error("Error parsing control packet: {0}")]
    ParseError(String),
}

/// A reader for an Extcap Control using a [`Channel`][mpsc::channel]. This is
/// the easier to use, but higher overhead way to read control packets. When the
/// reader is spawned, a thread is spawned to continuously read messages and
/// writes them into a bounded `sync_channel`. This allows the user to read the
/// control messages without worrying about threading, by calling
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
///         while let Some(packet) = reader.try_read_packet() {
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
                tx.send(reader.read_control_packet().await.unwrap()).await.unwrap();
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


pub struct ExtcapControlReader {
    pub in_file: File,
}

impl ExtcapControlReader {
    /// Creates a new instance of [`ExtcapControlReader`].
    pub async fn new(in_path: &Path) -> Self {
        Self {
            in_file: File::open(in_path).await.unwrap(),
        }
    }

    /// Read one control packet from the given input file.
    pub async fn read_control_packet(&mut self) -> Result<ControlPacket<'static>, ReadControlError> {
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

/// Sender for extcap control packets. These control packets controls the UI generated by Wireshark.
/// See <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html> for details.
#[async_trait]
pub trait ExtcapControlSenderTrait: Send + Sync {
    async fn send(&mut self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error>;

    /// Shows a message in an information dialog popup.
    async fn info_message(&mut self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::InformationMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in a warning dialog popup.
    async fn warning_message(&mut self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::WarningMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in an error dialog popup.
    async fn error_message(&mut self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::ErrorMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in the status bar
    async fn status_message(&mut self, message: &str) -> Result<(), tokio::io::Error> {
        self.send(ControlPacket::new_with_payload(
            UNUSED_CONTROL_NUMBER,
            ControlCommand::StatusbarMessage,
            message.as_bytes(),
        ))
        .await
    }
}

pub struct ExtcapControlSender {
    out_file: File,
}

impl ExtcapControlSender {
    /// Creates a new instance of [`ExtcapControlSender`].
    pub async fn new(out_path: &Path) -> Self {
        Self {
            out_file: File::create(out_path).await.unwrap(),
        }
    }
}

#[async_trait]
impl ExtcapControlSenderTrait for ExtcapControlSender {
    /// Sends a control message to Wireshark.
    async fn send(&mut self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error> {
        debug!("Sending extcap control message: {packet:#?}");
        self.out_file.write_all(&packet.to_header_bytes()).await?;
        self.out_file.write_all(&packet.payload).await?;
        self.out_file.flush().await?;
        Ok(())
    }
}

#[async_trait]
impl<T: ExtcapControlSenderTrait> ExtcapControlSenderTrait for Option<T> {
    /// Sends a control message to Wireshark.
    async fn send(&mut self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error> {
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
///
/// Using this requires a somewhat strange `mut control:
/// &Mutex<ExtcapControlSender>` or `control: &mut Mutex<ExtcapControlSender>`
/// syntax, which is just an artifact of how the `ExtcapControlSenderTrait` is
/// defined. The `Mutex` reference is not mutated in any way.
#[async_trait]
impl<T: ExtcapControlSenderTrait> ExtcapControlSenderTrait for &Mutex<T> {
    /// Sends a control message to Wireshark.
    async fn send(&mut self, packet: ControlPacket<'_>) -> Result<(), tokio::io::Error> {
        self.lock().await.send(packet).await
    }
}
