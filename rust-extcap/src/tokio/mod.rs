use crate::{ControlCommand, ControlPacket};
use anyhow::anyhow;
use async_trait::async_trait;
use log::{debug, warn};
use nom_derive::Parse;
use std::path::{Path, PathBuf};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

pub mod util;
use util::AsyncReadExt as _;

/// Manager for the extcap control pipes. The control pipes are a pair of FIFOs, one incoming and
/// one outgoing, and used to control extra functionalities, mostly UI-related, with Wireshark.
///
/// This class manages the serialization and deserialization of the control packets, and dispatches
/// them onto Tokio channels, so that functions running on other tasks can subcribe to and emit
/// those control packets.
///
/// See <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html> for details.
pub struct ExtcapControl {
    in_path: PathBuf,
    out_path: PathBuf,
    in_tx: tokio::sync::broadcast::Sender<ControlPacket<'static>>,
    out_tx: mpsc::Sender<ControlPacket<'static>>,
    out_rx: mpsc::Receiver<ControlPacket<'static>>,
}

impl ExtcapControl {
    /// Subscribe to new incoming control packets.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ControlPacket<'static>> {
        self.in_tx.subscribe()
    }

    /// Monitors the given tokio channel for control packets, and forwards the
    /// serialized bytes onto `out_file`.
    async fn mon_output_pipe(
        rx: &mut mpsc::Receiver<ControlPacket<'static>>,
        mut out_file: File,
    ) -> anyhow::Result<()> {
        while let Some(packet) = rx.recv().await {
            debug!("Got outgoing control packet: {packet:?}");
            out_file.write_all(&packet.to_header_bytes()).await?;
            out_file.write_all(&packet.payload).await?;
            out_file.flush().await?;
            debug!("Packet written and flushed");
        }
        Ok(())
    }

    /// Read one control packet from the given input file.
    async fn read_control_packet(in_file: &mut File) -> anyhow::Result<ControlPacket<'static>> {
        let header_bytes = in_file
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
                in_file.read_exact(&mut payload_bytes).await?;
                let all_bytes = [header_bytes.as_slice(), payload_bytes.as_slice()].concat();
                ControlPacket::parse(&all_bytes)
                    .map(|(_, packet)| (&[][..], packet.into_owned()))
                    .unwrap_or_else(|e| panic!("Unable to parse header packet: {e}"))
            }
            Err(e) => Err(anyhow!("Error parsing control packet: {e}"))?,
        };
        debug!("Parsed incoming control message: {packet:?}");
        Ok(packet)
    }

    /// Monitors the input pipe (`in_file`) for incoming control packets, parses
    /// them into [`ControlPackets`][ControlPacket], forwards them to the given
    /// tokio channel `tx`.
    async fn mon_input_pipe(
        tx: &tokio::sync::broadcast::Sender<ControlPacket<'static>>,
        mut in_file: File,
    ) -> anyhow::Result<()> {
        loop {
            let packet = Self::read_control_packet(&mut in_file).await?;
            tx.send(packet).unwrap();
        }
    }

    /// Creates a new instance of [`ExtcapControl`].
    pub fn new(in_path: &Path, out_path: &Path) -> Self {
        let (in_tx, _) = tokio::sync::broadcast::channel::<ControlPacket<'static>>(100);
        let (out_tx, out_rx) = mpsc::channel::<ControlPacket<'static>>(100);
        Self {
            in_path: in_path.to_owned(),
            out_path: out_path.to_owned(),
            in_tx,
            out_tx,
            out_rx,
        }
    }

    /// Optionally creates a new instance of [`ExtcapControl`], if both
    /// `in_path` and `out_path` are present.
    pub fn new_option(in_path: Option<PathBuf>, out_path: Option<PathBuf>) -> Option<Self> {
        Some(Self::new(in_path?.as_path(), out_path?.as_path()))
    }

    /// Starts processing the control packets on both the input and output
    /// pipes. Note that this method loops infinitely, and will not complete
    /// unless an error has occurred or a signal is received. (`SIGTERM` is sent
    /// by Wireshark when the capture stops).
    pub async fn process(&mut self) -> anyhow::Result<()> {
        let mut in_file = File::open(&self.in_path).await?;
        let out_file = File::create(&self.out_path).await?;
        let init_packet = Self::read_control_packet(&mut in_file).await?;
        assert_eq!(init_packet.command, ControlCommand::Initialized);
        tokio::try_join!(
            Self::mon_input_pipe(&self.in_tx, in_file),
            Self::mon_output_pipe(&mut self.out_rx, out_file),
        )?;
        Ok(())
    }

    /// Gets a control pipe that can send control messages to Wireshark.
    pub fn get_control_pipe(&self) -> mpsc::Sender<ControlPacket<'static>> {
        self.out_tx.clone()
    }
}

/// Sender for extcap control packets. These control packets controls the UI generated by Wireshark.
/// See <https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html> for details.
#[async_trait]
pub trait ExtcapControlSenderTrait {
    const UNUSED_CONTROL_NUMBER: u8 = 255;

    async fn send(&self, packet: ControlPacket<'static>);

    /// Enable a button with the given control number.
    async fn enable_button(&self, button: u8) {
        self.send(ControlPacket::new(button, ControlCommand::Enable, &[]))
            .await
    }

    /// Disable a button with the given control number.
    async fn disable_button(&self, button: u8) {
        self.send(ControlPacket::new(button, ControlCommand::Disable, &[]))
            .await
    }

    /// Shows a message in an information dialog popup.
    async fn info_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::InformationMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in a warning dialog popup.
    async fn warning_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::WarningMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in an error dialog popup.
    async fn error_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::ErrorMessage,
            message.as_bytes(),
        ))
        .await
    }

    /// Shows a message in the status bar
    async fn status_message(&self, message: &'static str) {
        self.send(ControlPacket::new(
            Self::UNUSED_CONTROL_NUMBER,
            ControlCommand::StatusbarMessage,
            message.as_bytes(),
        ))
        .await
    }
}

pub type ExtcapControlSender = mpsc::Sender<ControlPacket<'static>>;

#[async_trait]
impl ExtcapControlSenderTrait for mpsc::Sender<ControlPacket<'static>> {
    /// Sends a control message to Wireshark.
    async fn send(&self, packet: ControlPacket<'static>) {
        debug!("Sending extcap control message: {packet:#?}");
        self.send(packet)
            .await
            .unwrap_or_else(|e| warn!("Failed to send control packet. {e}"));
    }
}

// Convenience impl to allow `Option::None` to be a no-op sender.
#[async_trait]
impl<T: ExtcapControlSenderTrait + Sync> ExtcapControlSenderTrait for Option<T> {
    /// Sends a control message to Wireshark.
    async fn send(&self, packet: ControlPacket<'static>) {
        if let Some(sender) = self {
            sender.send(packet).await;
        }
    }
}
