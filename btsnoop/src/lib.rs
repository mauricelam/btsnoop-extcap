//! A parser for the BTSnoop file format, which is a bluetooth HCI logs format similar to the snoop
//! format, as documented in RFC 1761.
//! Reference: https://fte.com/webhelpii/bpa600/Content/Technical_Information/BT_Snoop_File_Format.htm
//!
//! Notably this is used in Android and can be captured from your device following instructions from
//! https://source.android.com/docs/core/connect/bluetooth/verifying_debugging#debugging-options.

use nom_derive::{Nom, Parse};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

/// Represents the entire btsnoop file. This includes one fixed-size file header followed
/// by an arbitrary number of `Packet`s.
#[derive(Nom, Debug)]
pub struct File<'a> {
    /// The file's header.
    pub header: Header<'a>,
    /// The list of packets contained in this file.
    pub packets: Vec<Packet<'a>>,
}

/// The type of datalink header used in the packet records that follow.
#[derive(Nom, Debug)]
#[repr(u32)]
pub enum DatalinkType {
    UnencapsulatedHci = 1001,
    HciUart = 1002,
    HciBscp = 1003,
    HciSerial = 1004,
}

/// The file header contains general metadata about the packet file and format of the packets it 
/// contains.
#[derive(Nom, Debug)]
pub struct Header<'a> {
    #[nom(Tag(b"btsnoop\0"))]
    pub identification_pattern: &'a [u8],
    #[nom(Verify="*version == 1")]
    pub version: u32,
    pub datalink_type: DatalinkType,
}

/// Direction of data transfer.
/// 
/// Direction is relative to the host, meaning for controllers, `Sent` means
/// from host to controller, and `Received` means from controller to host.
#[derive(Debug, FromPrimitive)]
pub enum DirectionFlag {
    Sent = 0,
    Received = 1,
}

/// The packet type, whether it contains data or commands.
#[derive(Debug, FromPrimitive)]
pub enum CommandFlag {
    Data = 0,
    CommandOrEvent = 1,
}

/// A bit-level nom parser that takes one bit and parses it to the given `Enum` type. Since this
/// only takes one bit, it is only used for parsing enums with two variants.
fn parse_single_bit_enum<Enum: FromPrimitive>(
    input: (&[u8], usize),
) -> nom::IResult<(&[u8], usize), Enum> {
    nom::combinator::map_opt(nom::bits::complete::take(1_usize), Enum::from_u8)(input)
}

/// The packet flags field.
#[derive(Debug)]
pub struct PacketFlags {
    pub direction: DirectionFlag,
    pub command: CommandFlag,
    pub reserved: u32,
}

// Manually implement parse since nom_derive doesn't support bit-level parsers.
impl<'a> Parse<&'a [u8]> for PacketFlags {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        nom::combinator::map(
            nom::bits::bits(nom::sequence::tuple((
                parse_single_bit_enum::<DirectionFlag>,
                parse_single_bit_enum::<CommandFlag>,
                nom::bits::complete::take(30_usize),
            ))),
            |(direction, command, reserved)| PacketFlags {
                direction,
                command,
                reserved,
            },
        )(input)
    }
}

#[derive(Nom, Debug)]
pub struct Packet<'a> {
    /// Number of bytes in the captured packet, as received via a network.
    pub original_length: u32,
    /// Length of the `packet_data` field. This is the number of bytes included in this packet
    /// record, which may be less than `original_length` if the received packet was truncated.
    pub included_length: u32,
    /// Flags specific to this packet.
    pub packet_flags: PacketFlags,
    /// The culmulative number of packets that has been dropped (by the system that created the
    /// packet file), since the first packet record in the file.
    /// Capturing systems may decide to drop records due to configurations, privacy, or insufficient
    /// resources.
    ///
    /// Note: some implementations always set this field to zero.
    pub culmulative_drops: u32,
    /// The time of packet arrival, measured in microseconds since 0:00 midnight, January 1, 0 AD.
    ///
    /// See the [bluez source code](https://github.com/bluez/bluez/blob/9be85f867856195e16c9b94b605f65f6389eda33/tools/hcidump.c#L240)
    /// to see how it is converted from a unix timestamp.
    pub timestamp_microseconds: i64,
    /// A byte string, `included_length` bytes long, that was captured by the system, beginning with
    /// its datalink header. The format of the bytes can be inferred from
    /// `File.header.datalink_type`
    #[nom(Take(included_length))]
    pub packet_data: &'a [u8],
}

#[derive(Error, Debug)]
pub enum Error<'a> {
    #[error("unable to parse: {0}")]
    ParseError(String),
    #[error("unexpected data remaining")]
    UnexpectedData(&'a [u8]),
}

/// Parses a given btsnoop file. 
pub fn parse_btsnoop_file(input: &[u8]) -> Result<File, Error> {
    let (rem, file) = File::parse(input).map_err(|e| Error::ParseError(format!("{e:?}")))?;
    if rem.is_empty() {
        Ok(file)
    } else {
        Err(Error::UnexpectedData(rem))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_file_parsing_works() {
        let hci_bytes = include_bytes!("testdata/btsnoop_hci.log");
        let (rem, file) = File::parse(hci_bytes).unwrap();
        assert!(rem.is_empty(), "Unexpected remaining bytes: {rem:?}");
        assert_eq!(file.packets.len(), 222);
        assert_eq!(file.packets[0].packet_data, &[0x01, 0x03, 0x0c, 0x00]);
    }

    #[test]
    fn truncated() {
        let hci_bytes = include_bytes!("testdata/btsnoop_hci.log");
        let hci_bytes = &hci_bytes[..hci_bytes.len() - 50];
        let (rem, file) = File::parse(hci_bytes).unwrap();
        assert!(!rem.is_empty());
        // Header should still be available
        assert_eq!(file.header.identification_pattern, b"btsnoop\0");
    }
}
