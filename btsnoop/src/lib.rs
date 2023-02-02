//! A parser for the BTSnoop file format, which is a bluetooth HCI logs format similar to the snoop
//! format, as documented in RFC 1761.
//! Reference: <https://fte.com/webhelpii/bpa600/Content/Technical_Information/BT_Snoop_File_Format.htm>
//!
//! Notably this is used in Android and can be captured from your device following instructions from
//! [Verifying and Debugging Bluetooth](https://source.android.com/docs/core/connect/bluetooth/verifying_debugging#debugging-options)
//! on source.android.com.
//!
//! ## Example
//!
//! ```rust
//! use btsnoop::parse_btsnoop_file;
//!
//! let btsnoop_bytes: &[u8] = include_bytes!("testdata/btsnoop_hci.log");
//! let file: btsnoop::File = parse_btsnoop_file(btsnoop_bytes).unwrap();
//! for packet in file.packets {
//!     println!("Packet={:x?}", packet.packet_data);
//! }
//! ```

use nom_derive::{Nom, Parse};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

/// Represents the entire btsnoop file. This includes one fixed-size file header followed
/// by an arbitrary number of `Packet`s.
#[derive(Nom, Debug)]
pub struct File<'a> {
    /// The file's header.
    pub header: FileHeader<'a>,
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
pub struct FileHeader<'a> {
    /// The magic header identifying the packet format. Must always be `b"btsnoop\0"`.
    #[nom(Tag(b"btsnoop\0"))]
    pub identification_pattern: &'a [u8],
    /// The version of the btsnoop file. Only version 1 is supported.
    #[nom(Verify = "*version == 1")]
    pub version: u32,
    /// The datalink type for the packet records that follow.
    pub datalink_type: DatalinkType,
}

impl<'a> FileHeader<'a> {
    /// The fixed length of a file header.
    pub const LENGTH: usize = 16;
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
    nom::combinator::map_opt(nom::bits::streaming::take(1_usize), Enum::from_u8)(input)
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
                nom::bits::streaming::take(30_usize),
            ))),
            |(direction, command, reserved)| PacketFlags {
                direction,
                command,
                reserved,
            },
        )(input)
    }
}

/// Header fields for a packet record.
#[derive(Nom, Debug)]
pub struct PacketHeader {
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
}

#[derive(Debug, PartialEq, Eq)]
pub struct TimeVal {
    pub sec: i64,
    pub usec: i64,
}

impl PacketHeader {
    /// The fixed length of a packet header.
    pub const LENGTH: usize = 24;

    /// Returns the timestamp in the [TimeVal] struct format.
    pub fn timestamp_tv(&self) -> TimeVal {
        eprintln!("timestamp={}", self.timestamp_microseconds);
        let num_us_since_unix = self.timestamp_microseconds - 0x00dcddb30f2f8000;
        TimeVal {
            sec: num_us_since_unix / 1_000_000,
            usec: num_us_since_unix % 1_000_000 * 1000,
        }
    }
}

/// A packet record in the logs.
#[derive(Nom, Debug)]
pub struct Packet<'a> {
    /// Header fields for this packet
    pub header: PacketHeader,
    /// A byte string, `included_length` bytes long, that was captured by the system, beginning with
    /// its datalink header. The format of the bytes can be inferred from
    /// `File.header.datalink_type`
    #[nom(Take(header.included_length))]
    pub packet_data: &'a [u8],
}

/// Error type returned in `parse_btsnoop_file` if parsing failed.
#[derive(Error, Debug)]
pub enum Error<'a> {
    /// Error parsing the input data.
    #[error(transparent)]
    ParseError(#[from] nom::Err<nom::error::Error<Vec<u8>>>),
    /// The input data was successfully parsed, but there is data leftover. This can be a symptom
    /// of malformed data if the length field in the packet is wrong.
    #[error("unexpected data remaining")]
    UnexpectedData(&'a [u8]),
}

// Converts the nom error from holding &[u8] (the input type) to holding Vec<u8>, since
// std::error::Error's `source` field doesn't allow non-'static lifetimes.
impl<'a> From<nom::Err<nom::error::Error<&[u8]>>> for Error<'a> {
    fn from(nom_error: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        Self::ParseError(match nom_error {
            nom::Err::Incomplete(n) => nom::Err::Incomplete(n),
            nom::Err::Error(nom::error::Error { input, code }) => {
                nom::Err::Error(nom::error::Error {
                    input: input.to_vec(),
                    code,
                })
            }
            nom::Err::Failure(nom::error::Error { input, code }) => {
                nom::Err::Failure(nom::error::Error {
                    input: input.to_vec(),
                    code,
                })
            }
        })
    }
}

/// Parses a given btsnoop file.
pub fn parse_btsnoop_file(input: &[u8]) -> Result<File, Error> {
    let (rem, file) = File::parse(input)?;
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

    #[test]
    fn timestamp() {
        let hci_bytes = include_bytes!("testdata/btsnoop_hci.log");
        let (rem, file) = File::parse(hci_bytes).unwrap();
        assert!(rem.is_empty(), "Unexpected remaining bytes: {rem:?}");
        assert_eq!(
            file.packets[0].header.timestamp_tv(),
            TimeVal {
                sec: 1674874116,
                usec: 395644000,
            },
        );
    }

    #[test]
    fn timestamp_at_2000() {
        let packet_header = PacketHeader {
            original_length: 10,
            included_length: 10,
            packet_flags: PacketFlags { direction: DirectionFlag::Sent, command: CommandFlag::Data, reserved: 0 },
            culmulative_drops: 1,
            timestamp_microseconds: 0x00E03AB44A676000, // 2000-01-01 00:00:00
        };
        assert_eq!(
            packet_header.timestamp_tv(),
            TimeVal {
                sec: 946684800, // 2000-01-01 00:00:00
                usec: 0,
            }
        );
    }
}
