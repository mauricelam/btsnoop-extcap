//! Extensions to btsnoop

use anyhow::anyhow;

/// Corresponds to the extra "Direction" field in `BLUETOOTH_HCI_H4_WITH_PHDR`.
pub enum Direction {
    Sent,
    Received,
    Unknown,
}

impl Direction {
    pub fn to_hci_pseudo_header(&self) -> [u8; 4] {
        match self {
            Direction::Sent => 0_u32.to_be_bytes(),
            Direction::Received => 1_u32.to_be_bytes(),
            Direction::Unknown => 0xff_u32.to_be_bytes(),
        }
    }

    pub fn parse_from_payload(payload: &[u8]) -> anyhow::Result<Direction> {
        // Check the HCI packet type header to determine the direction
        // Additional reference for format inside of the payload: https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_sdk/1.60.00.29_new/exports/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html#specification-interface
        Ok(match payload[0] {
            HCI_PACKET_TYPE_COMMAND => Direction::Sent,
            HCI_PACKET_TYPE_SYNCHRONOUS_DATA | HCI_PACKET_TYPE_ASYNC_DATA => {
                // Check the "PB Flag" for the direction. This is taken from Wireshark's androiddump.c,
                // even though it doesn't seem to exactly match the BT specs.
                // See 5.4.2 HCI ACL Data Packets in Specification of the Bluetooth System, v4.2
                if payload[2] & 0x20 == 0 {
                    Direction::Sent
                } else {
                    Direction::Received
                }
            }
            HCI_PACKET_TYPE_EVENT => Direction::Received,
            HCI_PACKET_TYPE_EXTENDED_COMMAND => Err(anyhow!("Extended Command (0x09) not supported"))?,
            _ => Err(anyhow!("Unknown payload header {}", payload[0]))?,
        })
    }
}

// Reference for HCI_PACKET_TYPE: https://software-dl.ti.com/simplelink/esd/simplelink_cc13x2_sdk/1.60.00.29_new/exports/docs/ble5stack/vendor_specific_guide/BLE_Vendor_Specific_HCI_Guide/hci_interface.html#specification-interface
const HCI_PACKET_TYPE_COMMAND: u8 = 0x01;
const HCI_PACKET_TYPE_SYNCHRONOUS_DATA: u8 = 0x02;
const HCI_PACKET_TYPE_ASYNC_DATA: u8 = 0x03;
const HCI_PACKET_TYPE_EVENT: u8 = 0x04;
const HCI_PACKET_TYPE_EXTENDED_COMMAND: u8 = 0x09;
