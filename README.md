# Extcap binary for capturing bluetooth packets from Android devices

[![Build status](https://github.com/mauricelam/btsnoop-extcap/actions/workflows/cargo-build-and-test.yml/badge.svg)](https://github.com/mauricelam/btsnoop-rs/actions)
[![Crates.io](https://img.shields.io/crates/v/btsnoop-extcap.svg)](https://crates.io/crates/btsnoop-extcap)

## Installation

```sh
$ cargo install btsnoop-extcap

# Running btsnoop-extcap from command line is not part of the normal workflow,
# but it will print out installation instructions. For example:
$ btsnoop-extcap
Missing input extcap command.

This is an extcap plugin meant to be used with Wireshark or tshark.
To install this plugin, run
    btsnoop-extcap --install

# Run the given command to create the symlink
$ btsnoop-extcap --install
Is your Wireshark 4.1 or above? [Y/n] y
Creating symlink at "~/.local/lib/wireshark/extcap/btsnoop-extcap"
Enter path to adb executable [Default: ~/Library/Android/sdk/platform-tools/adb]: <Enter>
```

_Root is required on the selected Android device._

This extcap plugin is designed to be used with [Wireshark](https://www.wireshark.org/) or tshark,
and will show a live stream of Bluetooth HCI events from the selected device.

Detected devices are shown in Wireshark's __Capture__ interface list.

<img width="1462" alt="wireshark" src="https://github.com/user-attachments/assets/0afa77cf-fd25-4163-8e8c-31517cd6175c">

## Instructions to turn on btsnoop log capturing

1. Enable __Developer options__ on the device.
2. In the __Developer options__ menu, activate the __Enable Bluetooth HCI snoop log__ toggle.
3. Restart Bluetooth for logging to take effect.
4. Run `adb root`

## Relationship with `androiddump`

Wireshark has `androiddump` as one of the included extcap implementations. It is
based on an old configuration in Android that forwarded the btsnoop logs to port
8872, which was
[disabled](https://android.googlesource.com/platform/packages/modules/Bluetooth/+/4dcaa4646c0a44300a727e332859f518a08f6085)
in 2015. While it can be turned back on by changing the source code, recompiling
Android is inconvenient in some cases.

Meanwhile, Android continues to provide the option to write the HCI logs to a
local log file (in the `/system` partition, so root access is required to read
it), and that is what this extcap uses as the packet source.
