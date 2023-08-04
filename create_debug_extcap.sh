#! /usr/bin/env bash

# Run this script to generate a debug version of the extcap executable, which enables debug
# logging and writes them to /tmp/btsnoop-extcap.log.

set -ex

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# NOTE: Change to ~/.local/lib/wireshark/extcap if using Wireshark 4.1 or above
cat <<EOF > ~/.config/wireshark/extcap/btsnoop-extcap
#! /usr/bin/env bash
exec 2>/tmp/btsnoop-extcap.log
# Use exec to make sure the rust program will get SIGTERM from wireshark when stopping
RUST_LOG=debug exec $SCRIPT_DIR/../target/debug/btsnoop-extcap "\$@"
EOF
chmod +x ~/.config/wireshark/extcap/btsnoop-extcap
