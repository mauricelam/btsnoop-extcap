use pcap_file::DataLink;

#[derive(Clone, Debug)]
pub struct Dlt<S: AsRef<str>> {
    /// Reference: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h
    pub data_link_type: DataLink,
    pub name: S,
    pub display: S,
}

impl<S: AsRef<str>> Dlt<S> {
    /// Print the configuration line suitable for use with `--extcap-dlts`.
    pub fn print_config(&self) {
        println!(
            "dlt {{number={}}}{{name={}}}{{display={}}}",
            <u32>::from(self.data_link_type),
            self.name.as_ref(),
            self.display.as_ref()
        )
    }
}
