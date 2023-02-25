use pcap_file::DataLink;
use typed_builder::TypedBuilder;

#[derive(Clone, Debug, TypedBuilder)]
pub struct Dlt {
    /// Reference: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h
    pub data_link_type: DataLink,
    pub name: String,
    pub display: String,
}

impl Dlt {
    /// Print the configuration line suitable for use with `--extcap-dlts`.
    pub fn print_config(&self) {
        println!(
            "dlt {{number={}}}{{name={}}}{{display={}}}",
            <u32>::from(self.data_link_type),
            self.name,
            self.display
        )
    }
}
