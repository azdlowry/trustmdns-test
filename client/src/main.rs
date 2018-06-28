extern crate chrono;
extern crate futures;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate tokio;
extern crate tokio_timer;
extern crate trust_dns;
extern crate trust_dns_server;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::runtime::current_thread::Runtime;

use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::multicast::MdnsQueryType;
use trust_dns::multicast::{MdnsClientStream};
use trust_dns::rr::{DNSClass, Name, RecordType};

const MDNS_PORT: u16 = 5353;

lazy_static! {
    /// 250 appears to be unused/unregistered
    static ref TEST_MDNS_IPV4: IpAddr = Ipv4Addr::new(224,0,0,251).into();
}

fn main() {
    let addr = SocketAddr::new(*TEST_MDNS_IPV4, MDNS_PORT);

    // Check that the server is ready before sending...
    let mut io_loop = Runtime::new().unwrap();
    //let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = MdnsClientStream::new(addr, MdnsQueryType::OneShot, None, None, None);
    let client = ClientFuture::new(stream, sender, None);
    let mut client = io_loop.block_on(client).unwrap();

    {
        let name = Name::from_ascii("_services._dns-sd._udp.local").unwrap();
        let future = client.query(name.clone(), DNSClass::IN, RecordType::PTR);
        let message = io_loop.block_on(future).expect("mdns query failed");
        println!("{:?}", message);
    }
    {
        let name = Name::from_ascii("_devpolterg._tcp.local").unwrap();
        let future = client.query(name.clone(), DNSClass::IN, RecordType::PTR);
        let message = io_loop.block_on(future).expect("mdns query failed");
        println!("{:?}", message);
    }
    {
        let name = Name::from_ascii("deadbeefdeadbeef._devpolterg._tcp.local").unwrap();
        let future = client.query(name.clone(), DNSClass::IN, RecordType::SRV);
        let message = io_loop.block_on(future).expect("mdns query failed");
        println!("{:?}", message);
    }
    {
        let name = Name::from_ascii("deadbeefdeadbeef._devpolterg._tcp.local").unwrap();
        let future = client.query(name.clone(), DNSClass::IN, RecordType::TXT);
        let message = io_loop.block_on(future).expect("mdns query failed");
        println!("{:?}", message);
    }
}
