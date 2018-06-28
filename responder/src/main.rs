extern crate chrono;
extern crate futures;
extern crate log;
extern crate tokio;
extern crate tokio_timer;
extern crate trust_dns;
extern crate trust_dns_server;

use std::time::{Duration, Instant};

use futures::future::Either;
use futures::{Future, Stream};
use std::str::FromStr;
use tokio::runtime::current_thread::Runtime;
use tokio_timer::Delay;
use trust_dns::error::*;
use trust_dns::multicast::MdnsQueryType;
use trust_dns::multicast::MdnsStream;
use trust_dns::op::Message;
use trust_dns::rr::rdata::{SRV, TXT};
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::serialize::binary::BinDecodable;

fn main() {
    mdns_responder();
}

fn mdns_responder() {
    let mut io_loop = Runtime::new().unwrap();

    // a max time for the test to run
    let mut timeout = Delay::new(Instant::now() + Duration::from_millis(1000));

    // FIXME: ipv6 if is hardcoded, need a different strategy
    let (mdns_stream, mdns_handle) = MdnsStream::new_ipv4::<ClientError>(
        MdnsQueryType::Continuous,
        None,
        None,
    );

    let mut stream = io_loop
        .block_on(mdns_stream)
        .expect("failed to create server stream")
        .into_future();

    loop {
        match io_loop
            .block_on(stream.select2(timeout))
            .ok()
            .expect("server stream closed")
        {
            Either::A((data_src_stream_tmp, timeout_tmp)) => {
                let (data_src, stream_tmp) = data_src_stream_tmp;
                let (data, src) = data_src.expect("no buffer received");

                stream = stream_tmp.into_future();
                timeout = timeout_tmp;

                let mut message = Message::from_bytes(&data).expect("message decode failed");

                println!("Message {:?} - {:?}", message, src);

                let answers = message
                    .queries()
                    .iter()
                    .filter_map(|ref query| {
                        //println!("Query: {}", query);
                        match (
                            &*query.name().to_lowercase().to_ascii(),
                            query.query_type(),
                            query.query_class(),
                        ) {
                            ("_services._dns-sd._udp.local.", RecordType::PTR, DNSClass::IN) => {
                                let mut record =
                                    Record::with(query.name().clone(), RecordType::A, 60);
                                record.set_rdata(RData::PTR(
                                    Name::from_str("_devpolterg._tcp.local.")
                                        .unwrap(),
                                ));
                                Some(record)
                            }
                            ("_devpolterg._tcp.local.", RecordType::PTR, DNSClass::IN) => {
                                let mut record =
                                    Record::with(query.name().clone(), RecordType::A, 60);
                                record.set_rdata(RData::PTR(
                                    Name::from_str("deadbeefdeadbeef._devpolterg._tcp.local.")
                                        .unwrap(),
                                ));
                                Some(record)
                            }
                            (
                                "deadbeefdeadbeef._devpolterg._tcp.local.",
                                RecordType::TXT,
                                DNSClass::IN,
                            ) => {
                                let mut record =
                                    Record::with(query.name().clone(), RecordType::A, 60);
                                record.set_rdata(RData::TXT(TXT::new(vec![])));
                                Some(record)
                            }
                            (
                                "deadbeefdeadbeef._devpolterg._tcp.local.",
                                RecordType::SRV,
                                DNSClass::IN,
                            ) => {
                                let mut record =
                                    Record::with(query.name().clone(), RecordType::A, 60);
                                record.set_rdata(RData::SRV(SRV::new(
                                    0,
                                    0,
                                    8883,
                                    Name::from_str("deadbeefdeadbeef._devpolterg._tcp.local.")
                                        .unwrap(),
                                )));
                                Some(record)
                            }
                            _ => {
                                println!("Unknown query {}", query.name());
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>();

                message.add_answers(answers);
                
                println!("Response: {:?}", message);

                mdns_handle
                    .unbounded_send((message.to_vec().expect("message encode failed"), src))
                    .unwrap();
            }
            Either::B(((), data_src_stream_tmp)) => {
                stream = data_src_stream_tmp;
                timeout = Delay::new(Instant::now() + Duration::from_millis(1000));
            }
        }
    }
}
