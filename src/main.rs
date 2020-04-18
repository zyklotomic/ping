#[macro_use]
extern crate clap;
extern crate ctrlc;

use nix::errno::errno;
use std::sync::Arc; use byteorder::{ByteOrder, NetworkEndian};
use std::str::FromStr;
use std::time::{Instant, Duration};
use std::net::{ToSocketAddrs, SocketAddr};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{Error, ErrorKind};

type Socket = i32;

struct Statistics {
    // Times are in microseconds
    sum: u128,
    square_sum: u128,
    count: usize,
    loss: usize,
    min: u128,
    max: u128,
}

impl Statistics {
    fn new() -> Self {
        Statistics {
            sum: 0,
            square_sum: 0,
            count: 0,
            loss: 0,
            min: u128::MAX,
            max: 0,
        }
    }

    fn add_ping_duration(&mut self, duration: Duration) {
        let micros = duration.as_micros();
        if micros < self.min {
            self.min = micros;
        }

        if micros > self.max {
            self.max = micros;
        }

        self.sum += micros;

        self.square_sum += micros.checked_mul(micros).unwrap();
        self.count += 1;
    }

    fn add_loss(&mut self) {
        self.loss += 1;
    }
}

impl fmt::Display for Statistics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.count != 0 {
            let transmitted = self.count + self.loss;
            let received = self.count;
            let packet_loss = (1.0 - ((received as f32) / (transmitted as f32))) * 100.0;
            let packet_info = format!("{} packets transmitted, {} received, {:.2}% packet loss",
                                      transmitted, received, packet_loss);
            let avg = Duration::from_micros((self.sum / (self.count as u128)) as u64);
            let var = Duration::from_micros((self.square_sum / (self.count as u128)) as u64) - avg;
            let mdev = Duration::from_micros((var.as_micros() as f64).sqrt() as u64);
            let min = Duration::from_micros(self.min as u64);
            let max = Duration::from_micros(self.max as u64);
            let ping_stats = format!("rtt min/avg/max/mdev = {:?}/{:?}/{:?}/{:?}",
                                     min, avg, max, mdev);
            write!(f, "{}\n{}", packet_info, ping_stats)
        } else {
            let transmitted = self.count + self.loss;
            write!(f, "{} packets transmitted, 0 received, 100% packet loss", transmitted)
        }
    }
}

struct CmdOptions {
    count: Option<usize>,
    destination: String,
    address: SocketAddr,
    interval: Option<Duration>,
    ttl: Option<u8>,
}

fn clap_str_to_int(s: &str, arg: &str) -> Result<usize, clap::Error> {
    match usize::from_str(s) {
        Ok(c) => Ok(c),
        Err(_) => Err(clap::Error {
            message: String::from(format!("Bad argument \"{}\" for <{}>", s, arg)),
            kind: clap::ErrorKind::InvalidValue,
            info: None,
        })
    }
}

fn clap_parse_ttl(s: &str) -> Result<u8, clap::Error> {
    match u8::from_str(s) {
        Ok(c) => Ok(c),
        Err(_) => Err(clap::Error {
            message: String::from(format!("Bad argument \"{}\" for <ttl>", s)),
            kind: clap::ErrorKind::InvalidValue,
            info: Some(vec!(String::from("Note: ttl must be an integer value between 0 and 255 inclusive"))),
        })
    }
}

impl CmdOptions {
    fn from_matches(matches: clap::ArgMatches) -> Result<Self, clap::Error> {
        let count = match matches.value_of("count") {
            None => None,
            Some(s) => Some(clap_str_to_int(&s, "count")?)
        };

        let destination = String::from(
            matches.value_of("dest").expect("Error unpacking <dest>"));

        let mut dest_clone = destination.clone();
        dest_clone.push_str(":0"); // Port 0
        let address_opt = match dest_clone.to_socket_addrs() {
            Ok(mut iter) => iter.next(),
            Err(_) => return Err(clap::Error{
                message: String::from(
                    format!("Could not resolve destination {}", &destination)),
                kind: clap::ErrorKind::InvalidValue,
                info: None,
            })
        };

        if address_opt == None {
            return Err(clap::Error{
                message: String::from(
                    format!("Could not resolve destination {}", &destination)),
                kind: clap::ErrorKind::InvalidValue,
                info: None,
            });
        }

        let interval_secs = match matches.value_of("interval") {
            None => None,
            Some(s) => Some(clap_str_to_int(&s, "interval")?)
        };
        let interval = match interval_secs {
            None => None,
            Some(secs) => Some(Duration::from_secs(secs as u64)),
        };

        let ttl = match matches.value_of("ttl") {
            None => None,
            Some(s) => Some(clap_parse_ttl(s)?),
        };

        Ok(CmdOptions {
            count,
            destination,
            address: address_opt.unwrap(),
            interval,
            ttl,
        })
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct EchoPacket {
    id: u16,
    sequence: u16,
}

enum EchoReply {
    TimeExceeded,
    DestinationUnreachable,
    UndefinedType(u8),
    InvalidChecksum,
    Valid,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct IcmpHdr {
    // TODO: Allow custom payload, may be hard
    // to work around in Rust due to compile-time
    // due to sizes needing to be known at compile-time.
    // Page 14 https://tools.ietf.org/html/rfc792
    type_t: u8,
    code: u8,
    checksum: u16,
    echo_pkt: EchoPacket,
    __payload1: [u8; 32],
    __payload2: [u8; 24],
}

impl IcmpHdr {
    const ICMP_REPLY: u8 = 0;
    const ICMP_UNREACHABLE: u8 = 3;
    const ICMP_ECHO: u8 = 8;
    const ICMP_TIME_EXCEEDED: u8 = 11;
    fn new(echo_pkt: EchoPacket) -> Self {
        IcmpHdr {
            type_t: Self::ICMP_ECHO,
            code: 0,
            checksum: 0,
            echo_pkt,
            __payload1: [0u8; 32],
            __payload2: [0u8; 24],
        }
    }

    fn calc_checksum(&self) -> u16 {
        // Payload is zeroed out, ignored for now.
        let mut checksum = (self.type_t as u32)
            .checked_add((self.code as u32) << 8).unwrap()
            .checked_add(self.echo_pkt.id as u32).unwrap()
            .checked_add(self.echo_pkt.sequence as u32).unwrap();
        checksum = (checksum >> 16) + (checksum & 0xffff);
        checksum += checksum >> 16;
        !checksum as u16
    }

    fn set_checksum(&mut self) {
        self.checksum = self.calc_checksum();
    }

    fn verify_reply(&self) -> EchoReply {
        match self.type_t {
            Self::ICMP_UNREACHABLE => EchoReply::DestinationUnreachable,
            Self::ICMP_TIME_EXCEEDED => EchoReply::TimeExceeded,
            Self::ICMP_REPLY => {
                if self.checksum == self.calc_checksum() {
                    EchoReply::Valid
                } else {
                    EchoReply::InvalidChecksum
                }
            },
            x => EchoReply::UndefinedType(x)
        }
    }
}

#[derive(Debug)]
#[repr(C)]
struct Ipv4Packet {
    version_ihl: u8, // Mask to get value, 4 bits each
    _r0: u8,
    _r1: [u8; 7],
    ttl: u8,
    _r2: [u8; 11],
    optional_1: [u8; 20],
    optional_2: [u8; 20],
    icmphdr_buffer: IcmpHdr,
}

impl Ipv4Packet {
    fn into_icmphdr(self) -> Result<IcmpHdr, std::io::Error> {
        let ihl: u8 = self.version_ihl & 0x0f;
        if ihl < 5 {
            Err(Error::new(
                ErrorKind::InvalidData, "Invalid IHL in packet"))
        } else {
            let packet_ptr = &self as *const _ as *const u8;
            let icmphdr_ptr = unsafe {
                packet_ptr.offset(ihl as isize * 4) as *const IcmpHdr
            };
            let icmphdr = unsafe { *icmphdr_ptr };
            Ok(icmphdr)
        }
    }

    fn new() -> Self {
        Ipv4Packet {
            version_ihl: 0,
            _r0: 0,
            _r1: [0u8; 7],
            ttl: 0,
            _r2: [0u8; 11],
            optional_1: [0u8; 20],
            optional_2: [0u8; 20],
            icmphdr_buffer: IcmpHdr::new(EchoPacket {
                id: 0,
                sequence: 0,
            }),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
struct CmsghdrTTL {
    // Risky maneuver / undefined behavior,
    // See cmsg(3) setsockopt/getsockopt(2)
    // Working hack for now since we know recvmsg will only return TTL
    cmsghdr: libc::cmsghdr,
    ttl: u8,
}

impl CmsghdrTTL {
    fn new() -> Self {
        CmsghdrTTL {
            cmsghdr: libc::cmsghdr {
                cmsg_len: 0,
                cmsg_level: 0,
                cmsg_type: 0,
            },
            ttl: 0,
        }
    }
}

fn socket(opts: &CmdOptions) -> Result<Socket, std::io::Error> {
    const IP_RECVTTL: libc::c_int = 12;
    // AF_INET for IPv4
    let socket_fd = unsafe {
        // For some reason SOCK_DGRAM unfortunately does not receive
        // ICMP error messages
        libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
    };

    if socket_fd == -1 {
        match errno() {
            13 => return Err(Error::new(ErrorKind::PermissionDenied, "")),
            x => return Err(
                Error::new(ErrorKind::Other,
                            format!("Failed to create socket(), errno={}", x))),
        }
    }

    let opt_len = std::mem::size_of::<u8>() as u32;
    if opts.ttl != None {
        let ttl = &opts.ttl.unwrap() as *const _ as *const libc::c_void;
        match unsafe {
            libc::setsockopt(socket_fd, libc::SOL_IP, libc::IP_TTL, ttl, opt_len)
        } {
            0 => (),
            -1 => return Err(
                Error::new(ErrorKind::Other,
                           format!("Failed to set TTL, setsockopt() errno={}", errno()))),
            _ => unreachable!(),
        }
    }

    let hold: *const libc::c_void = &1 as *const _ as *const libc::c_void;
    match unsafe {
        libc::setsockopt(socket_fd, libc::SOL_IP, IP_RECVTTL, hold, opt_len)
    } {
        0 => (),
        -1 => return Err(
            Error::new(ErrorKind::Other,
                       format!("Failed to set IP_RECVTTL, setsockopt() errno={}", errno()))),
        _ => unreachable!(),
    }

    Ok(socket_fd)
}

fn sendto(sockfd: Socket, icmphdr: IcmpHdr, ip_addr: std::net::Ipv4Addr) -> Result<usize, ()> {
    let icmp_len = std::mem::size_of::<IcmpHdr>();
    let addr_len = std::mem::size_of::<libc::sockaddr>();
    let buf = &icmphdr as *const _ as *const libc::c_void;

    let mut sa_data: [libc::c_char; 14] = [0; 14];
    // This cast is for the sin_addr field in the sockaddr_in struct
    let mut slice: &mut [u8] = unsafe { &mut *(&mut sa_data[2..6] as *mut [i8] as *mut [u8]) };
    NetworkEndian::write_u32(&mut slice,  u32::from(ip_addr));
    let destination: libc::sockaddr = libc::sockaddr {
        sa_family: libc::AF_INET as u16,
        sa_data,
    };

    let dest_addr = &destination as *const _ as *const libc::sockaddr;

    let return_value = unsafe {
        libc::sendto(sockfd, buf, icmp_len, 0, dest_addr, addr_len as u32)
    };

    if return_value == -1 {
        Err(())
    } else {
        Ok(return_value as usize)
    }
}

fn recvmsg(sockfd: Socket,
           running: Arc<AtomicBool>,
           start_time: Instant,
           iteration: usize,
           stats: &mut Statistics,
           opts: &CmdOptions) -> Result<(), std::io::Error> {
    let packet = Box::new(Ipv4Packet::new());
    let packet_ptr = Box::into_raw(packet);

    let msg_iovec = Box::new(libc::iovec {
        iov_base: packet_ptr as *mut libc::c_void,
        iov_len: std::mem::size_of::<Ipv4Packet>(),
    });

    let msg_iovec_ptr = Box::into_raw(msg_iovec);

    let cmsghdr = Box::new(CmsghdrTTL::new());
    let cmsghdr_len = std::mem::size_of::<CmsghdrTTL>();
    let cmsghdr_ptr = Box::into_raw(cmsghdr);

    let msg = Box::new(libc::msghdr {
        msg_name: std::ptr::null() as *const usize as *mut libc::c_void,
        msg_namelen: 0,
        msg_iov: msg_iovec_ptr,
        msg_iovlen: 1,
        msg_control: cmsghdr_ptr as *mut libc::c_void,
        msg_controllen: cmsghdr_len,
        msg_flags: libc::MSG_WAITALL,
    });

    let msg_ptr = Box::into_raw(msg);

    loop {
        println!("loop");
        let recv_res = unsafe {
            libc::recvmsg(sockfd, msg_ptr, libc::MSG_DONTWAIT)
        };
        match recv_res {
            -1 => {
                let errno = errno();
                if errno != libc::EAGAIN && errno != libc::EWOULDBLOCK {
                    return Err(Error::new(
                        ErrorKind::ConnectionRefused, format!("errno={}", errno)));
                }
            }
            n if n >= 0 => break, // n should be 64 since size is fixed
            _ => unreachable!(),
        }

        if !running.load(Ordering::SeqCst) {
            return Err(Error::new(ErrorKind::Interrupted, ""));
        }

        // Up to 0.01ms accuracy
        std::thread::sleep(Duration::from_nanos(8000));
    }

    let elapsed = start_time.elapsed();
    let packet_res = unsafe { Box::from_raw(packet_ptr) };
    let icmphdr_res = packet_res.into_icmphdr()?;
    let echo_reply = icmphdr_res.verify_reply();
    match echo_reply {
        EchoReply::TimeExceeded => println!("Error: Time Exceeded"),
        EchoReply::DestinationUnreachable => println!("Error: Destination Unreachable"),
        EchoReply::UndefinedType(t) => println!("Error: Undefined response type {}", t),
        EchoReply::InvalidChecksum => println!("Error: Invalid Checksum"),
        EchoReply::Valid => {
            let cmsghdr_res = unsafe { Box::from_raw(cmsghdr_ptr) };
            let ttl = cmsghdr_res.ttl;
            println!("64 bytes of data from {}, icmp_seq={} ttl={} time={:?}",
                opts.address, iteration, ttl, elapsed);
        }
    }

    match echo_reply {
        EchoReply::Valid => stats.add_ping_duration(elapsed),
        _ => stats.add_loss(),
    }

    unsafe {
        Box::from_raw(msg_ptr);
        Box::from_raw(msg_iovec_ptr);
    }
    Ok(())
}

fn main() {
    // TODO: Future Improvements
    // 1) Hard-coded payload at the moment, may need a fundamental rewrite
    // to allow variable payload due to Rust compile-time requirements
    // 2) Clean up repetitive code with macros
    // 3) Memory Leaks, valgrind --tool=massif reports single instance of leak,
    // so, culprit is most likely ctrl-c handler
    // 4) Rust Duration does not support `Display` trait, does not allow to specify
    // reporting time statistics to a specified precision. Current statistics
    // report is misleading since precision is only up to 0.01ms due to sleep
    let matches = clap_app!(ping =>
        (version: "1.0.0")
        (author: "Ethan Tsz Hang Kiang @zyklotomic")
        (about: "A cute little `ping` in Rust")
        (@arg count: -c --count +takes_value
            "Stop sending after <count> many packets have been sent.")
        (@arg interval: -i --interval +takes_value
         "Wait <interval> seconds between sending each packet. Default is one second.")
        (@arg ttl: -t +takes_value "ttl")
        (@arg dest: +required "Target destination. Only Ipv4 supported")
    ).get_matches();


    let opts_res = CmdOptions::from_matches(matches);
    if let Err(clap_err) = opts_res {
        clap_err.exit();
    }
    let opts = opts_res.unwrap();

    let mut stats = Statistics::new();

    let sockfd = socket(&opts).expect("Failed to create socket.");

    let ip = match opts.address {
        SocketAddr::V4(socket_addr) => socket_addr.ip().clone(),
        SocketAddr::V6(_) => panic!("Ipv6 not supported yet!")
    };

    println!("PING {} ({}) 56(84) bytes of data.", opts.destination, ip);

    // ctrl-c SIGINT handler
    // Due to upstream crate implementation, will cause leak
    // since another thread is spawned and not collected,
    // acceptable for now as a once-per-run leak.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting up ctrl-c seq");

    let mut counter = 1usize;
    while match opts.count {
        None => true,
        Some(c) => counter <= c,
    } && running.load(Ordering::SeqCst) {
        let echo_pkt = EchoPacket { id: 0, sequence: counter as u16 };
        let mut icmphdr = IcmpHdr::new(echo_pkt);
        icmphdr.set_checksum();
        let start_time = Instant::now();
        let _bytes_sent = sendto(sockfd, icmphdr, ip);
        let recvmsg_res = recvmsg(sockfd, running.clone(), start_time, counter,
                                  &mut stats, &opts);
        if let Err(e) = recvmsg_res {
            println!("{}", e);
            break;
        }

        let interval = match opts.interval {
            None => Duration::new(1,0),
            Some(d) => d,
        };
        std::thread::sleep(interval);
        counter += 1;
    }
    println!("--- {} ping statistics ---\n{}", opts.destination, stats);
}
