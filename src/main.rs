#[macro_use] extern crate clap;

use nix::errno::errno;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::slice;
use std::fmt;
use std::str::FromStr;
use std::io::{Read, Write};
use byteorder::{ByteOrder, NetworkEndian};

mod structs;
use structs::{IcmpHeader, Ipv4Packet, sockaddr_in};

// setsockopt constant
const IP_RECVTTL: libc::c_int = 12;

macro_rules! c_const_ptr {
    ($x:literal, $t:ty) => {
        (&($x as $t) as *const _ as *const libc::c_void,
         std::mem::size_of::<$t>() as u32)
    };

    ($x:expr) => {
        &$x as *const _ as *const libc::c_void
    };

    ($x:expr, $t:ty) => {
        &$x as *const _ as *const $t
    }
}

macro_rules! libc_ioerr {
    ($x:literal) => {
        Error::new(ErrorKind::Other, format!("{}, errno {}", $x, errno()))
    }
}

struct Socket {
    fd: libc::c_int
}

impl std::io::Write for Socket {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let len = buf.len();
        let ptr = buf.as_ptr() as *const libc::c_void;
        let null_ptr = std::ptr::null() as *const libc::sockaddr;

        let bytes_sent = unsafe {
            libc::sendto(self.fd, ptr, len, libc::MSG_NOSIGNAL, null_ptr, 0)
        };

        if bytes_sent == -1 {
            Err(libc_ioerr!("sendto() failed"))
        } else {
            Ok(bytes_sent as usize)
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}

impl std::io::Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let len = buf.len();
        let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut libc::c_void;
        let null_sock: *mut libc::sockaddr = std::ptr::null_mut();
        let zero_ptr: *mut u32 = std::ptr::null_mut();

        let bytes_read = unsafe {
            libc::recvfrom(self.fd, buf_ptr, len, 0, null_sock, zero_ptr)
        };

        if bytes_read == -1 {
            Err(libc_ioerr!("read() from socket failed"))
        } else {
            Ok(bytes_read as usize)
        }
    }
}

impl std::ops::Drop for Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
    }
}

impl Socket {
    fn new() -> Result<Self, std::io::Error> {
        let sockfd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
        };

        if sockfd == -1 {
            return match errno() {
                13 => Err(Error::new(ErrorKind::PermissionDenied, "")),
                _ => Err(libc_ioerr!("socket() syscall error")),
            };
        }

        Ok(Socket { fd: sockfd })
    }

    fn setsockopt(&mut self, level: libc::c_int, name: libc::c_int, value: libc::c_int)
                  -> Result<(), std::io::Error> {
        let err = {
            let optval = c_const_ptr!(value);
            let len = std::mem::size_of::<libc::c_int>() as u32;
            unsafe {
                libc::setsockopt(self.fd, level, name, optval, len)
            }
        };

        if err == -1 {
            return Err(libc_ioerr!("setsockopt() failed"))
        }
        Ok(())
    }

    fn connect(&mut self, sockaddr: SocketAddr) -> Result<(), std::io::Error> {
        match sockaddr {
            SocketAddr::V6(_) =>  Err(libc_ioerr!("Ipv4 only support at the moment!")),
            SocketAddr::V4(socketaddrv4) => {
                let addr = sockaddr_in::new(&socketaddrv4);
                let addr_ptr = c_const_ptr!(addr, libc::sockaddr);
                let len = std::mem::size_of::<libc::sockaddr>() as u32;

                let err = unsafe { libc::connect(self.fd, addr_ptr, len) };
                if err == -1 {
                    Err(libc_ioerr!("connect() failed"))
                } else {
                    Ok(())
                }
            },
        }
    }
}

fn ping(socket: &mut Socket, icmphdr: &IcmpHeader) {
    let buf: &[u8] = unsafe {
        std::slice::from_raw_parts(
            c_const_ptr!(icmphdr, u8),
            std::mem::size_of::<IcmpHeader>()
        )
    };
    socket.write_all(buf);

    let ipv4_packet_size = std::mem::size_of::<Ipv4Packet>();
    let mut read_buf = Vec::with_capacity(100);
    socket.read_to_end(&mut read_buf);
}

fn main() -> Result<(), std::io::Error> {
    let args = clap_app!(ping =>
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

    let ttl: Option<usize> = args.value_of("ttl")
        .map(usize::from_str)
        .transpose()
        .expect("Failed to parse argument for --ttl (-t)");

    let count = args.value_of("count")
        .map(usize::from_str)
        .transpose()
        .expect("Failed to parse argument for --count (-c)")
        .unwrap_or(1usize);

    let interval = args.value_of("interval")
        .map(usize::from_str)
        .transpose()
        .expect("Failed to parse argument for --interval (-i)")
        .unwrap_or(1usize);

    let dest: SocketAddr = args.value_of("dest")
        .map(|input| format!("{}:0", input).to_socket_addrs())
        .transpose()
        .expect("Failed to resolve destintation argument")
        .map(|mut iter| iter.next())
        .flatten()
        .unwrap(); // to_socket_addrs returns Some if non-empty iter

    let mut socket = Socket::new()?;

    if let Some(t) = ttl {
        socket.setsockopt(libc::SOL_IP, libc::IP_TTL, t as i32)?;
    }
    socket.setsockopt(libc::SOL_IP, IP_RECVTTL, 1)?;
    socket.connect(dest)?;

    let mut icmphdr = IcmpHeader::new();

    for _ in 0..count {
        ping(&mut socket, &icmphdr);
        icmphdr.increment_seq();
    }

    Ok(())
}
