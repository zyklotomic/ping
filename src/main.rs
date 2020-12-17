#[macro_use] extern crate clap;

use nix::errno::errno;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::fmt;
use std::str::FromStr;
use byteorder::{ByteOrder, NetworkEndian};

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

struct Socket { fd: libc::c_int }

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

#[repr(C)]
#[derive(Clone, Copy)]
struct sockaddr_in {
    sa_family: libc::sa_family_t,
    sin_port: [u8; 2],
    sin_addr: [u8; 4],
}

impl sockaddr_in {
    fn new(sockaddr: &SocketAddrV4) -> Self {
        let mut sin_addr = [0u8; 4];
        let mut sin_port = [0u8; 2];
        NetworkEndian::write_u32(&mut sin_addr, u32::from(sockaddr.ip().clone()));
        NetworkEndian::write_u16(&mut sin_port, sockaddr.port());
        Self {
            sa_family: libc::AF_INET as u16,
            sin_port,
            sin_addr,
        }
    }
}

#[repr(C)]
struct IcmpHeader {
    type_t: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
}

impl IcmpHeader {
    const ICMP_ECHO: u8 = 8;

    fn new(sequence: u16) -> Self {
        let mut header = Self {
            type_t: Self::ICMP_ECHO,
            code: 0,
            checksum: 0,
            id: 0,
            sequence,
        };
        header.checksum = header.calc_checksum();
        header
    }

    fn calc_checksum(&self) -> u16 {
        let mut checksum = (self.type_t as u32)
            .checked_add((self.code as u32) << 8).unwrap()
            .checked_add(self.checksum as u32).unwrap()
            .checked_add(self.id as u32).unwrap()
            .checked_add(self.sequence as u32).unwrap();
        checksum = (checksum >> 16) + (checksum & 0xffff);
        checksum += checksum >> 16;
        !checksum as u16
    }
}

impl Socket {
    fn new() -> Result<Self, std::io::Error> {
        let sockfd = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_STREAM, libc::IPPROTO_TCP)
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
            return Err(libc_ioerr!("Failed to set TTL in setsockopt()"))
        }
        Ok(())
    }

    fn connect(&mut self, sockaddr: SocketAddrV4) -> Result<(), std::io::Error> {
        let addr = sockaddr_in::new(&sockaddr);
        let addr_ptr = c_const_ptr!(addr, libc::sockaddr);
        let len = std::mem::size_of::<libc::sockaddr>() as u32;
        let err = unsafe {
            libc::connect(self.fd, addr_ptr, len)
        };

        if err == -1 {
            Err(libc_ioerr!("connect() failed"))
        } else {
            Ok(())
        }
    }
}

fn main() {
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

    let ttl = args.value_of("ttl")
        .map(usize::from_str)
        .transpose()
        .expect("Failed to parse argument for --ttl (-t)")
        .unwrap_or(64usize);

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

    let mut socket = Socket::new().unwrap();
    socket.setsockopt(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP).unwrap();
    socket.setsockopt(libc::SOL_IP, libc::IP_TTL, ttl as i32).unwrap();
    socket.setsockopt(libc::SOL_IP, IP_RECVTTL, 1);

    for _ in 0..count {

    }
}
