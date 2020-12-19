use nix::errno::errno;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::slice;
use std::fmt;
use std::str::FromStr;
use std::io::{Read, Write};
use byteorder::{ByteOrder, NetworkEndian};

enum EchoReply {
    TimeExceeded,
    DestinationUnreachable,
    UndefinedType(u8),
    InvalidChecksum,
    Valid,
}

#[repr(C)]
pub struct Ipv4Packet {
    version_ihl: u8, // Mask to get value, 4 bits each
    _r0: u8,
    _r1: [u8; 7],
    ttl: u8,
    _r2: [u8; 11],
    optional_1: [u8; 20],
    optional_2: [u8; 20],
    icmphdr_buffer: IcmpHeader,
}

impl Ipv4Packet {
    pub fn into_icmphdr(self) -> Result<IcmpHeader, std::io::Error> {
        let ihl: u8 = self.version_ihl & 0x0f;
        if ihl < 5 {
            Err(Error::new(
                ErrorKind::InvalidData, "Invalid IHL in packet"))
        } else {
            let packet_ptr = &self as *const _ as *const u8;
            let icmphdr_ptr = unsafe {
                packet_ptr.offset(ihl as isize * 4) as *const IcmpHeader
            };
            let icmphdr = unsafe { *icmphdr_ptr };
            Ok(icmphdr)
        }
    }

    pub fn new() -> Self {
        Ipv4Packet {
            version_ihl: 0,
            _r0: 0,
            _r1: [0u8; 7],
            ttl: 0,
            _r2: [0u8; 11],
            optional_1: [0u8; 20],
            optional_2: [0u8; 20],
            icmphdr_buffer: IcmpHeader::new(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    sa_family: libc::sa_family_t,
    sin_port: [u8; 2],
    sin_addr: [u8; 4],
}

impl sockaddr_in {
    pub fn new(sockaddr: &SocketAddrV4) -> Self {
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
#[derive(Clone, Copy)]
pub struct IcmpHeader {
    type_t: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
}

impl IcmpHeader {
    const ICMP_ECHO: u8 = 8;

    pub fn new() -> Self {
        let mut header = Self {
            type_t: Self::ICMP_ECHO,
            code: 0,
            checksum: 0,
            id: 0,
            sequence: 0,
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

    pub fn increment_seq(&mut self) {
        self.sequence += 1;
        self.checksum = self.calc_checksum();
    }

}
