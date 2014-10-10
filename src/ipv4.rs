extern crate std;

use std::mem::transmute;
use std::num::Int;
use std::io::net::ip::{IpAddr, Ipv4Addr};
use std::vec::Vec;

#[deriving(PartialEq, PartialOrd, Eq, Ord,
           Clone, Show)]
pub struct V { buf: Vec<u8> }

pub struct A { buf:    [u8] }

// TODO: sanitzation inside new() methods?

impl V {
  pub fn new(buf: Vec<u8>) -> V {
    V { buf: buf }
  }

  pub fn from_body(_ip: IpAddr, _protocol: u8, data: &[u8]) -> V {
    let mut buf: Vec<u8> = Vec::with_capacity(data.len() + MIN_HDR_LEN_BYTES as uint);
    // insert header into buf;
    buf.push_all(data);
    V { buf: buf }
  }

  pub fn as_vec(self) -> Vec<u8> { self.buf }

  pub fn borrow(&self) -> &A { unsafe { transmute(self.buf.as_slice()) } }

  pub fn borrow_mut(&mut self) -> &mut A { unsafe { transmute(self.buf.as_mut_slice()) } }

}

pub static MIN_HDR_LEN_BITS: u32 = MIN_HDR_LEN_WORDS * 32;
pub static MIN_HDR_LEN_BYTES: u32 = MIN_HDR_LEN_WORDS * 4;
pub static MIN_HDR_LEN_WORDS: u32 = 5;

///   From RFC 791
///
///    0                   1                   2                   3
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |Version|  IHL  |Type of Service|          Total Length         |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         Identification        |Flags|      Fragment Offset    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  Time to Live |    Protocol   |         Header Checksum       |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                       Source Address                          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Destination Address                        |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |                    Options                    |    Padding    |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[repr(packed)]
#[unstable]
pub struct IpStruct {
  pub version_ihl:           u8,  // IP version (= 4)
  ////////////////////////////////// Internet header length
  pub type_of_service:       u8,  // Type of service
  pub total_length:          u16, // Total length in octets
  pub identification:        u16, // Identification
  pub flags_fragment_offset: u16, // 3-bits Flags
  ////////////////////////////////// Fragment Offset
  pub time_to_live:          u8,  // Time To Live
  pub protocol:              u8,  // Protocol
  pub header_checksum:       u16, // Checksum
  pub source_address:        u32, // Source Address
  pub destination_address:   u32, // Destination Address

  // this is invalid if there are options
  // mainly used to make struct a DST, so pointer can be cast
  pub body:                  [u8],   // body of packet
}

#[repr(u8)]
pub enum Precedence {
  NetworkControl      = 0b111_00000,
  InternetworkControl = 0b110_00000,
  CriticEpc           = 0b101_00000,
  FlashOverride       = 0b100_00000,
  Flash               = 0b011_00000,
  Immediate           = 0b010_00000,
  Priority            = 0b001_00000,
  Routine             = 0b000_00000,
}

bitflags! {
  flags ServiceFlags: u8 {
    #[allow(non_uppercase_statics)]
    static LowDelay          = 0b000_100_00,
    #[allow(non_uppercase_statics)]
    static HighThroughput    = 0b000_010_00,
    #[allow(non_uppercase_statics)]
    static HighReliability   = 0b000_001_00,
    //static NormalDelay       = !LowDelay       .bits,
    //static NormalThroughput  = !HighThroughput .bits,
    //static NormalReliability = !HighReliability.bits,
  }
}

bitflags! {
  flags IpFlags: u16 {
    #[allow(non_uppercase_statics)]
    static DontFragment  = 0b010_00000_00000000,
    #[allow(non_uppercase_statics)]
    static MoreFragments = 0b001_00000_00000000,
  }
}


impl A {

  pub fn as_slice(&self) -> &[u8] {
    unsafe { transmute(self) }
  }

  pub fn as_mut_slice(&mut self) -> &mut [u8] {
    unsafe { transmute(self) }
  }

  pub fn cast(&self) -> &IpStruct {
    unsafe { transmute(self.cast()) }
  }

  pub fn cast_mut(&mut self) -> &mut IpStruct {
    unsafe { transmute(self.cast()) }
  }

  pub fn new(buf: &[u8]) -> &A {
    unsafe { transmute(buf) }
  }

  pub fn new_mut(buf: &mut [u8]) -> &mut A {
    unsafe { transmute(buf) }
  }

  pub fn get_version(&self) -> u8 { self.buf[0] >> 4 }
  pub fn set_version(&mut self, v: u8) {
    static MASK: u8 = 0b1111_0000;
    assert!(v & MASK == 0);
    self.buf[0] &= MASK;
    self.buf[0] |= v << 4;
  }

  pub fn get_hdr_len(&self) -> u8 { self.buf[0] & 0x0F }
  pub fn set_hdr_len(&mut self, v: u8) {
    static MASK: u8 = 0b1111_0000;
    assert!(v & MASK == 0);
    self.buf[0] |= v;
  }

  pub fn hdr_bytes(&self) -> u8 { self.get_hdr_len() * 4 }

  pub fn get_total_length(&    self) -> u16 { Int::from_be(self.cast()    .total_length) }
  pub fn set_total_length(&mut self, v: u16)             { self.cast_mut().total_length = v.to_be(); }


  pub fn get_type_of_service(&self) -> (Precedence, ServiceFlags) {
    static MASK: u8 = 0b111_00000;
    let tos = self.cast().type_of_service;
    ( unsafe { ::std::mem::transmute(tos & MASK) },
      ServiceFlags { bits: tos & !MASK } )
  }
  pub fn set_type_of_service(&mut self, prec: Precedence, flags: ServiceFlags) {
    self.cast_mut().type_of_service = prec as u8 | flags.bits;
  }


  pub fn get_identification(&    self) -> u16 { Int::from_be(self.cast()    .identification) }
  pub fn set_identification(&mut self, v: u16)             { self.cast_mut().identification = v.to_be(); }


  pub fn get_flags_fragment_offset(&self) -> (IpFlags, u16) {
    let ffo = self.cast().flags_fragment_offset;
    static MASK: u16 = 0b111_00000_00000000;
    ( unsafe { ::std::mem::transmute(ffo & MASK) },
      ffo & !MASK)
  }
  pub fn set_flags_fragment_offset(&mut self, flags: IpFlags, offset: u16) {
    assert!(0 == (offset & 0b111_00000_00000000));
    self.cast_mut().flags_fragment_offset = flags.bits | offset;
  }


  pub fn get_time_to_live(&    self) -> u8  { self.cast()    .time_to_live }
  pub fn set_time_to_live(&mut self, v: u8) { self.cast_mut().time_to_live = v; }

  pub fn get_protocol(&    self) -> u8  { self.cast()    .protocol }
  pub fn set_protocol(&mut self, v: u8) { self.cast_mut().protocol = v; }

  pub fn get_header_checksum(&    self) -> u16 { Int::from_be(self.cast()    .header_checksum) }
  pub fn set_header_checksum(&mut self, v: u16)             { self.cast_mut().header_checksum = v.to_be(); }

  pub fn get_source(&self) -> IpAddr {
    Ipv4Addr(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
  }
  pub fn set_source(&mut self, ip: IpAddr) -> Result<(), ()> {
    match ip {
      Ipv4Addr(a, b, c, d) => {
        self.buf[12] = a;
        self.buf[13] = b;
        self.buf[14] = c;
        self.buf[15] = d;
      },
      _ => return Err(()),
    }
    Ok(())
  }

  pub fn get_destination(&self) -> IpAddr {
    Ipv4Addr(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
  }
  pub fn set_destination(&mut self, ip: IpAddr) -> Result<(), ()> {
    match ip {
      Ipv4Addr(a, b, c, d) => {
        self.buf[16] = a;
        self.buf[17] = b;
        self.buf[18] = c;
        self.buf[19] = d;
      },
      _ => return Err(()),
    }
    Ok(())
  }

  // Eh, todo. Iterator over IpOptions?
  //pub fn options(&self) -> ... {  }

  pub fn get_payload(&self) -> &[u8] {
    if self.get_total_length() as uint > self.buf.len() {
      self.buf.slice_from(self.hdr_bytes() as uint)
    } else {
      self.buf.slice(self.hdr_bytes() as uint, self.get_total_length() as uint)
    }
  }

  //TODO: this results in when actually run
  //    task '<unknown>' has overflowed its stack
  //    Illegal instruction (core dumped)
  pub fn print(&self) {
    println!("Ip  | ver {} | {} | Tos {} | Len {}  |",
             self.get_version(), self.get_hdr_len(), self.cast().type_of_service, self.get_total_length());
    println!("    | FId {}    |   off {} |", self.get_identification(), self.get_flags_fragment_offset().val1());
    println!("    | ttl {} | proto {} | sum {} |", self.get_time_to_live(), self.get_protocol(), self.get_header_checksum());
    println!("    | Src {}   | Dst {} |", self.get_source(), self.get_destination());
  }
}
