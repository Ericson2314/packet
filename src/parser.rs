extern crate std;

pub struct Icmp<'a> {buf: &'a [u8] }

impl<'a> Icmp<'a> {
  pub fn new<'a>(buf: &'a [u8]) -> Icmp<'a> {
    Icmp{buf: buf}
  }

  pub fn icmp_type(&self) -> u8 {
    self.buf[0]
  }

  pub fn code(&self) -> u8 {
    self.buf[1]
  }

  pub fn checksum(&self) -> u16 {
    ((self.buf[2] as u16) << 8) | (self.buf[3] as u16)
  }

  pub fn data(&self) -> &'a [u8] {
    self.buf.slice(4, 8)
  }

  pub fn payload(&self) -> &'a [u8] {
    self.buf.slice_from(8)
  }
  pub fn print(&self) {
    println!("Icmp| type : {}  | code : {}  |", self.icmp_type(), self.code() );
    println!("    | length: {}  | Chksm: {}  |", self.payload().len(), self.checksum() );
  }
}

#[deriving(Show)]
pub struct Udp<'a> {buf: &'a [u8] }
/*
  pub srcport: u16, pub dstport: u16, pub length: u16, pub checksum: u16
*/

impl<'a> Udp<'a> {
  pub fn new<'a>(buf: &'a [u8]) -> Udp<'a> {
    Udp{buf: buf}
  }

  pub fn srcport(&self) -> u16 {
    ((self.buf[0] as u16) << 8) | (self.buf[1] as u16)
  }

  pub fn dstport(&self) -> u16 {
    ((self.buf[2] as u16) << 8) | (self.buf[3] as u16)
  }

  /// The length of the packet, including header, in bytes
  pub fn length(&self) -> u16 {
    ((self.buf[4] as u16) << 8) | (self.buf[5] as u16)
  }

  pub fn checksum(&self) -> u16 {
    ((self.buf[6] as u16) << 8) | (self.buf[7] as u16)
  }

  pub fn payload(&self) -> &'a [u8] {
    if self.buf.len() > self.length() as uint {
      self.buf.slice(8, self.length() as uint)
    } else {
      self.buf.slice_from(8)
    }
  }

  pub fn print(&self) {
    println!("Udp | Srcp: {}  | Dstp: {}  |", self.srcport(), self.dstport() );
    println!("    | length: {}  | Chksm: {}  |", self.length(), self.checksum() );
  }
}
