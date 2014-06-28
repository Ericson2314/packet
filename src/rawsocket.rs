extern crate std;
extern crate libc;
use self::libc::{c_int, c_void, socket, AF_INET, sockaddr_storage};
static SOCK_RAW: c_int = 3;
static IPPROTO_ICMP: c_int = 1;

pub struct RawSocket {
  sock: c_int
}

impl RawSocket {

  pub fn icmp_sock() -> Option<RawSocket> {
    let sock = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if sock < 0 {
      println!("{}, couldn't open.", sock);
      return None
    }
    Some(RawSocket{sock: sock})
  }

  pub fn recvfrom<'buf>(&self, buf: &'buf mut [u8]) -> &'buf mut [u8] {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
    let storagep = &mut storage as *mut _ as *mut libc::sockaddr;
    let mut addrlen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let bytes = unsafe { libc::recvfrom(self.sock,
                   buf.as_mut_ptr() as *mut c_void,
                   buf.len() as u64, 
                   0, storagep, &mut addrlen) };

    buf.mut_slice_to(bytes as uint)
  }
}
