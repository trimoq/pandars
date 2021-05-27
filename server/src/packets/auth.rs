#![allow(non_snake_case)]

use bytes::{BytesMut, BufMut, Buf};
use std::convert::TryFrom;

use crate::packets::{Serializeable, ParseError};
use crate::crypto::ClientProof;


const ALC_BASE_SIZE: u16= 30;
const GAME_NAME: &[u8;3] = b"WoW";
const PLATTFORM: &[u8;3] = b"x86";
// const OS: &[u8;3] = b"Win";
const OS: &[u8;3] = b"Win";
const COUNTRY: &[u8;4] = b"enUS";

/*
  The first packet sent of every connection
*/
pub struct CAuthLogonChallenge{
  pub command: u8,
  pub error: u8,
  pub size: u16,
  pub game_name: [u8;3],
  pub version_1 : u8,
  pub version_2 : u8,
  pub version_3 : u8,
  pub build: u16,
  pub plattform: [u8;3],
  pub os: [u8;3],
  pub country: [u8;4],
  pub tzBias: u32,
  pub ip: [u8;4],
  pub srp_I_len: u8,
  pub srp_I: Vec<u8>
}

/*
  Create a default auth logon challenge
*/
impl CAuthLogonChallenge{
  pub fn new (name: &Vec<u8>) -> Self {
    let size = ALC_BASE_SIZE + name.len() as u16;
    CAuthLogonChallenge{
      command: 0,
      error: 8,
      size ,
      game_name: *GAME_NAME,
      version_1: 5,
      version_2: 4,
      version_3: 8,
      build: 18414,
      plattform: *PLATTFORM,
      os: *OS,
      country: *COUNTRY,
      tzBias: 60,
      ip: [192, 168, 121,1],
      srp_I_len: name.len() as u8,
      srp_I: name.clone()
    }
  }
}

/*
  The Auth logon challenge is a bit special, hence it is not serialized in an automated way
*/
impl Serializeable for CAuthLogonChallenge{
  fn write(&self, buf: &mut BytesMut){
    buf.put_u8(self.command);
    buf.put_u8(self.error);
    buf.put_u16_le(self.size);
    buf.put(&self.game_name[..]);
      buf.put_u8(0);
    buf.put_u8(self.version_1);
    buf.put_u8(self.version_2);
    buf.put_u8(self.version_3);
    buf.put_u16_le(self.build);
    let mut my_plattform = self.plattform.clone();
    my_plattform.reverse();
    buf.put(&my_plattform[..]);
      buf.put_u8(0);
    let mut my_os = self.os.clone();
    my_os.reverse();
    buf.put(&my_os[..]);
      buf.put_u8(0);
    let mut my_country = self.country.clone();
    my_country.reverse();
    buf.put(&my_country[..]);
    buf.put_u32_le(self.tzBias);
    buf.put(&self.ip[..]);
    buf.put_u8(self.srp_I_len);
    buf.put(&self.srp_I[..]);

    // buf.put(&[65;200_000_000][..]);


  }
}
#[derive(Debug,Clone)]
pub struct RemoteParameters{
  pub g: Vec<u8>,
  pub n: Vec<u8>,
  pub b: Vec<u8>,
  pub s: Vec<u8>,
}

#[derive(Debug)]
pub struct SAuthLogonChallenge{
 pub remote_parameters: RemoteParameters
}



impl TryFrom<&mut BytesMut> for SAuthLogonChallenge{
  type Error = ParseError;
  fn try_from(buf: &mut BytesMut) -> Result<Self, Self::Error>{
    let error = buf.get_u16_le();
    if error > 0 {
      return Err(ParseError::Fatal);
    }

    // reversed: b, n
    // not reversed: g, s

    // parameter B
    if buf.len()<32{
      return Err(ParseError::NotEnoughData);
    }
    let mut b = vec![0;32 as usize];
    buf.copy_to_slice(&mut b);

    // parameter g
    let g_len = buf.get_u8();
    if buf.len()<g_len as usize{
      return Err(ParseError::NotEnoughData);
    }
    if g_len > 32 {
      return Err(ParseError::Fatal);
    }
    let mut g = vec![0;g_len as usize];
    buf.copy_to_slice(&mut g);

    // parameter n
    let n_len = buf.get_u8();
    if buf.len()<n_len as usize{
      return Err(ParseError::NotEnoughData);
    }
    if n_len > 32 {
      return Err(ParseError::Fatal);
    }
    let mut n = vec![0;n_len as usize];
    buf.copy_to_slice(&mut n);

    // parameter s
    if buf.len()<32{
      return Err(ParseError::NotEnoughData);
    }
    let mut s = vec![0;32 as usize];
    buf.copy_to_slice(&mut s);

    if buf.len()<17{
      return Err(ParseError::NotEnoughData);
    }
    let mut _trailing_bytes  = vec![0;16 as usize];
    buf.copy_to_slice(&mut _trailing_bytes);

    let mut _unsued_end_bzte = buf.get_u8();

    g.reverse();
    n.reverse();
    b.reverse();

    Ok(
      SAuthLogonChallenge{
        remote_parameters: RemoteParameters{
          b,
          g,
          n,
          s
        }
      }
    )
  }
}

pub struct CAuthLogonProof{
  client_proof: ClientProof
}
impl CAuthLogonProof{
  pub fn new(client_proof: ClientProof) -> Self{
    CAuthLogonProof{
      client_proof
    }
  }
}
impl Serializeable for CAuthLogonProof{
  fn write(&self, buf: &mut BytesMut){
    buf.put_u8(1);
    buf.put(&self.client_proof.A[..]);
    buf.put(&self.client_proof.M1[..]);
    buf.put(&self.client_proof.crc[..]);
    buf.put_u16_le(0); // whatever this is

  }
}

#[allow(dead_code)]
pub struct SAuthLogonProof{
  m2: Vec<u8>
}


impl TryFrom<&mut BytesMut> for SAuthLogonProof {
  type Error = ParseError;
  fn try_from(buf: &mut BytesMut) -> Result<Self, Self::Error> {
    let _error = buf.get_u8();
    // if error > 0 {
    //   return Err(ParseError::Fatal);
    // }

    if buf.len() < 30 {
      return Err(ParseError::Fatal);
    }
    let mut m2 = vec![0;30];
    buf.copy_to_slice(&mut m2);
    Ok(SAuthLogonProof{
      m2
    })
  }
}

pub struct CRealmList{
}
impl Serializeable for CRealmList{
  fn write(&self, buf: &mut BytesMut){
    buf.put_u8(0x10);
    buf.put_u32_le(0); // whatever this is

  }
}

#[derive(Debug)]
pub struct RealmListEntry{
  pub ty: u8,
  pub lock: u8,
  pub flags: u8,
  pub name: String,
  pub addr: String,
  pub population: u32,
  pub char_count: u8,
  pub timezone: u8,
  pub realmid: u8,
}

pub struct SRealmList{
  // ub command: u8, removed outside
  pub size: u16,
  pub num_realm: u16,
  pub realms: Vec<RealmListEntry>,
}

impl TryFrom<&mut BytesMut> for SRealmList {
  type Error = ParseError;
  fn try_from(buf: &mut BytesMut) -> Result<Self, Self::Error> {
    if buf.len() < 3{
      return Err(ParseError::NotEnoughData);

    }

    let size = buf.get_u16_le();
    if buf.len() < size as usize{
      return Err(ParseError::NotEnoughData);
    }

    let _padding = buf.get_u32_le();
    let num = buf.get_u16_le();

    let mut realms = Vec::new();
    for _i in 0 .. num {
      let ty = buf.get_u8();
      let lock = buf.get_u8();
      let flags = buf.get_u8();

      let mut name_buff = Vec::new();
      let mut b = 0xffu8;
      while b!=0x00 && buf.len()>0 {
        b = buf.get_u8();
        if b != 0x00 {
          name_buff.push(b);
        }
      }

      let mut addr_buff = Vec::new();
      let mut b = 0xffu8;
      while b!=0x00 && buf.len()>0 {
        b = buf.get_u8();
        if b != 0x00 {
          addr_buff.push(b);
        }
      }
      if buf.len() < 8 {
        return Err(ParseError::NotEnoughData);
      }
      let population = buf.get_u32_le();
      let char_count = buf.get_u8();
      let realmid = buf.get_u8();
      let timezone = buf.get_u8();

      let entry = RealmListEntry{
        ty,
        lock,
        flags,
        name: String::from_utf8(name_buff).unwrap(),
        addr: String::from_utf8(addr_buff).unwrap(),
        population,
        char_count,
        timezone,
        realmid
      };
      realms.push(entry);
    }
    let _padding2 = buf.get_u16_le();
    //let _padding3 = buf.get_u8();

    Ok(SRealmList{
      size,
      num_realm: num,
      realms: realms
    })
  }
}