use bytes::BytesMut;
use std::convert::TryFrom;
use crate::packets::auth::*;
use crate::{ParseError, ConnectionState};
use crate::handlers::Handler;
use crate::packets::meta::UnimplementedPacket;
use crate::packets::Readable;
use crate::packets::world_session::{SAuthResponse, SEnumCharactersResponse, SUpdateObject, SAuctionHello, SAuctionListResult,STimesyncRequest,SAuctionBidderListResult,SAuctionOwnerListResult, SAccountDataTimes};
use crate::packets::warden::SWardenPacket;

pub fn get_auth_packet_from_body(opcode:&u8, body: &mut BytesMut) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{
  match opcode {
    0x00 => SAuthLogonChallenge::try_from(body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x01 => SAuthLogonProof::try_from(body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x10 => SRealmList::try_from(body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    e => {
      println!("##### ILLEGAL AUTH opcode: {}",e);
      return Err(ParseError::Unimplemented);
    }    
  }
}

pub fn get_world_packet_from_body(opcode:&u16, size: &u16, body: &mut BytesMut) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{
  match opcode {
    0x0ABA => SAuthResponse::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x11C3 => SEnumCharactersResponse::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x1792 => SUpdateObject::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x10A7 => SAuctionHello::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x0982 => SAuctionListResult::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x1A8F => STimesyncRequest::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x0B24 => SAuctionBidderListResult::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x1785 => SAuctionOwnerListResult::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x162B => SAccountDataTimes::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    0x0C0A => SWardenPacket::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
    _ => UnimplementedPacket::read(opcode, size,body).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>),
  }
}