use crate::packets::{Readable, ParseError, Serializeable};
use bytes::{BytesMut, Buf};
use std::fmt::{Debug, Formatter,};
use crate::handlers::Handler;
use crate::state::ConnectionState;

use crate::packets;
use std::mem::transmute;

pub struct UnimplementedPacket{
    opcode: u16,
    size: u16
}

impl Debug for UnimplementedPacket{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {

        let oc: packets::opcodes::Opcode = unsafe { transmute(self.opcode as u16) };

        f.write_str(&format!("UnimplementedPacket [ {} ] len {} : {:?}",
                             hex::encode((self.opcode as u16).to_be_bytes()).to_uppercase(),
                             self.size,
                             oc
        )).into()
    }
}

impl Readable for UnimplementedPacket{
    fn read(opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {
        if *size > buf.remaining() as u16{
            println!("Over-Long packet received!");
            return Err(ParseError::NotEnoughData);
        }
        
        buf.advance(*size as usize);
        Ok(UnimplementedPacket{
            opcode: *opcode,
            size: *size
        })
    }
}

impl Handler<ConnectionState> for UnimplementedPacket{
    fn execute(&self, _state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        //println!("Skipping unimplemented packet {:?}",self);
        if self.opcode == 0x0C0A{
            println!("WARDEN PACKET, AAAAAAAAAAAHHHHHHHHHHHHHHHHHh");
            println!("WARDEN PACKET: {}bytes",self.size)

        }
        None
    }
}