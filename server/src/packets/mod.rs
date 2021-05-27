use bytes::{BytesMut, BufMut};
use crate::ConnectionState;
use bytes::Buf;
use crate::handlers::Handler;
use crate::handlers::world_session::*;
use std::convert::TryFrom;
use std::convert::TryInto;
use crate::packets::opcode_matcher::get_world_packet_from_body;


pub mod auth;
pub mod world_session;
pub mod meta;
pub mod opcodes;
pub mod bitutil;
pub mod warden;

mod opcode_matcher;

const MIN_SIZE_AUTH:usize = 1;
const MIN_SIZE_WORLD: usize = 4;

pub trait Serializeable{
  fn write(&self, buf: &mut BytesMut);
}

pub trait Readable{
  fn read(opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> where Self: std::marker::Sized;
}

trait SpecializedParser{
  fn parse(&mut self, bytes: &mut BytesMut, state: &mut ConnectionState) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>;
}

pub enum ConnectionType{
  AuthServer,
  WorldServer
}

pub enum ParseError{
  NotEnoughData,
  Fatal,
  Unimplemented
}

pub struct MopParser{
  parser: Box< dyn SpecializedParser>
}

struct AuthServerParser{

}
impl AuthServerParser{
  fn new() -> Self{
    AuthServerParser{}
  }
}
struct WorldServerParser{
  hello_received: bool,
  authenticated: bool,
  state: Option<WorldServerParserState>,
}
impl WorldServerParser{
  pub fn new() -> Self{
    WorldServerParser{
      hello_received: false,
      authenticated: false,
      state: None
    }
  }
}
struct WorldServerParserState{
  current_packet_size: u16,
  current_packet_opcode: u16,
}

impl MopParser{
  pub fn new( connection_type: ConnectionType) -> Self {
    MopParser{
      parser: match connection_type{
        ConnectionType::AuthServer => Box::new(AuthServerParser::new()),
        ConnectionType::WorldServer => Box::new(WorldServerParser::new())
      }
    }
  }

  pub fn parse(&mut self, bytes: &mut BytesMut, state: &mut ConnectionState) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{
    self.parser.parse(bytes,state)
  }
}


impl SpecializedParser for AuthServerParser{
  fn parse(&mut self, bytes: &mut BytesMut, _state: &mut ConnectionState) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{
    // println!("AuthServerParser here");
    // println!("parsing: {}", hex::encode(&bytes));
    if bytes.len() < MIN_SIZE_AUTH {
      return Err(ParseError::NotEnoughData)
    }
    let opcode = bytes.get_u8();
    //let error = bytes.get_u16_le();
    // if error > 0 {
    //   return Err(ParseError::Fatal)
    // }
    opcode_matcher::get_auth_packet_from_body(&opcode, bytes)
  }
}


impl SpecializedParser for WorldServerParser{
  fn parse(&mut self, bytes: &mut BytesMut, state: &mut ConnectionState) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{
    // println!("WorldServerParser here");

    if bytes.len() < MIN_SIZE_WORLD {
      return Err(ParseError::NotEnoughData)
    }

    if !self.hello_received {
      self.hello_received = true;
      return HelloHandler::try_from(bytes).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>);
    }

    if !self.authenticated{
      self.authenticated = true;
      self.parse_fixed_header(bytes)
    }
    else {
      // once handshake is complete and we are authenticated, all packets have to match this branch
      self.parse_encrypted_header(bytes, state)
    }
    //Err(ParseError::Fatal)
  }
}

impl WorldServerParser{
  fn parse_fixed_header(&mut self, bytes: &mut BytesMut) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{

    let size = bytes.get_u16_le();
    let opcode = bytes.get_u16_le();

    if opcode == 0x0949{
      return AuthChallengeHandler::try_from(bytes).map(|x|Box::new(x)as Box<dyn Handler<ConnectionState>>);
    }
    else if opcode == 0x0000 {
      unimplemented!()
    }
    else{
      println!("Received unknown opcode: {:x} This is fatal if not authenticated!",opcode);
      bytes.advance(size as usize);
      Err(ParseError::Fatal)
    }
  }
  fn parse_encrypted_header(&mut self, bytes: &mut BytesMut, state: &mut ConnectionState) -> Result<Box<dyn Handler<ConnectionState>>,ParseError>{

    if bytes.len() < MIN_SIZE_WORLD {
      return Err(ParseError::NotEnoughData)
    }



    if let Some(world_crypt) = &mut state.world_crypt{

      // decide whether to start from fresh packet
      match &mut self.state{

        // there are bytes in the buffer, that still needs to be parsed.
        // Its header has already been processed
        Some(s) => {
          if bytes.remaining() < s.current_packet_size as usize {
            return Err(ParseError::NotEnoughData);
          }
          else{
            let _oc: crate::packets::opcodes::Opcode = unsafe { std::mem::transmute(s.current_packet_opcode as u16) };
            let opcode = s.current_packet_opcode;
            let size =  s.current_packet_size;
            // println!("packet receive complete: {:?}",oc );
            self.state = None;  // we can now remove the cached packet header metadata

            return get_world_packet_from_body(&opcode, &size, bytes);
          }  
        },

        // we start with a fresh packet
        None => {
          // println!("No lingering packet found");

          let mut encrypted_header = vec![0;4];
          let mut decrypted_header = vec![0;4];
          bytes.copy_to_slice(&mut encrypted_header);
          // println!("EncryptedHeader {}", hex::encode(&encrypted_header));
          world_crypt.decrypt_header(&encrypted_header,&mut decrypted_header);
          // println!("DecryptedHeader {}", hex::encode(&decrypted_header));
          let header = u32::from_le_bytes(decrypted_header[..].try_into().unwrap());
          let opcode = ( header & 0x1FFF ) as u16;
          let size = ((header & (!0x1FFF)) >> 13) as u16;
          let _oc: crate::packets::opcodes::Opcode = unsafe { std::mem::transmute(opcode as u16) };
          // println!("OC[{:?}],size[{}],len[{}]",oc,size,bytes.remaining());
          // println!("Opcode: {}", hex::encode((opcode as u16).to_be_bytes()));
          // println!("size: {}", size);
    
          // if size > 10236 {
          //   panic!("Unimplemented jumbo packets");
          // }

          if size > bytes.remaining() as u16{
            // println!("incomplete packet received");
            self.state = Some(WorldServerParserState{
              current_packet_size: size,
              current_packet_opcode: opcode,
            });
            return Err(ParseError::NotEnoughData);
          }
    
          return get_world_packet_from_body(&opcode, &size,bytes);

        }
      }
    }
    else{
      return Err(ParseError::Fatal);
    }
  }
}

pub fn to_plain_header(size: u16, opcode: u16) -> Vec<u8>{
  let data :u32 = ((size as u32) << 13) | (opcode as u32);
  data.to_le_bytes().to_vec()
}



pub fn write_guid_mask_login(bytes: &mut BytesMut, guid: &Vec<u8>) {
  let order = vec![1, 4, 7, 3, 2, 6, 5, 0];
  write_guid_mask(bytes, guid, order)
}
pub fn write_guid_login(bytes: &mut BytesMut, guid: &Vec<u8>){
  //let order = vec![2, 1, 4, 7, 5, 0, 3, 6];
  // let order = vec![5, 1, 0, 6, 2, 4, 7, 3];
  // let order = vec![0, 1, 2, 3, 4, 5, 6, 7];
  let order = vec![5, 1, 0, 6, 2, 4, 7, 3];
  let order = order.iter().map(|i| 7-i).collect();
  write_guid(bytes, guid, order)
}

pub fn write_guid_mask_ah_hello(bytes: &mut BytesMut, guid: &Vec<u8>) {
  let order = vec![1, 5, 2, 0, 3, 6, 4, 7];
  write_guid_mask(bytes, guid, order)
}
pub fn write_guid_ah_hello(bytes: &mut BytesMut, guid: &Vec<u8>){
  let order = vec![2, 7, 1, 3, 5, 0, 4, 6];
  write_guid(bytes, guid, order)
}

// pub fn write_guid_mask_ah_list(bytes: &mut BytesMut, guid: &Vec<u8>) {
//   let order = vec![1, 5, 2, 0, 3, 6, 4, 7];
//   write_guid_mask(bytes, guid, order)
// }
// pub fn write_guid_ah_list(bytes: &mut BytesMut, guid: &Vec<u8>){
//   let order = vec![2, 7, 1, 3, 5, 0, 4, 6];
//   write_guid(bytes, guid, order)
// }

pub fn write_guid_mask_set_selection(bytes: &mut BytesMut, guid: &Vec<u8>) {
  let order = vec![7, 6, 5, 4, 3, 2, 1, 0];
  write_guid_mask(bytes, guid, order)
}
pub fn write_guid_set_selection(bytes: &mut BytesMut, guid: &Vec<u8>){
  let order = vec![0, 7, 3, 5, 1, 4, 6, 2];
  write_guid(bytes, guid, order)
}

pub fn write_guid_mask_ah_list_owner_items(bytes: &mut BytesMut, guid: &Vec<u8>) {
  let order = vec![4, 5, 2, 1, 7, 0, 3, 6];
  write_guid_mask(bytes, guid, order)
}
pub fn write_guid_ah_list_owner_items(bytes: &mut BytesMut, guid: &Vec<u8>){
  let order = vec![5, 7, 3, 6, 4, 2, 0, 1];
  write_guid(bytes, guid, order)
}

pub fn write_guid_mask(bytes: &mut BytesMut, guid_bytes: &Vec<u8>, order: Vec<u8>) {
  let mut result = 0;
  for (i,idx) in order.iter().rev().enumerate() {
    result += ((guid_bytes[*idx as usize] > 0)  as usize) << i;
  }
  bytes.put_u8(result as u8);
}
pub fn write_guid(bytes: &mut BytesMut, guid_bytes: &Vec<u8>,order: Vec<u8>){
  for idx in order.iter() {
    let b = guid_bytes[*idx as usize];
    if b != 0{
      bytes.put_u8(b ^ 1);
    }
  }
}