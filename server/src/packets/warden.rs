use bytes::{BytesMut, Buf};
use crate::packets::{Readable, ParseError, Serializeable};
use crate::handlers::Handler;
use crate::state::ConnectionState;


pub struct SWardenPacket{
    pub payload: Vec<u8>
}


impl Readable for SWardenPacket{
    fn read(_opcode:&u16, size: &u16,buf: &mut BytesMut) -> Result<Self, ParseError> {

        let mut warden_payload = vec![0; *size as usize];
        buf.copy_to_slice(&mut warden_payload);

        // Some idiot (me) thought it may suffice if we expose crypto stuff in the handler

        Ok(SWardenPacket{
            payload: warden_payload
        })
    }
}

impl Handler<ConnectionState> for SWardenPacket{
    fn execute(&self, state: &mut ConnectionState)-> Option<Vec<Box<dyn Serializeable>>> {
        println!("==========  WARDEN ACTIVE ===========");

        if let Some(warden_crypt) = &mut state.warden_crypt{
            let mut plain_warden = vec![0u8;self.payload.len()];
            warden_crypt.decrypt_payload(&self.payload, &mut plain_warden);
            let mut buf = BytesMut::from(&plain_warden[..]);

            let command = buf.get_u8();

            let mut module_id = vec![0u8;16];
            let mut module_key = vec![0u8;16];
            buf.copy_to_slice(&mut module_id);
            buf.copy_to_slice(&mut module_key);

            let size = buf.get_u32_le();
            println!("Warden Command: {}, size: {}, id:{}, key:{}",
                     command, size,
                     hex::encode(&module_id),
                     hex::encode(&module_key)
            );
        }








        // Some(vec![Box::new(
        //
        // )])
        None
    }
}