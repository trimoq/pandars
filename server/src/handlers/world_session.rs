use crate::packets::{Serializeable, ParseError};
use bytes::{BytesMut, BufMut, Buf};
use crate::handlers::Handler;
use crate::state::{ConnectionState, AuthState};
use std::convert::TryFrom;
use crate::crypto::{generate_auth_response, SessionCrypto, WardenCrypto};
use crate::packets::world_session::{*};

pub struct HelloHandler;

impl TryFrom<&mut BytesMut> for HelloHandler {
    type Error = ParseError;
    fn try_from(buf: &mut BytesMut) -> Result<Self, Self::Error> {
        let size = buf.get_u16_le();
        // println!("size: {}",size);
        if buf.remaining() < size as usize {
            println!("Fatal problem in HelloHandler!");
            return Err(ParseError::Fatal);
        }
        buf.advance(size as usize);
        Ok(HelloHandler)
    }
}
impl Handler<ConnectionState> for HelloHandler{
    fn execute(&self, _state: &mut ConnectionState)-> Option<Vec<Box<dyn Serializeable>>> {
        // println!("HEllo from the hello handler");
        Some(vec![Box::new(HelloHandler)])
    }
}
impl Serializeable for HelloHandler{
    fn write(&self, buf: &mut BytesMut) {
        buf.put_u8(0x030);
        buf.put_u8(0x000);
        buf.put(&b"WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER"[..]);
        buf.put_u8(0x000);
    }
}

pub struct AuthChallengeHandler{
    seed: Vec<u8>
}

impl TryFrom<&mut BytesMut> for AuthChallengeHandler {
    type Error = ParseError;
    fn try_from(buf: &mut BytesMut) -> Result<Self, Self::Error> {
        if buf.len() < 0x25 {
            println!("Fatal problem in AuthChallengeHandler!");
            return Err(ParseError::Fatal);
        }
        let _ = buf.get_u16();  // some crap
        let mut crap = vec![0;32];
        buf.copy_to_slice(&mut crap);
        let _ = buf.get_u8();   // more crap
        let mut seed = vec![0;4];
        buf.copy_to_slice(&mut seed);
        // println!("Parsed AuthChallengeHandler--------");
        Ok(AuthChallengeHandler{
            seed
        })
    }
}

impl Handler<ConnectionState> for AuthChallengeHandler{
    fn execute(&self, state: &mut ConnectionState)-> Option<Vec<Box<dyn Serializeable>>> {
        // println!("Computing Auth Challenge");

        let (hmac, seed) = generate_auth_response(
            state.handshake.session_key.clone(),
            state.handshake.username.clone(),
            self.seed.clone()
        );

        state.world_crypt = Some(SessionCrypto::new(state.handshake.session_key.clone()));
        state.warden_crypt = Some(WardenCrypto::new(state.handshake.session_key.clone()));

        Some(vec![Box::new(CAuthResponse{
            digest: hmac,
            client_seed: seed,
            account: state.handshake.username.clone(),
            .. Default::default()
        })])
    }
}

impl Handler<ConnectionState> for SAuthResponse{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        if !self.success {
            panic!("Unsuccessful login, aborting")
        }
        state.auth_state = AuthState::Authenticated;
        Some(vec![
            Box::new(CReadyForAccountDataTimes{}),
            Box::new(CEnumCharacters{}),
        ])
    }
}

impl Handler<ConnectionState> for SEnumCharactersResponse{
    fn execute(&self, _state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {

        println!("Trying to login with guid {}", hex::encode(&self.guid.to_be_bytes()));

        Some(vec![
            Box::new(CPlayerLogin{guid: self.guid}),
        ])
    }
}

impl Handler<ConnectionState> for SUpdateObject{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        state.world_state.record_observed_guids(self.guids.clone());
        // None
        use std::{thread, time};
        thread::sleep(time::Duration::from_millis(300));

        match state.world_state.try_start_auction_scan(){
            None => None,
            Some(guid) => {
                // println!("XXXXXXXXXXXXXXXXXXXXXXXXX STARTING AH SCAN WITH {} XXXXXXXXXXXXXXXXXXXXXXXXX", hex::encode(&guid));
                Some(vec![
                    // Box::new(CInspect{}),
                    Box::new(CSetSelection{guid: guid.clone()}),
                    Box::new(CAuctionHello{guid: guid.clone()}),
                ])
            }
        }
    }
}
impl Handler<ConnectionState> for SAuctionHello{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        state.world_state.current_scan_offset = 0;
        use std::{thread, time};

        thread::sleep(time::Duration::from_millis(300));

        // println!("++++++++++++++++++ Received SAuctionHello, starting prelude++++++++++++++++++++++++");
        Some(vec![
            Box::new(CListBidderItems{guid: state.world_state.current_scan_npc.clone().expect("got hello without starting scan?")}),
        ])        
    }
}

impl Handler<ConnectionState> for SAuctionListResult{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        use std::{thread, time};
        println!("-------------------------- Received SAuctionListResult  --------------------------");

        let auctions_count = self.auctions.len();
        if auctions_count >1 {
            state.world_state.current_scan_offset += auctions_count as u32;
            // this is extremely bad
            thread::sleep(time::Duration::from_millis(100));
            Some(vec![
                Box::new(CAuctionListItems{
                    guid: state.world_state.current_scan_npc.clone().expect("got hello without starting scan?"),
                    start_list_from: state.world_state.current_scan_offset
                }),
            ])
        }
        else{
            println!("Found no further auctions");
            None
        }
        
    }
}

impl Handler<ConnectionState> for STimesyncRequest{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {  
        
        state.world_state.timesync_ctr += 1;
        
        let counter = self.counter;

        use std::time::{SystemTime, UNIX_EPOCH};
        let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let unix_ms_time = unix_time.as_secs() * 1000 + unix_time.subsec_nanos() as u64 / 1_000_000;

        let client_ticks = ((unix_ms_time-state.world_state.server_start_time)/50)as u32;
        // println!("Answering STimesyncRequest with ticks {}", client_ticks);
        Some(vec![
            Box::new(CTimesyncResponse{
                counter,
                client_ticks
            }),
        ])
    }
}


impl Handler<ConnectionState> for SAuctionBidderListResult{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        use std::{thread, time};
        // println!("SAuctionBidderListResult prelude");
        thread::sleep(time::Duration::from_millis(100));
        Some(vec![
            Box::new(CListOwnerItems{guid: state.world_state.current_scan_npc.clone().expect("got hello without starting scan?")}),
            // Box::new(CAuctionMagicPacket{}),
            // Box::new(CInspect{})
        ])      
        
    }
}

impl Handler<ConnectionState> for SAuctionOwnerListResult{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        use std::{thread, time};
        // println!("SAuctionOwnerListResult prelude");
        // println!("++++++++++++++++++ Received SAuctionOwnerListResult, starting scan ++++++++++++++++++++++++");
        thread::sleep(time::Duration::from_millis(300));
        Some(vec![
            Box::new(CAuctionListItems{
                guid: state.world_state.current_scan_npc.clone().expect("got hello without starting scan?"),
                start_list_from: state.world_state.current_scan_offset
            }),
        ])  
    }
}

impl Handler<ConnectionState> for SAccountDataTimes{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>> {
        // println!("SAccountDataTimes");
        state.world_state.server_start_time = self.server_start_time;
        None
    }
}
