
use crate::state::{ConnectionState, AuthState};
use crate::packets::Serializeable;
use crate::packets::auth::{CAuthLogonChallenge, SAuthLogonChallenge, CAuthLogonProof, SAuthLogonProof, SRealmList, CRealmList};
use crate::handlers::Handler;
use crate::crypto::SRP;
use num::BigInt;

pub struct AuthConnectionEvent{}
impl AuthConnectionEvent{
    pub fn new()->Self{Self{}}
}

impl Handler<ConnectionState> for AuthConnectionEvent{
    fn execute(&self, state: &mut ConnectionState) -> Option<Vec<Box<dyn Serializeable>>>{
        // println!("executing AuthConnectionEvent");
        let mut response_messages:Vec<Box<dyn Serializeable>> = Vec::new();
        let username = state.handshake.username.clone().to_uppercase();
        let alc = Box::new(CAuthLogonChallenge::new(&username.into_bytes()));
        response_messages.push(alc);
        state.auth_state = AuthState::WaitingForChallenge;
        Some(response_messages)
    }
}


impl Handler<ConnectionState> for SAuthLogonChallenge{
    fn execute(&self, state: &mut ConnectionState)-> Option<Vec<Box<dyn Serializeable>>> {
        // println!("executing SAuthLogonChallenge");
        state.handshake.remote_parameters = Some(self.remote_parameters.clone());
        // println!("ALC_Params: {:?}",self.remote_parameters);
        let srp = SRP::new(&self.remote_parameters,state.handshake.username.clone(), state.handshake.password.clone());
        let a = BigInt::parse_bytes(
            b"00000000000000000000000000861565895658c4b0118940b7245c2f264ccc72",
            16,
        ).unwrap();
        let k = BigInt::parse_bytes(b"03", 16).unwrap();
        let (session_key,proof) = srp.compute_challenge(a,k);
        state.handshake.session_key = session_key;
        state.auth_state = AuthState::WaitingForProof;
        Some(vec![Box::new(CAuthLogonProof::new(proof))])
    }
}

impl Handler<ConnectionState> for SAuthLogonProof{
    fn execute(&self, state: &mut ConnectionState)-> Option<Vec<Box<dyn Serializeable>>> {
        // println!("executing SAuthLogonProof");
        // we should validate m2 here but i dont care

        if state.auth_state != AuthState::WaitingForProof{
            println!("Received SAuthLogonProof in wrong state, blocking");
            return None;
        }

        // the next step is to contact the world server
        state.auth_state = AuthState::ReceivedSessionKey;
        Some(vec![Box::new(CRealmList{})])
    }
}

impl Handler<ConnectionState> for SRealmList{
    fn execute(&self, state: &mut ConnectionState)-> Option<Vec<Box<dyn Serializeable>>> {
        // println!("executing SRealmList");
        for realm in &self.realms{
            println!("Realm {} has IP {} and {} chars", realm.name, realm.addr, realm.char_count)
        }

        if state.auth_state != AuthState::ReceivedSessionKey{
            println!("Received SRealmList in wrong state, blocking");
            return None;
        }

        match &self.realms.iter().filter(|r|r.char_count>=1 && r.char_count <=2).next(){
            Some(realm) => {
                println!("Connecting to {} at {}", realm.name, realm.addr);
                state.handshake.realm = Some(realm.addr.clone());
                state.auth_state = AuthState::ReadyForWorldServer;
            },
            _ => println!("No matching realm found")

        };
        None
    }
}