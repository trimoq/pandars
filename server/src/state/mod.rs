use crate::packets;
use crate::crypto::{SessionCrypto, WardenCrypto};

pub mod world_session;
use world_session::WorldSessionState;

pub struct ConnectionState{
    pub handshake: Handshake,
    pub auth_state: AuthState,
    pub world_crypt: Option<SessionCrypto>,
    pub warden_crypt: Option<WardenCrypto>,
    pub world_state: WorldSessionState
}

pub struct Handshake{
    pub username: String,
    pub password: String,
    pub remote_parameters: Option<packets::auth::RemoteParameters>,
    pub session_key: Vec<u8>,
    pub realm: Option<String>
}

impl Handshake{
    pub fn new(username: String, password: String) -> Self {
        Handshake{
            username,
            password,
            remote_parameters: None,
            session_key: vec![],
            realm: None
        }
    }
}

#[derive(PartialEq)]
pub enum AuthState{
    Fresh,
    WaitingForChallenge,
    WaitingForProof,
    ReceivedSessionKey,
    ReadyForWorldServer,
    ConnectingToWorld,
    Authenticated
}