use crate::packets::Serializeable;

pub mod auth;
pub mod world_session;

pub trait Handler<T>{
    fn execute(&self, state: &mut T) -> Option<Vec<Box<dyn Serializeable>>>;
}