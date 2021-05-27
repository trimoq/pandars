use mio::event::Event;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Registry, Token};
use bytes::{BytesMut, Buf, BufMut};
use std::io::{self, Read, Write};


use slab::Slab;
use mio_timerfd::{ClockId,TimerFd};


use std::time::{Duration};

mod handlers;
mod state;
mod packets;
mod crypto;
use crate::handlers::Handler;
use crate::handlers::auth::AuthConnectionEvent;
use crate::packets::{Serializeable, MopParser, ConnectionType, ParseError};
use crate::state::{ConnectionState, Handshake, AuthState, world_session::WorldSessionState};



const TIMER: Token = Token(131072);


struct MopConnection{
    stream: TcpStream,
    token: Token,
    write_buffer: BytesMut,
    outgoing_messages: Vec<Box< dyn Serializeable>>,
    connected: bool,
    read_buffer: BytesMut,
    parser: MopParser,
    connection_state: ConnectionState
}

fn main() -> io::Result<()> {
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);
    
    let mut timer = TimerFd::new(ClockId::Monotonic).unwrap();
    timer.set_timeout_interval(&Duration::from_millis(1000)).unwrap();
    poll.registry().register(&mut timer, TIMER,Interest::READABLE).unwrap();
    

    let mut slab = Slab::with_capacity(7);

    for _i in 0..1{
        let addr = "192.168.121.170:3724".parse().unwrap();
        println!("\n");
        println!("##################################################################");
        println!("#############         starting   panda_rs         ################");
        println!("##################################################################");
        println!("# > Don't write Bots that ruin it for others !                   #");
        println!("##################################################################");

        println!("Starting Panda_rs for {:?}", addr);

        let mut connection = TcpStream::connect(addr)?;

        let entry = slab.vacant_entry();
        let key = entry.key();
        let token = Token(key);

        poll.registry().register(&mut connection, token, Interest::READABLE | Interest::WRITABLE)?;

        let mop = MopConnection{
            stream: connection,
            token,
            write_buffer: BytesMut::with_capacity(1024),
            outgoing_messages: Vec::new(),
            connected: false,
            read_buffer: BytesMut::with_capacity(10),
            parser: MopParser::new(ConnectionType::AuthServer),
            connection_state: ConnectionState{
                handshake: Handshake::new("BOT".to_string().to_uppercase(),"BOT".to_string().to_uppercase()),
                auth_state: AuthState::Fresh,
                world_crypt: None,
                warden_crypt: None,
                world_state: WorldSessionState::new()
            }
        };
        entry.insert(mop);
    }
    

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {            
            match event.token() {

                TIMER => {
                    slab
                        .iter_mut()
                        .filter(|(_id,mop)| mop.connection_state.auth_state == AuthState::ReadyForWorldServer)
                        .for_each(|(_id,mop)|{
                            let addr = mop.connection_state.handshake.realm.clone();

                            if let Some(addr) = addr{
                                match addr.parse(){
                                    Ok(addr) => {
                                        poll.registry().deregister(&mut mop.stream).unwrap();
                                        println!("Connecting to {:?}", addr);
                                        let mut connection = TcpStream::connect(addr).expect("Could not open new connection");
                                        // println!("Connected");
                                        poll.registry()
                                            .register(&mut connection, mop.token.clone(), Interest::READABLE | Interest::WRITABLE)
                                            .expect("Could not open new connection");

                                        // Overwrite the old connection, that should drop and close it
                                        mop.stream = connection;
                                        mop.parser = MopParser::new(ConnectionType::WorldServer);
                                        mop.connection_state.auth_state = AuthState::ConnectingToWorld;
                                        mop.read_buffer.clear();

                                    },
                                    Err(e) => {
                                        println!("Could not connect to real: {}",e)
                                    }
                                }
                            }

                        });
                    // println!("Timer ticked, ticks: {}",timer.read().unwrap());
                }
                // matches all other tokens
                token => {
                    if let Some( mut mop) = slab.get_mut(token.0){
                        handle_connection_event(poll.registry(), &mut mop, event)?;
                    }
                    else{
                        panic!("Token generated event that has no connection")
                    }
                },
            }
        }
    }
}
#[allow(dead_code)]
#[derive(Debug)]
enum WriteBufferResult{
    WriteComplete,
    IncompleteWrite,
    WouldBlock,
    Error(std::io::Error)
}

fn send_buffer(bytes: &mut BytesMut, stream: &mut TcpStream) -> WriteBufferResult{
    let remaining = bytes.len();
    match stream.write(&bytes) {
        Ok(n) if n < remaining => {
            // println!("Incomplete write: {}", n);
            bytes.advance(n);
            WriteBufferResult::IncompleteWrite
        },
        Ok(_n) => {
            // println!("Buffer written completely, wrote {} bytes", n);
            WriteBufferResult::WriteComplete
        },
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            // println!("would block");
            WriteBufferResult::WouldBlock
        }
        Err(err) => {
            panic!("error: {}",err);
        }
    }   
}

fn handle_connection_event(
    registry: &Registry,
    mop: &mut MopConnection,
    event: &Event,
) -> io::Result<bool> {
    if event.is_writable() {
        // println!("writeable");

        if !mop.connected {
            mop.connected = true;

            if let Some(messages) =  AuthConnectionEvent::new().execute(&mut mop.connection_state){
                for message in messages{
                    mop.outgoing_messages.push(message);                    
                }
            }          
        }

        let mut still_sendable = true; 
        if !mop.write_buffer.is_empty() {
            // println!("OBEN Sending remaining bytes from last run");
            match send_buffer(&mut mop.write_buffer, &mut mop.stream){
                WriteBufferResult::WriteComplete => {            
                    mop.write_buffer.clear();
                },
                WriteBufferResult::IncompleteWrite => {
                    // println!("Ok,incomplete write");
                    still_sendable = false;
                },
                WriteBufferResult::WouldBlock => {
                    // println!("would block");
                    still_sendable = false;
                },
                WriteBufferResult::Error(_e) => {
                    // println!("Err, b: {:?}", e);
                    still_sendable = false;

                }
            }            
        }

        /* 
        Only write to the buffer, if there is still send capacity
        This has te following implications:
          - The buffer will be empty at this point
          - The buffer will be empty before new stuff is written to it
          - The above call may call write with a tiny buffer, even if there is more to be sent.
            This may decrease performance but ensures that the send buffer will only be as large as the sum of the 
            lengths of all messages produced by a single run of the state machines
        */
        if still_sendable{

            // We write all queued messages, if the buffer is not large enough, well, bad luck, it will resize itself
            for message in &mop.outgoing_messages{
                let mut buffer = BytesMut::with_capacity(1024);
                message.write(&mut buffer);
                if mop.connection_state.auth_state == AuthState::Authenticated {
                    if let Some(crypto) = &mut mop.connection_state.world_crypt{
                        let mut header_bytes = vec![0;4];
                        buffer.copy_to_slice(&mut header_bytes);
                        // println!("Sending packet, plain header is {}", hex::encode(&header_bytes));
                        let mut encrypted_header =  vec![0;4];
                        crypto.encrypt_header(&header_bytes,&mut encrypted_header);
                        // println!("Sending packet, enc header is {}", hex::encode(&encrypted_header));
                        mop.write_buffer.put(&encrypted_header[..]);
                        mop.write_buffer.put(buffer);
                    }
                    else { unreachable!() }
                }
                else{
                    mop.write_buffer.put(buffer);
                }
            }     
            // clear all outgoing messages, so they wont be serialized into the write buffer again
            mop.outgoing_messages.clear();

            if !mop.write_buffer.is_empty(){
                // println!("UNTEN Sending remaining bytes from this run");
                match send_buffer(&mut mop.write_buffer, &mut mop.stream){
                    WriteBufferResult::WriteComplete => {
                        // Do not send the buffer againmw
                        mop.write_buffer.clear();
                        // println!("Ok,complete write");
                    },
                    WriteBufferResult::IncompleteWrite => {
                        // println!("Ok,incomplete write");
                    },
                    WriteBufferResult::WouldBlock => {
                        // println!("would block");
                    },
                    WriteBufferResult::Error(e) => {
                        println!("Err, b: {:?}", e);
                    }
                }   
            }         
        }

    }

    if event.is_readable() {
        // println!("readable");

        if mop.connection_state.auth_state == AuthState::ReadyForWorldServer{
            return Ok(false);
        }

        // let mut bytes_read = 0;
        let mut received_data = vec![0; 4096];  // this should not be allocated over and over again
        loop {
            match mop.stream.read(&mut received_data) {
                Ok(0) =>  panic!("Connection closed by Remote "),
                Ok(n) => {
                    // bytes_read += n;
                    // println!("read: {} bytes: {}", &n, hex::encode(&&received_data[..bytes_read]));
                    if n == received_data.len() {
                        // println!("Resized received data, read {} bytes",n);
                        mop.read_buffer.put(&received_data[..]);
                        received_data = vec![0; n + 4096];
                    }
                    else{
                        // the buffer was not filled, the next read call will not provide new data
                        // println!("Read buffer not full, read {} bytes",n);
                        mop.read_buffer.put(&received_data[..n]);
                    }
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    // println!("Would block reading");
                    break
                },
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => panic!("IO ERROR ")
            }
        }
//TODO incomplete reads
//         let mut bm = BytesMut::from(&received_data[..bytes_read]);
        loop{
            // println!("########### Begin packet loop ########## {} bytes available",&mop.read_buffer.len());
            if mop.connection_state.auth_state == AuthState::ReadyForWorldServer{
                mop.read_buffer.clear();
                return Ok(false);
            }

            match mop.parser.parse(&mut mop.read_buffer, &mut mop.connection_state){
                Ok(packet) => {

                    if let Some(messages) =  packet.execute(&mut mop.connection_state){
                        for message in messages{
                            mop.outgoing_messages.push(message);
                        }
                        let _ = registry.reregister(&mut mop.stream, event.token(), Interest::WRITABLE|Interest::READABLE);
                    }
                },
                Err(ParseError::NotEnoughData) => {
                    // println!("Not Enough Data, leaving {} bytes for next iteration",&mop.read_buffer.len());
                    // in this case we need to save the whole buffer contents until the next read call
                    break;
                },
                Err(ParseError::Unimplemented) => {
                    // println!("Skipping unimplemented packet");
                },
                _ => {println!("Fatality!")}
            }
        }
    }
    Ok(false)
}