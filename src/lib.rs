mod func;

use func::*;

use std::{
    io::{
        Read,
        Write
    },
    net::{
        TcpStream,
        TcpListener,
        SocketAddrV4,
        Ipv4Addr
    },
    error::Error,
    time::Duration,
    thread,
    mem
};
use openssl::ssl::SslStream;

pub type CallbackUnion = Box<dyn Fn(TcpStream, SocketAddrV4) -> Result<(), Box<dyn Error>> + Send>;

pub const IP: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

pub trait ReadWrite: Read + Write + Send + Sync {
    fn shutdown(&mut self);
}

impl ReadWrite for TcpStream {
    fn shutdown(&mut self) {
        let _ = TcpStream::shutdown(self, std::net::Shutdown::Both);
    }
}

impl ReadWrite for SslStream<TcpStream> {
    fn shutdown(&mut self) {
        let _ = SslStream::shutdown(self);
    }
}

pub struct Union(Vec<Direction>);

impl Union {
    pub fn new(direction: Vec<Direction>) -> Self {
        Union(direction)
    }

    pub fn start(&self) {
        for dir in &self.0 {
            // println!("Starting {:?} Model {:?} - {}:{}", dir.address, dir.model, dir.port, dir.to_port.unwrap_or(dir.port));

            let func = dir.model.get();

            Self::_start(func, SocketAddrV4::new(dir.address, dir.port), dir.to_port);
        }
    }

    fn _start(func: CallbackUnion, mut to: SocketAddrV4, port: Option<u16>) {
        let port_listen = to.port();

        if let Some(p) = port {
            to.set_port(p);
        }

        thread::spawn(move || loop {
            if let Ok(tcp) = TcpListener::bind(SocketAddrV4::new(IP, port_listen)) {
                let mut incoming = tcp.incoming();

                while let Some(Ok(listen)) = incoming.next() {
                    if let Err(err) = func(listen, to) {
                        dbg!(err);
                    }
                }
            }

            println!("Reseting connection: {to}");

            thread::sleep(Duration::from_secs(5));
        });
    }
}

impl Default for Union {
    fn default() -> Self {
        Self(Default::default())
    }
}

pub struct Direction {
    model: Box<dyn GetCallbackUnion>,
    address: Ipv4Addr,
    port: u16,
    to_port: Option<u16>
}

impl Direction {
    pub fn new<C: GetCallbackUnion + 'static>(model: C, address: Ipv4Addr, port: u16, to_port: Option<u16>) -> Self {
        Self {
            model: Box::new(model),
            address,
            port,
            to_port
        }
    }
}

pub trait GetCallbackUnion {
    fn get(&self) -> CallbackUnion;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Model {
    Direct = 1,
    Increment
}

impl From<u8> for Model {
    fn from(v: u8) -> Self {
        unsafe {
            mem::transmute(v)
        }
    }
}

impl GetCallbackUnion for Model {
    fn get(&self) -> CallbackUnion {
        Box::new(match self {
            Model::Direct => treat_con_default,
            Model::Increment => treat_con_https
        })
    }
}

impl<F> GetCallbackUnion for F
    where F: Fn(TcpStream, SocketAddrV4) -> Result<(), Box<dyn Error>> + Send + Clone + 'static
{
    fn get(&self) -> CallbackUnion {
        Box::new(self.clone())
    }
}