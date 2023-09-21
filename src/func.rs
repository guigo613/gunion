use std::{
    io::{
        Read,
        Write
    },
    net::{
        TcpStream,
        SocketAddrV4
    },
    error::Error,
    thread,
    sync::Arc,
};
use openssl::ssl::{
    SslMethod,
    // SslConnector,
    SslAcceptor,
    SslFiletype,
    SslVerifyMode
};
use super::ReadWrite;

type ReadToWrite = (Arc<dyn ReadWrite>, Arc<dyn ReadWrite>);

static mut ACCEPTOR: Option<SslAcceptor> = None;
// static mut CONNECTOR: Option<SslConnector> = None;

pub fn treat_con_default(listen: TcpStream, to: SocketAddrV4) -> Result<(), Box<dyn Error>> {
    let stream = TcpStream::connect(to)?;
    let stream_c = stream.try_clone()?;
    let listen_c = listen.try_clone()?;
    
    for (mut s, mut l) in [(listen, stream), (stream_c, listen_c)] {
        thread::spawn(move || {
            let mut buf = [0u8; 2048];
            
            while let Ok(size) = s.read(&mut buf) {
                if let 0 = size {
                    break;
                }
    
                if let Err(err) = l.write(&buf[..size]) {
                    dbg!(err);
                    break;
                }
            }

            ReadWrite::shutdown(&mut l);
        });
    }

    Ok(())
}

pub fn treat_con_https(listen: TcpStream, to: SocketAddrV4) -> Result<(), Box<dyn Error>> {
    let listen = get_acceptor().accept(listen.try_clone()?)?;
    let mut buf = [0u8; 2048];
    let stream_t = Arc::new(TcpStream::connect(to)?);
    let stream_c = Arc::clone(&stream_t);
    let listen_t = Arc::new(listen);
    let listen_c = Arc::clone(&listen_t);
    
    let pairs: [ReadToWrite; 2] = [(listen_t, stream_t), (stream_c, listen_c)];

    for (s, l) in pairs {
        thread::spawn(move || {
            unsafe {
                let s: &mut dyn ReadWrite = &mut *(s.as_ref() as *const dyn ReadWrite as *mut _);
                let l: &mut dyn ReadWrite = &mut *(l.as_ref() as *const dyn ReadWrite as *mut _);
    
                while let Ok(size) = s.read(&mut buf) {
                    if let 0 = size {
                        break;
                    }
        
                    if let Err(err) = l.write(&buf[..size]) {
                        dbg!(err);
                        break;
                    }
                }
                
                l.shutdown();
            }
        });
    }

    Ok(())
}

pub fn get_acceptor() -> &'static mut SslAcceptor {
    unsafe {
        ACCEPTOR.get_or_insert_with(new_acceptor)
    }
}

pub fn new_acceptor() -> SslAcceptor {
    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file(r"C:\conf\key.pem", SslFiletype::PEM).unwrap();
    acceptor.set_certificate_chain_file(r"C:\conf\cert.pem").unwrap();
    acceptor.set_verify_callback(SslVerifyMode::empty(), |_, _| true);
    acceptor.check_private_key().unwrap();

    acceptor.build()
}

// pub fn get_connector() -> &'static mut SslConnector {
//     unsafe {
//         CONNECTOR.get_or_insert_with(new_connector)
//     }
// }

// pub fn new_connector() -> SslConnector {
//     let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();

//     connector.set_verify_callback(SslVerifyMode::empty(), |_, _| true);
//     connector.build()
// }