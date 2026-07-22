use rustls::crypto::{CryptoProvider, aws_lc_rs};
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use rustls::server::Acceptor;
use rustls_platform_verifier::{BuilderVerifierExt};
use tokio::time::timeout;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;


enum Mode {
    TLS12,
    TLS13,
    QUIC
}


fn init_cyphers() {
    let kx_groups = vec![
        kx_group::MLKEM768,
        kx_group::SECP256R1,
        kx_group::SECP384R1,
    ];

    let provider = CryptoProvider {
        kx_groups,
        ..aws_lc_rs::default_provider()
    };
    _= provider.install_default();
}


fn handle_client_tcp(mut stream: TcpStream, done: Arc<Mutex<bool>>) {
    println!("New connection from: {}", stream.peer_addr().unwrap());

    let mut raw_handshake_bytes = Vec::new();
    let mut buffer = [0u8; 2048]; 

    match stream.read(&mut buffer) {
        Ok(0) => return, 
        Ok(bytes_read) => {
            raw_handshake_bytes.extend_from_slice(&buffer[..bytes_read]);
        }
        Err(e) => {
            eprintln!("Failed to read raw bytes: {}", e);
            return;
        }
    }

    // Chain our cloned bytes with the original live socket so rustls can still parse it
    let mut combined_reader = Cursor::new(raw_handshake_bytes.clone()).chain(stream);
    let mut acceptor = Acceptor::default();

    if let Err(e) = acceptor.read_tls(&mut combined_reader) {
        eprintln!("Rustls failed to read TLS bytes: {}", e);
        return;
    }

    // Validate ClientHello
    let mut file_name = format!("tls_client_hello.bin");
    match acceptor.accept() {
        Ok(Some(accepted)) => {
            let client_hello = accepted.client_hello();
            println!("Parsed ClientHello successfully.");
            if let Some(sni) = client_hello.server_name() {
                println!("SNI: {}", sni);
                file_name = format!("tls_{sni}.bin");
            }
        }
        Ok(None) => println!("Incomplete ClientHello frame."),
        Err(e) => eprintln!("Invalid ClientHello data: {}", e.0),
    }


    // Save the bytes to a binary file ---
    match File::create(&file_name) {
        Ok(mut file) => {
            if let Err(e) = file.write_all(&raw_handshake_bytes) {
                eprintln!("Failed to write to file: {}", e);
            } else {
                println!("\n---Successfully saved {} raw bytes to '{}'---", raw_handshake_bytes.len(), &file_name);
            }
        }
        Err(e) => eprintln!("Failed to create file: {}", e),
    }

    match done.lock() {
        Ok(mut done) => *done = true,
        _ => ()
    }
}


fn connect_tcp_socket(mode: &Mode, sni: String) -> bool {
    let mut stream = TcpStream::connect(format!("127.0.0.1:1111")).unwrap();

    let tls_ver = if let Mode::TLS12 = mode { &rustls::version::TLS12 } else { &rustls::version::TLS13 };

    let mut config = ClientConfig::builder_with_protocol_versions(&[tls_ver])
        .with_platform_verifier().unwrap()
        .with_no_client_auth();

    // bloat TLS 1.2 client hello
    if let Mode::TLS12 = mode {
        config.alpn_protocols = vec![
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];
        for _ in 0..40 {
            config.alpn_protocols.push(vec![0u8; 20]);
        }
    }

    let servername = if let Ok(val) = ServerName::try_from(sni.clone()) {
        val
    } else {
        println!("\n---ERROR: wrong SNI: {sni}---");
        return false;
    };

    let mut conn = ClientConnection::new(Arc::new(config), servername).unwrap();
    let mut stream = rustls::Stream::new(&mut conn, &mut stream);
    _ = stream.conn.complete_io(&mut stream.sock);

    return true;
}


async fn connect_udp_socket(sni: String) {
    let client_config = quinn::ClientConfig::try_with_platform_verifier().unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:9999".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let endpoint_fut = endpoint.connect("127.0.0.1:1111".parse().unwrap(), &sni).unwrap();

    _= timeout(Duration::from_secs(1), endpoint_fut).await;
}


fn open_tcp_socket(port: usize, done: Arc<Mutex<bool>>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
    println!("Server running on 127.0.0.1:{port}. Waiting for TLS connection...");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                    handle_client_tcp(stream, done.clone());
                    let done = done.lock().unwrap();
                    if *done {
                        return;
                    }
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
}

fn handle_client_udp(bytes_read: usize, src_addr: SocketAddr, buffer: &mut [u8; 4096], done: &Arc<Mutex<bool>>, sni: &String) {
                println!("Received UDP datagram from: {}", src_addr);
                
                let raw_packet = &buffer[..bytes_read];

                // if raw_packet.len() > 14 && raw_packet[4] == 0x01 {
                if raw_packet.len() > 14 { // do not check proto

                    // Save the exact raw UDP bytes to a binary file
                    let file_name = format!("quic_{sni}.bin");

                    println!("Saving UDP fake to file '{file_name}'");

                    match File::create(&file_name) {
                        Ok(mut file) => {
                            if let Err(e) = file.write_all(raw_packet) {
                                eprintln!("Failed to write to file: {}", e);
                            } else {
                                println!(
                                    "\n---Successfully saved {} raw UDP bytes to '{}'---\n",
                                    raw_packet.len(),
                                    file_name
                                );
                                let mut done = done.lock().unwrap();
                                *done = true;
                            }
                        }
                        Err(e) => eprintln!("Failed to create file: {}", e),
                    }
                } else {
                    println!("Received non-ClientHello packet.");
                    // debug
                    // println!("{}",raw_packet.into_iter().fold(String::new(), |acc, el| acc + " " + &format!("{:x}", el)));
                }
}

fn open_udp_socket(port: usize, done: Arc<Mutex<bool>>, sni: String) {
    let socket = UdpSocket::bind(format!("127.0.0.1:{port}")).unwrap();
    println!("Server running on 127.0.0.1:{port}. Waiting for QUIC connection...");
    let mut buffer = [0u8; 4096];

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((bytes_read, src_addr)) => {
                handle_client_udp(bytes_read, src_addr, &mut buffer, &done, &sni);
                let done = done.lock().unwrap();
                if *done {
                    return;
                }
            }
            Err(e) => {
                eprintln!("Failed to read UDP socket: {}", e);
            }
        }
    }
}


fn handle_input() -> (Mode, String) {
    let stdin = std::io::stdin();
    loop {
        // choose mode
        println!("Enter mode:\n1 - TLS 1.2\n2 - TLS 1.3\n3 - QUIC");
        let mut mode_num_buff = String::new();
        _= stdin.read_line(&mut mode_num_buff);

        let mode_num = mode_num_buff.trim().parse::<usize>();
        
        let mode = match mode_num {
            Ok(1) => Mode::TLS12,
            Ok(2) => Mode::TLS13,
            Ok(3) => Mode::QUIC,
            _ => {
                println!("Incorrect mode number, try again\n");
                continue;
            }
        };

        // choose SNI
        println!("\nEnter domain (default: www.google.com):");
        let mut sni_buff = String::new();
        _= std::io::stdin().read_line(&mut sni_buff);

        let sni = if sni_buff.trim().is_empty() {
            format!("www.google.com")
        } else {
            sni_buff.trim().to_owned()
        };

        println!();

        return (mode, sni);
    }
}

#[tokio::main]
async fn main() {
    init_cyphers();

    loop {
        let (mode, sni) = handle_input();
        let done = Arc::new(Mutex::new(false));
        let done_th = done.clone();

        match mode {
            Mode::TLS12 | Mode::TLS13 => {
                let th_tcp_socket = thread::spawn(move || open_tcp_socket(1111, done_th));
                let th_tcp_connect = thread::spawn(move || {
                    let res = connect_tcp_socket(&mode, sni);
                    if !res {
                        *done.lock().unwrap() = true;
                    }
                });

                _= th_tcp_socket.join();
                _= th_tcp_connect.join();
            },
            Mode::QUIC => {
                let sni_th = sni.clone();
                let th_udp_socket = thread::spawn(move || open_udp_socket(1111, done_th, sni_th));
                connect_udp_socket(sni).await;

                _= th_udp_socket.join();
            },
        }

        println!("\nRestart\n");
    }
}
