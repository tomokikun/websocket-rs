// WebSocket serverの実装
//
// 以下の記事の写経:
// https://zenn.dev/ohke/articles/8d6b690c144a0e
//
// 詳細はこちらを参照:
// https://www.rfc-editor.org/rfc/rfc6455
//
// Protocol Overview:
//
//    The protocol has two parts: a handshake and the data transfer.

//    The handshake from the client looks as follows:

//         GET /chat HTTP/1.1
//         Host: server.example.com
//         Upgrade: websocket
//         Connection: Upgrade
//         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
//         Origin: http://example.com
//         Sec-WebSocket-Protocol: chat, superchat
//         Sec-WebSocket-Version: 13

//    The handshake from the server looks as follows:

//         HTTP/1.1 101 Switching Protocols
//         Upgrade: websocket
//         Connection: Upgrade
//         Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
//         Sec-WebSocket-Protocol: chat

//    The leading line from the client follows the Request-Line format.
//    The leading line from the server follows the Status-Line format.  The
//    Request-Line and Status-Line productions are defined in [RFC2616].

//    An unordered set of header fields comes after the leading line in
//    both cases.  The meaning of these header fields is specified in
//    Section 4 of this document.  Additional header fields may also be
//    present, such as cookies [RFC6265].  The format and parsing of
//    headers is as defined in [RFC2616].

//    Once the client and server have both sent their handshakes, and if
//    the handshake was successful, then the data transfer part starts.
//    This is a two-way communication channel where each side can,
//    independently from the other, send data at will.

//    After a successful handshake, clients and servers transfer data back
//    and forth in conceptual units referred to in this specification as
//    "messages".  On the wire, a message is composed of one or more
//    frames.  The WebSocket message does not necessarily correspond to a
//    particular network layer framing, as a fragmented message may be
//    coalesced or split by an intermediary.
//
//    A frame has an associated type.  Each frame belonging to the same
//    message contains the same type of data.  Broadly speaking, there are
//    types for textual data (which is interpreted as UTF-8 [RFC3629]
//    text), binary data (whose interpretation is left up to the
//    application), and control frames (which are not intended to carry
//    data for the application but instead for protocol-level signaling,
//    such as to signal that the connection should be closed).  This
//    version of the protocol defines six frame types and leaves ten
//    reserved for future use.

use base64::{engine::general_purpose, Engine as _};
use sha1::{Digest, Sha1};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread::sleep,
    time::Duration,
};

#[derive(Clone, Debug, PartialEq)]
pub enum Opcode {
    Continuation, // = 0x0,
    Text,         // = 0x1,
    Binary,       // = 0x2,
    Close,        // = 0x8,
    Ping,         // = 0x9,
    Pong,         // = 0xA,
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub fin: bool,
    pub rsv1: bool,
    pub rsv2: bool,
    pub rsv3: bool,
    pub opcode: Opcode,
    pub mask: bool,
    /// included extendted payload length
    pub payload_len: usize,
    pub masking_key: Option<[u8; 4]>,
    /// decoded with masking_key
    pub payload: Vec<u8>,
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        match byte & 0x0F {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            _ => panic!("Invalid opcode: {}", byte),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> Self {
        match opcode {
            Opcode::Continuation => 0x0,
            Opcode::Text => 0x1,
            Opcode::Binary => 0x2,
            Opcode::Close => 0x8,
            Opcode::Ping => 0x9,
            Opcode::Pong => 0xA,
        }
    }
}

impl Frame {
    pub fn new(opcode: Opcode, payload: Option<Vec<u8>>) -> Self {
        let (payload_len, payload) = match payload {
            Some(payload) => (payload.len(), payload),
            None => (0, vec![]),
        };

        Self {
            fin: true, // Fragmentation is not supported, so always true
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            mask: false,
            payload_len,
            masking_key: None,
            payload,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.push(
            (self.fin as u8) << 7
                | (self.rsv1 as u8) << 6
                | (self.rsv2 as u8) << 5
                | (self.rsv3 as u8) << 4
                | u8::from(self.opcode),
        );

        if self.payload_len < 126 {
            buffer.push((self.mask as u8) << 7 | self.payload_len as u8);
        } else if self.payload_len < 65536 {
            buffer.push((self.mask as u8) << 7 | 126);
            buffer.extend_from_slice(&(self.payload_len as u16).to_be_bytes());
        } else {
            buffer.push((self.mask as u8) << 7 | 127);
            buffer.extend_from_slice(&(self.payload_len as u64).to_be_bytes());
        }

        if self.mask {
            buffer.extend(self.masking_key.unwrap().clone());
        }

        for (i, b) in self.payload.iter().enumerate() {
            buffer.push(if self.mask {
                b ^ self.masking_key.unwrap()[i % 4]
            } else {
                *b
            });
        }

        return buffer;
    }
}

impl From<&[u8]> for Frame {
    fn from(buffer: &[u8]) -> Self {
        let fin = buffer[0] & 0b1000_0000 != 0; // 0x80
        let rsv1 = buffer[0] & 0b0100_0000 != 0; // 0x40
        let rsv2 = buffer[0] & 0b0010_0000 != 0; // 0x20
        let rsv3 = buffer[0] & 0b0001_0000 != 0; // 0x10
        let opcode = Opcode::from(buffer[0]);

        let mask = buffer[1] & 0b1000_0000 != 0;

        let (payload_len, mut i) = match buffer[1] & 0b0111_1111 {
            126 => (u16::from_be_bytes([buffer[2], buffer[3]]) as usize, 4),
            127 => {
                let mut payload_len = [0; 8];
                payload_len.copy_from_slice(&buffer[2..10]);
                (usize::from_be_bytes(payload_len), 10)
            }
            n => (n as usize, 2),
        };

        let masking_key = if mask {
            let mut masking_key = [0; 4];
            masking_key.copy_from_slice(&buffer[i..i + 4]);
            i += 4;
            Some(masking_key)
        } else {
            None
        };

        let payload = if mask {
            buffer[i..i + payload_len]
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ masking_key.unwrap()[i % 4])
                .collect::<Vec<u8>>()
        } else {
            buffer[i..i + payload_len].to_vec()
        };

        Self {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            mask,
            payload_len,
            masking_key,
            payload,
        }
    }
}

pub fn echo(payload: &[u8]) -> Vec<u8> {
    // payloadにechoしたことを示す文字列を付与して返す
    let mut payload = payload.to_vec();
    payload.extend_from_slice(b" (echoed)");
    payload
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:7778").unwrap();

    let mut buffer = [0; 4096];

    // TCPの待ち受け
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut is_websocket = false;

        loop {
            // print!("buffer: {:?}", buffer);

            if let Err(_) = stream.read(&mut buffer) {
                break;
            }

            if is_websocket {
                // WebSocketの処理
                let frame = Frame::from(&buffer[..]);
                // println!("frame: {:?}", frame);
                if frame.opcode == Opcode::Text {
                    println!("Text");
                    let payload = echo(frame.payload.as_slice());
                    let response = Frame::new(Opcode::Text, Some(payload));

                    stream.write(&response.clone().to_bytes()).unwrap();
                    stream.flush().unwrap();

                    sleep(Duration::from_secs(3));

                    stream.write(&response.clone().to_bytes()).unwrap();
                    stream.flush().unwrap();
                } else if frame.opcode == Opcode::Close {
                    println!("Close");
                    let response = Frame::new(Opcode::Close, None);
                    stream.write(&response.to_bytes()).unwrap();
                    stream.flush().unwrap();
                    break;
                } else {
                    todo!("impl of opcode: {:?}", frame.opcode)
                }
            } else {
                // HTTPの処理
                //
                // 以下のようなリクエストが来る:
                // GET ws://127.0.0.1:7778/ HTTP/1.1
                // Host: 127.0.0.1:7778
                // Connection: Upgrade
                // Upgrade: websocket
                // Sec-WebSocket-Version: 13
                // Sec-WebSocket-Key: 9Kl3Zz3tA0ibMWQwyn/9kQ==
                // Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits
                //
                // 以下のようなレスポンスを返す:
                // HTTP/1.1 101 OK
                // Upgrade: websocket
                // Connection: upgrade
                // Sec-WebSocket-Accept: EK2cqLXRG/oxQwrUdEVXGrPDBuA=

                let mut method = None;
                let mut upgrade = None;
                let mut connection = None;
                let mut sec_websocket_version = None;
                let mut sec_websocket_key = None;

                // HTTPのヘッダーをパース
                let request_text = String::from_utf8_lossy(&buffer[..]);
                for (i, line) in request_text.lines().enumerate() {
                    if i == 0 {
                        let values = line.split(" ").map(|s| s.trim()).collect::<Vec<&str>>();
                        method = Some(values[0]);
                        continue;
                    }

                    if line == "" {
                        break;
                    }

                    let values = line.split(":").map(|s| s.trim()).collect::<Vec<&str>>();
                    let key = values[0].to_ascii_lowercase();
                    let value = values[1];

                    if key == "upgrade" {
                        upgrade = Some(value);
                    }

                    if key == "connection" {
                        connection = Some(value);
                    }

                    if key == "sec-websocket-version" {
                        sec_websocket_version = Some(value);
                    }

                    if key == "sec-websocket-key" {
                        sec_websocket_key = Some(value);
                    }
                }

                // TODO: validation of request
                println!("method: {:?}", method);
                println!("upgrade: {:?}", upgrade);
                println!("connection: {:?}", connection);
                println!("sec_websocket_version: {:?}", sec_websocket_version);
                println!("sec_websocket_key: {:?}", sec_websocket_key);

                let rfc_defined_uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                let plain_text = format!("{}{}", sec_websocket_key.unwrap(), rfc_defined_uuid);

                let mut hasher = Sha1::new();
                hasher.update(plain_text);
                let sec_websocket_accept = general_purpose::STANDARD.encode(hasher.finalize());

                let response = format!(
                    "HTTP/1.1 101 OK\r\n\
                    Upgrade: websocket\r\n\
                    Connection: Upgrade\r\n\
                    Sec-WebSocket-Accept: {}\r\n\
                    \r\n",
                    sec_websocket_accept
                );

                stream.write(response.as_bytes()).unwrap();
                stream.flush().unwrap();
                is_websocket = true;
            }
        }
    }

    Ok(())
}
