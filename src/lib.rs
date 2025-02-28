use anyhow::{anyhow, Context, Result};
use std::{
    io::{BufReader, BufWriter, Read, Write},
    net::{IpAddr, TcpStream},
    result,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub struct Packet {
    pub buffer: Vec<u8>,
    pub cursor: usize,
    protocol_id: Option<u8>,
}

impl Packet {
    pub fn from_bytes(bytes: &[u8]) -> Packet {
        Packet {
            buffer: bytes.to_vec(),
            cursor: 0,
            protocol_id: None,
        }
    }

    pub fn with_size(size: usize) -> Packet {
        Packet {
            buffer: vec![0u8; size],
            cursor: 0,
            protocol_id: None,
        }
    }

    pub fn new() -> Packet {
        Packet {
            buffer: Vec::new(),
            cursor: 0,
            protocol_id: None,
        }
    }

    fn write_string(&mut self, value: &str) -> Result<()> {
        self.write_varint(value.len() as i32)?;
        self.buffer.extend_from_slice(value.as_bytes());

        Ok(())
    }

    fn read_string(&mut self) -> Result<String> {
        let length = self.read_varint()? as usize;
        let value = String::from_utf8(self.buffer[self.cursor..self.cursor + length].to_vec())?;
        self.cursor += length;

        Ok(value)
    }

    fn write_varint(&mut self, mut value: i32) -> Result<()> {
        let mut iterations = 1;
        loop {
            if iterations > 5 {
                return Err(anyhow!("Varint exceeds maximum allowed size"));
            }

            if (value & !VARINT_SEGMENT_BITS) == 0 {
                self.buffer.push(value as u8);
                return Ok(());
            }

            self.buffer
                .push((value & VARINT_SEGMENT_BITS | VARINT_CONTINUE_BIT) as u8);

            value = ((value as u32) >> 7) as i32;
            iterations += 1;
        }
    }

    fn read_varint(&mut self) -> Result<i32> {
        let mut value = 0i32;
        let mut bit_position = 0i32;

        loop {
            if self.cursor >= self.buffer.len() {
                return Err(anyhow!("Buffer is too short to read a valid varint"));
            }

            let current_byte = self.buffer[self.cursor];
            self.cursor += 1;

            value |= (current_byte as i32 & VARINT_SEGMENT_BITS) << bit_position;

            if (current_byte as i32 & VARINT_CONTINUE_BIT) == 0 {
                break;
            }

            bit_position += 7;
            if bit_position >= 32 {
                return Err(anyhow!("Varint too large"));
            }
        }

        Ok(value)
    }

    fn read_protocol_id(&mut self) -> Result<u8> {
        if self.cursor >= self.buffer.len() {
            return Err(anyhow!("Buffer is too short to read a valid varint"));
        }
        self.protocol_id = Some(self.buffer[self.cursor]);
        self.cursor += 1;

        self.protocol_id
            .map(|id| Ok(id))
            .unwrap_or_else(|| Err(anyhow!("Protocol ID is somehow missing")))
    }

    pub fn get_protocol_id(&self) -> Option<u8> {
        self.protocol_id
    }

    fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.extend_from_slice(slice);
    }

    fn read_slice(&mut self, amount: usize) -> Result<&[u8]> {
        if self.cursor + amount > self.buffer.len() - 1 {
            return Err(anyhow!("Could not read slice past buffer."));
        }
        let result = &self.buffer[self.cursor..self.cursor + amount];
        self.cursor += amount;
        Ok(result)
    }
}

pub struct Client {
    handshake_performed: bool,
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    hostname: String,
    port: u16,
}

const VARINT_SEGMENT_BITS: i32 = 0x7F;
const VARINT_CONTINUE_BIT: i32 = 0x80;

impl Client {
    pub fn new(hostname: &str, port: u16) -> Result<Client> {
        let address = format!("{}:{}", hostname, port);

        let stream = TcpStream::connect(&address)
            .with_context(|| format!("Failed to connect to {}", address))?;

        Ok(Client {
            handshake_performed: false,
            reader: BufReader::new(stream.try_clone()?),
            writer: BufWriter::new(stream.try_clone()?),
            hostname: String::from(hostname),
            port,
        })
    }

    fn invalidate_handshake(&mut self) -> Result<()> {
        if self.handshake_performed {
            let address = format!("{}:{}", self.hostname, self.port);
            let stream = TcpStream::connect(&address)
                .with_context(|| format!("Failed to connect to {}", address))?;
            self.reader = BufReader::new(stream.try_clone()?);
            self.writer = BufWriter::new(stream.try_clone()?);
            self.handshake_performed = true
        }

        Ok(())
    }

    pub fn login(&mut self) -> Result<()> {
        self.invalidate_handshake()?;

        let mut packet = Packet::new();
        packet.write_varint(0x00)?; // protocol id
        packet.write_varint(759)?; // protocol version
        packet.write_string(&self.hostname)?; // hostname
        packet.write_slice(&self.port.to_be_bytes()); // port
        packet.write_varint(2)?;

        self.send_packet(&packet)?; // Send Handshake with login as next state
        self.handshake_performed = true;

        let mut packet = Packet::new();
        packet.write_varint(0x00)?; // Protocol ID
        packet.write_string("extremq")?; // Username
        packet.write_slice(&[0u8; 1]); // Has Sig Data

        self.send_packet(&packet)?; // Send login start

        let mut response = self.block_until_packet_id(0x02)?; // Get login completed
        println!("UUID: {:?}", response.read_slice(16)?); // Read UUID
        println!("Username: {:?}", response.read_string()?); // Read Username

        Ok(())
    }

    pub fn status(&mut self) -> Result<String> {
        self.invalidate_handshake()?;

        let mut packet = Packet::new();
        packet.write_varint(0x00)?; // protocol id
        packet.write_varint(759)?; // protocol version
        packet.write_string(&self.hostname)?; // hostname
        packet.write_slice(&self.port.to_be_bytes()); // port
        packet.write_varint(1)?;

        self.send_packet(&packet)?; // Send Handshake with login as next state
        self.handshake_performed = true;

        let mut packet = Packet::new();
        packet.write_varint(0x00)?; // Protocol ID

        self.send_packet(&packet)?; // Send status packet

        let mut packet = self.block_until_packet_id(0x00)?;
        Ok(packet.read_string()?)
    }

    pub fn send_chat_message(&mut self) -> Result<()> {
        let mut packet = Packet::new();
        packet.write_varint(0x04)?; // protocol id
        packet.write_string("salut baietii")?; // Message
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        packet.write_slice(&timestamp_ms.to_be_bytes()); // timestamp
        packet.write_slice(&[0u8; 8]); // salt
        packet.write_slice(&[0u8; 1]); // signature length
        packet.write_slice(&[0u8; 1]); // signed preview

        self.send_packet(&packet)?;

        Ok(())
    }

    pub fn send_packet(&mut self, packet: &Packet) -> Result<()> {
        let mut length = Packet::new();
        length.write_varint(packet.buffer.len() as i32)?;

        self.writer.write(&length.buffer)?;
        self.writer.write(&packet.buffer)?;
        self.writer.flush()?;

        println!("Sent: {:?} {:?}", length.buffer, packet.buffer);

        Ok(())
    }

    pub fn block_until_packet_id(&mut self, packet_id: u8) -> Result<Packet> {
        println!("waiting for {}", packet_id);
        loop {
            let packet = match self.read_packet()? {
                None => continue,
                Some(val) => val,
            };

            let id = match packet.get_protocol_id() {
                None => continue,
                Some(val) => val,
            };

            if id == packet_id {
                return Ok(packet);
            }
        }
    }

    pub fn read_packet(&mut self) -> Result<Option<Packet>> {
        let mut response = Packet::new();
        loop {
            let mut byte = [0u8];
            self.reader.read_exact(&mut byte)?;

            response.buffer.extend_from_slice(&byte);
            if response.buffer.len() > 5 {
                return Ok(None);
            }

            if byte[0] as i32 & VARINT_CONTINUE_BIT == 0 {
                break;
            }
        }
        let payload_length = response.read_varint()? as usize;
        response
            .buffer
            .resize(response.buffer.len() + payload_length, 0);

        self.reader
            .read_exact(&mut response.buffer[response.cursor..])?;
        response.read_protocol_id()?;

        Ok(Some(response))
    }
}
