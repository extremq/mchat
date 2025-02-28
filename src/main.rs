use anyhow::{Context, Result};
use base64::prelude::*;
use colored::Colorize;
use image::GenericImageView;
use mchat::{Client, Packet};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio::{sync::mpsc, task, time::sleep};

#[derive(Serialize, Deserialize)]
struct Version {
    name: String,
    protocol: u32,
}

#[derive(Serialize, Deserialize)]
struct PlayerSample {
    name: String,
    id: String,
}

#[derive(Serialize, Deserialize)]
struct Players {
    max: u32,
    online: u32,
    sample: Option<Vec<PlayerSample>>,
}

#[derive(Serialize, Deserialize)]
struct Description {
    text: String,
}

#[derive(Serialize, Deserialize)]
struct MinecraftStatus {
    version: Version,
    players: Players,
    description: Description,
    favicon: Option<String>,
    enforcesSecureChat: Option<bool>,
}

fn main() -> Result<()> {
    let mut client = Client::new("localhost", 25565).with_context(|| "Failed to create client.")?;
    println!("{}", client.status()?);
    client.login()?;

    loop {
        let packet = client.block_until_packet_id(0x1E)?;
        let mut sender = Packet::from_bytes(&packet.buffer[packet.cursor - 1..]);
        sender.buffer[0] = 0x11;
        client.send_packet(&sender)?;
        client.send_chat_message()?;
    }
}

// let status: MinecraftStatus = serde_json::from_str(&client.status()).unwrap();

// let png = status.favicon.unwrap();
// let png = png.strip_prefix("data:image/png;base64,").unwrap();
// let raw = BASE64_STANDARD.decode(png).unwrap();
// let img = image::load_from_memory_with_format(&raw, image::ImageFormat::Png)
//     .unwrap()
//     .resize(16, 16, image::imageops::FilterType::Nearest);
// for pixel in img.pixels() {
//     print!("{}", "█".truecolor(pixel.2[0], pixel.2[1], pixel.2[2]));
//     if pixel.0 == img.width() - 1 {
//         println!();
//     }
// }
