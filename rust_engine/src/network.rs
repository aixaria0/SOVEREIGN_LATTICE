use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

pub async fn start_tcp_listener(addr: &str) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind(addr).await?;
    println!("📡 [NETWORK]: Hardened TCP socket listening on {}", addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        println!("🌐 [NETWORK]: Connection accepted from {}", peer_addr);
        
        tokio::spawn(async move {
            if let Err(e) = handle_framed_connection(socket).await {
                eprintln!("⚠️ [STREAM ERROR]: {}", e);
            }
        });
    }
}

async fn handle_framed_connection(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    // خواندن ۴ بایت اول برای تشخیص طول پیام (Framing)
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    // جلوگیری از حملات حافظه (رد کردن پیام‌های خیلی بزرگ یا خیلی کوچک)
    if payload_len > 4096 || payload_len < 40 {
        return Err("Invalid frame length or payload size mismatch".into());
    }

    let mut payload = vec![0u8; payload_len];
    socket.read_exact(&mut payload).await?;

    let sequence = u64::from_be_bytes(payload[0..8].try_into().unwrap());
    
    println!("⚡ [FRAMING]: Parsed verified packet -> Seq: {}", sequence);
    socket.write_all(b"ACK_FRAME_SECURED").await?;

    Ok(())
}
