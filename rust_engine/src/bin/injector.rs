use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚡ [MATRIX OVERRIDE]: Connecting to Sovereign Lattice Daemon...");
    
    // Connect to the main daemon listening on port 8080
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("🔗 [LINK ESTABLISHED]: Bypassing outer firewall. Injecting zero-trust payload...");

    // Construct packet exactly as defined in network.rs (8 bytes sequence + 32 bytes digest)
    let sequence: u64 = 1042;
    let digest: [u8; 32] = *b"SOVEREIGN_LATTICE_SECURE_PAYLOAD"; 
    
    let mut payload = Vec::new();
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&digest);

    // Add 4-byte length prefix (Framing) to prevent memory exhaustion attacks
    let payload_len = payload.len() as u32;
    let mut frame = Vec::new();
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);

    // Inject the framed payload directly into the TCP socket
    stream.write_all(&frame).await?;
    println!("🛡️ [PAYLOAD DELIVERED]: Sequence {} successfully injected into the consensus lattice.", sequence);
    
    Ok(())
}
