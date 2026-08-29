use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚡ [MATRIX OVERRIDE]: Connecting to Sovereign Lattice Daemon...");
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    
    // Phase mapping: 0 = PrePrepare, 1 = Prepare, 2 = Commit
    let phase: u8 = 2; // Simulating a COMMIT packet
    let sequence: u64 = 1042;
    let digest: [u8; 32] = *b"SOVEREIGN_LATTICE_SECURE_PAYLOAD"; 
    
    let mut payload = Vec::new();
    payload.push(phase); // Prepend the phase byte
    payload.extend_from_slice(&sequence.to_be_bytes());
    payload.extend_from_slice(&digest);

    let payload_len = payload.len() as u32;
    let mut frame = Vec::new();
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(&payload);

    stream.write_all(&frame).await?;
    println!("🛡️ [PAYLOAD DELIVERED]: Injected PBFT phase {} vote for sequence {}.", phase, sequence);
    
    Ok(())
}
