use bls12_381::{G2Projective, Scalar};
use ff::Field;
use rand::rngs::OsRng;
use sovereign_lattice::pbft::{PbftMessage, Phase};
use sovereign_lattice::threshold_bls::sign_bls_message;
use std::env;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_addr_str = env::var("TARGET_ADDR").unwrap_or_else(|_| "127.0.0.1:8000".into());
    let target_addr: SocketAddr = target_addr_str.parse()?;

    println!("⚡ [INJECTOR]: Connecting to target validator at {}...", target_addr);
    let mut stream = TcpStream::connect(target_addr).await?;

    let leader_sk = Scalar::random(&mut OsRng);
    let _leader_pk = G2Projective::generator() * leader_sk;

    let view = 0u64;
    let seq = 1u64;
    let digest = [0x5A; 32];
    let sender_id = 0u32;

    let mut canonical_msg = Vec::new();
    canonical_msg.push(Phase::PrePrepare as u8);
    canonical_msg.extend_from_slice(&view.to_be_bytes());
    canonical_msg.extend_from_slice(&seq.to_be_bytes());
    canonical_msg.extend_from_slice(&digest);

    let signature = sign_bls_message(&canonical_msg, &leader_sk);

    let pre_prepare_msg = PbftMessage {
        phase: Phase::PrePrepare,
        view,
        seq,
        digest,
        sender_id,
        signature,
    };

    let payload = pre_prepare_msg.to_bytes();
    let len_bytes = (payload.len() as u32).to_be_bytes();

    println!("📤 [INJECTOR]: Injecting PrePrepare proposal (seq: {}, view: {})...", seq, view);
    stream.write_all(&len_bytes).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;

    println!("✅ [INJECTOR]: Packet successfully transmitted over authenticated socket.");
    Ok(())
}
