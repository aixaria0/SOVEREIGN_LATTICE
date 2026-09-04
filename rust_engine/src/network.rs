const MAX_FRAME_SIZE: usize = 109; // PBFT message (101) or ViewChange (109)

// Inside your TCP stream reading loop:
let mut len_buf = [0u8; 4];
if stream.read_exact(&mut len_buf).await.is_err() {
    return; // Connection closed or error
}

let len = u32::from_be_bytes(len_buf) as usize;

// P0 FIX: Hard boundary to prevent OOM DOS attacks
if len < 101 || len > MAX_FRAME_SIZE {
    eprintln!("⚠️ SECURITY GUARD: Rejecting malicious frame size: {} bytes", len);
    return; // Drop the connection or ignore the packet
}

let mut payload = vec![0u8; len];
if stream.read_exact(&mut payload).await.is_err() {
    return;
}
