use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use crate::pbft::{PbftMessage, PbftState, Phase, ViewChangePayload};

// نهایت سایز مجاز برای جلوگیری از حملات مموری (ViewChange حداکثر ۱۰۹ بایته)
pub const MAX_FRAME_SIZE: usize = 109;

pub async fn handle_connection(mut stream: TcpStream, state: Arc<Mutex<PbftState>>) {
    loop {
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // اتصال قطع شده یا خطای شبکه
        }

        let len = u32::from_be_bytes(len_buf) as usize;

        // گارد امنیتی: دراپ کردن کانکشن‌هایی که پیام‌های بیش‌ازحد بزرگ یا غیرمجاز می‌فرستن
        if len < 101 || len > MAX_FRAME_SIZE {
            eprintln!("SECURITY GUARD: Rejecting malicious frame size: {} bytes. Dropping connection.", len);
            break; 
        }

        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).await.is_err() {
            break;
        }

        let mut locked_state = state.lock().await;
        dispatch_network_payload(&mut locked_state, &payload);
    }
}

pub fn dispatch_network_payload(state: &mut PbftState, payload: &[u8]) {
    if payload.is_empty() { return; }

    // مسیریاب: تشخیص نوع پیام بر اساس طول و بایت اول (فاز)
    if payload.len() == 109 && payload[0] == Phase::ViewChange as u8 {
        match ViewChangePayload::from_bytes(payload) {
            Ok(vc) => {
                if let Err(e) = state.handle_view_change_payload(&vc) {
                    eprintln!("ViewChange Rejected: {}", e);
                }
            }
            Err(e) => eprintln!("ViewChange Parse Error: {}", e),
        }
    } else if payload.len() == 101 {
        match PbftMessage::from_bytes(payload) {
            Ok(msg) => {
                if let Err(e) = state.handle_message(&msg) {
                    eprintln!("PBFT Message Rejected: {}", e);
                }
            }
            Err(e) => eprintln!("PBFT Parse Error: {}", e),
        }
    } else {
        eprintln!("SECURITY GUARD: Unrecognized frame format or length.");
    }
}
