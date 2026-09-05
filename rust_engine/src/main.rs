use bls12_381::{G2Projective, Scalar};
use sovereign_lattice::dkg::{DkgSession, DkgShareMessage};
use sovereign_lattice::network::{
    send_framed_message, spawn_outbound_broadcaster, start_tcp_listener, PACKET_TYPE_DKG,
};
use sovereign_lattice::pbft::{PbftMessage, PbftState};
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub node_id: u32,
    pub total_nodes: usize,
    pub threshold: usize,
    pub bind_addr: SocketAddr,
    pub peer_map: HashMap<u32, SocketAddr>,
}

impl NodeConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let node_id: u32 = env::var("NODE_ID")
            .unwrap_or_else(|_| "0".into())
            .parse()?;
        let total_nodes: usize = env::var("TOTAL_NODES")
            .unwrap_or_else(|_| "4".into())
            .parse()?;
        let threshold: usize = env::var("THRESHOLD")
            .unwrap_or_else(|_| "3".into())
            .parse()?;

        let bind_addr_str = env::var("BIND_ADDR")
            .unwrap_or_else(|_| format!("127.0.0.1:{}", 8000 + node_id));
        let bind_addr: SocketAddr = bind_addr_str.parse()?;

        let mut peer_map = HashMap::new();
        for id in 0..total_nodes as u32 {
            let port = 8000 + id as u16;
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
            peer_map.insert(id, addr);
        }

        Ok(Self {
            node_id,
            total_nodes,
            threshold,
            bind_addr,
            peer_map,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = NodeConfig::from_env()?;

    println!(
        "🚀 [BOOTSTRAP]: Initializing Sovereign-Lattice Node {} on {}...",
        config.node_id, config.bind_addr
    );

    let (tx_broadcast, rx_broadcast) = mpsc::channel::<PbftMessage>(256);
    let (tx_dkg, mut rx_dkg) = mpsc::channel::<DkgShareMessage>(256);

    let shared_state: Arc<Mutex<Option<PbftState>>> = Arc::new(Mutex::new(None));
    let shared_sk: Arc<Mutex<Option<Scalar>>> = Arc::new(Mutex::new(None));

    let broadcaster_handle = spawn_outbound_broadcaster(
        config.node_id,
        config.peer_map.clone(),
        rx_broadcast,
    );

    let l_addr = config.bind_addr;
    let l_id = config.node_id;
    let l_sk = Arc::clone(&shared_sk);
    let l_state = Arc::clone(&shared_state);
    let l_peers = config.peer_map.clone();
    let l_tx_b = tx_broadcast.clone();
    let l_tx_d = tx_dkg.clone();

    tokio::spawn(async move {
        if let Err(e) = start_tcp_listener(l_addr, l_id, l_sk, l_state, l_peers, l_tx_b, l_tx_d).await {
            eprintln!("FATAL_LISTENER_ERROR: {}", e);
        }
    });

    println!("⏳ [DKG PHASE 1]: Waiting for network peers to bind sockets...");
    sleep(Duration::from_millis(1500)).await;

    let mut dkg_session = DkgSession::new(config.node_id, config.threshold, config.total_nodes);
    let my_commitments = dkg_session.generate_commitments();

    println!("📡 [DKG PHASE 2]: Transmitting Feldman shares across TCP mesh...");
    for (&peer_id, &peer_addr) in &config.peer_map {
        if peer_id == config.node_id {
            continue;
        }

        let share_for_peer = dkg_session.evaluate_share_for(peer_id);
        let msg = DkgShareMessage {
            from_node: config.node_id,
            to_node: peer_id,
            share: share_for_peer,
            commitments: my_commitments.clone(),
        };

        let payload = msg.to_bytes();
        tokio::spawn(async move {
            let mut attempts = 0;
            while attempts < 10 {
                if send_framed_message(peer_addr, PACKET_TYPE_DKG, &payload).await.is_ok() {
                    break;
                }
                sleep(Duration::from_millis(300)).await;
                attempts += 1;
            }
        });
    }

    println!("📥 [DKG PHASE 3]: Ingesting authenticated inbound shares from network...");
    let expected_inbound = config.total_nodes - 1;
    let mut collected_peers = HashMap::new();

    while collected_peers.len() < expected_inbound {
        if let Some(msg) = rx_dkg.recv().await {
            if msg.to_node == config.node_id && !collected_peers.contains_key(&msg.from_node) {
                match dkg_session.process_incoming_share(msg.from_node, msg.share, &msg.commitments) {
                    Ok(_) => {
                        collected_peers.insert(msg.from_node, msg.commitments);
                        println!(
                            "   -> Verified Feldman share from Node {} ({}/{})",
                            msg.from_node,
                            collected_peers.len(),
                            expected_inbound
                        );
                    }
                    Err(e) => {
                        eprintln!("REJECTED_DKG_SHARE from Node {}: {}", msg.from_node, e);
                    }
                }
            }
        }
    }

    let all_participants: Vec<u32> = (0..config.total_nodes as u32).collect();
    let (my_secret_share, canonical_master_pk) = dkg_session
        .finalize_dkg(&all_participants)
        .map_err(|e| format!("DKG_FINALIZATION_FAILURE: {}", e))?;

    println!("🔑 [DKG COMPLETED]: Master Threshold Public Key successfully synthesized over wire.");

    let mut public_keys = HashMap::new();
    for &id in &all_participants {
        let mut node_pk = dkg_session.commitments[0];
        let x = Scalar::from((id + 1) as u64);

        let mut my_val = Scalar::zero();
        let mut x_pow = Scalar::one();
        for coeff in &dkg_session.secret_polynomial {
            my_val += *coeff * x_pow;
            x_pow *= x;
        }

        let mut sum_pk = G2Projective::generator() * my_val;
        for (&peer_id, commits) in &collected_peers {
            if peer_id == config.node_id {
                continue;
            }
            let mut peer_eval = G2Projective::identity();
            let mut p_pow = Scalar::one();
            for c in commits {
                peer_eval += *c * p_pow;
                p_pow *= x;
            }
            sum_pk += peer_eval;
        }
        public_keys.insert(id, sum_pk);
    }

    let pbft = PbftState::new(config.total_nodes, public_keys, canonical_master_pk)?;

    {
        let mut state_guard = shared_state.lock().await;
        *state_guard = Some(pbft);

        let mut sk_guard = shared_sk.lock().await;
        *sk_guard = Some(my_secret_share);
    }

    println!("🛡️ [PBFT RUNTIME]: State machine activated. Network consensus engine running...");

    let _ = broadcaster_handle.await;
    Ok(())
}
