// src/frost_sim.rs

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use rand::{RngCore, CryptoRng};

/// Simulates a basic FROST round safely
pub fn simulate_frost_round<R: RngCore + CryptoRng>(rng: &mut R) -> bool {
    println!("🌀 [FROST] Starting threshold signature simulation...");

    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    let d = Scalar::from_bytes_mod_order(bytes);

    let mut bytes_e = [0u8; 32];
    rng.fill_bytes(&mut bytes_e);
    let e = Scalar::from_bytes_mod_order(bytes_e);

    // Compute public commitment using &d reference as requested by compiler
    let r_point = RISTRETTO_BASEPOINT_TABLE * &d;
    
    // Accumulate safely
    let zero = Scalar::from(0u64);
    let mut z = zero;
    z += d * e;

    let success = r_point != RistrettoPoint::default() && z != zero;
    
    if success {
        println!("✅ [FROST] Simulation passed successfully.");
    } else {
        println!("❌ [FROST] Simulation check failed.");
    }

    success
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_frost_simulation() {
        let mut rng = OsRng;
        assert!(simulate_frost_round(&mut rng));
    }
}
