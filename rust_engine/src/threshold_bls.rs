use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, Scalar};
use ff::Field;
use sha2::{Sha256, Digest};
use group::Curve;

pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let mut counter = 0u32;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(dst);
        hasher.update(msg);
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        
        let scalar_opt = Scalar::from_bytes(&bytes);
        if bool::from(scalar_opt.is_some()) {
            return scalar_opt.unwrap();
        }
        counter += 1;
    }
}

pub fn lagrange_basis_at_zero(i: u32, participants: &[u32]) -> Scalar {
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    let x_i = Scalar::from(i as u64);

    for &j in participants {
        if j == i { continue; }
        let x_j = Scalar::from(j as u64);
        
        num *= x_j;
        
        let mut diff = x_j;
        diff -= x_i;
        den *= diff;
    }
    
    let den_inv = den.invert();
    if bool::from(den_inv.is_some()) {
        num * den_inv.unwrap()
    } else {
        Scalar::zero()
    }
}

pub fn reconstruct_threshold_signature(
    signatures: &HashMap<u32, G1Projective>,
    threshold: usize
) -> Result<G1Projective, &'static str> {
    if signatures.len() < threshold {
        return Err("THRESHOLD_NOT_MET");
    }

    let participants: Vec<u32> = signatures.keys().copied().take(threshold).collect();
    let mut master_sig = G1Projective::identity();

    for &i in &participants {
        let sig_i = signatures.get(&i).unwrap();
        let lambda_i = lagrange_basis_at_zero(i, &participants);
        master_sig += sig_i * lambda_i;
    }

    Ok(master_sig)
}

pub fn reconstruct_threshold_public_key(
    public_keys: &HashMap<u32, G2Projective>,
    threshold: usize,
    participants: &[u32]
) -> Result<G2Projective, &'static str> {
    let mut master_pk = G2Projective::identity();

    for &i in participants {
        if let Some(pk_i) = public_keys.get(&i) {
            let lambda_i = lagrange_basis_at_zero(i, participants);
            master_pk += pk_i * lambda_i;
        } else {
            return Err("MISSING_PUBKEY");
        }
    }

    Ok(master_pk)
}

pub fn independent_nums_g2_generator() -> G2Projective {
    let scalar = hash_to_scalar(b"SOVEREIGN_LATTICE_VSS_GENERATOR", b"NUMS_DOMAIN");
    G2Projective::generator() * scalar
}

pub fn verify_threshold_signature(
    msg: &[u8], 
    dst: &[u8], 
    signatures: &HashMap<u32, G1Projective>, 
    public_keys: &HashMap<u32, G2Projective>,
    threshold: usize
) -> bool {
    let master_sig = match reconstruct_threshold_signature(signatures, threshold) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    
    let participants: Vec<u32> = signatures.keys().copied().take(threshold).collect();
    
    let master_pk = match reconstruct_threshold_public_key(public_keys, threshold, &participants) {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let h_scalar = hash_to_scalar(msg, dst);
    let h = G1Projective::generator() * h_scalar; 

    let p1 = bls12_381::pairing(&master_sig.to_affine(), &G2Projective::generator().to_affine());
    let p2 = bls12_381::pairing(&h.to_affine(), &master_pk.to_affine());
    
    p1 == p2
}

pub fn verify_bls_signature(
    msg: &[u8], 
    signature: &G1Projective, 
    public_key: &G2Projective
) -> bool {
    let h_scalar = hash_to_scalar(msg, b"PBFT_BLS_SIG_V1_CSUITE");
    let h = G1Projective::generator() * h_scalar; 
    
    let p1 = bls12_381::pairing(&signature.to_affine(), &G2Projective::generator().to_affine());
    let p2 = bls12_381::pairing(&h.to_affine(), &public_key.to_affine());
    
    p1 == p2
}
