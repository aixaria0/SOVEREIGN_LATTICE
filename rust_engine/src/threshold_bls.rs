use std::collections::HashMap;
use bls12_381::{G1Projective, G2Projective, G2Affine, Scalar};
use ff::Field;
use sha2::{Sha512, Digest};
use group::Curve;

pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(dst);
    hasher.update(msg);
    let hash = hasher.finalize();
    
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash[0..64]);
    
    Scalar::from_bytes_wide(&wide_bytes)
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

pub fn independent_nums_g2_generator() -> G2Projective {
    let mut counter = 0u32;
    loop {
        let mut hasher = Sha512::new();
        hasher.update(b"SOVEREIGN_LATTICE_VSS_GENERATOR");
        hasher.update(&counter.to_le_bytes());
        let hash = hasher.finalize();
        
        let mut bytes = [0u8; 96];
        bytes[0..64].copy_from_slice(&hash[0..64]);
        bytes[0] |= 0xc0; 
        
        let affine_opt = G2Affine::from_compressed(&bytes);
        if bool::from(affine_opt.is_some()) {
            let affine = affine_opt.unwrap();
            if bool::from(affine.is_on_curve()) && bool::from(affine.is_torsion_free()) {
                return G2Projective::from(affine);
            }
        }
        counter += 1;
    }
}

pub fn verify_threshold_signature(
    msg: &[u8], 
    dst: &[u8], 
    signatures: &HashMap<u32, G1Projective>, 
    master_public_key: &G2Projective,
    threshold: usize
) -> bool {
    let master_sig = match reconstruct_threshold_signature(signatures, threshold) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    let h_scalar = hash_to_scalar(msg, dst);
    let h = G1Projective::generator() * h_scalar; 

    let p1 = bls12_381::pairing(&master_sig.to_affine(), &G2Projective::generator().to_affine());
    let p2 = bls12_381::pairing(&h.to_affine(), &master_public_key.to_affine());
    
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
