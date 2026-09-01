// rust_engine/src/dkg/feldman.rs
// Educational multi-dealer Feldman VSS / Joint DKG
// Not production-hardened (no constant-time, no network layer, etc.)

use bls12_381::{G2Projective, Scalar};
use ff::Field;
use group::{Curve, Group};
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct Share {
    pub index: u32,
    pub value: Scalar,
}

#[derive(Clone)]
pub struct Commitment {
    pub dealer: u32,
    pub commitments: Vec<G2Projective>, // C_k = g^{a_k}
}

#[derive(Clone)]
pub struct Complaint {
    pub from: u32,
    pub against: u32,
    pub share: Share,
}

pub struct MultiDealerDKG {
    pub n: u32,
    pub t: u32,
    pub commitments: HashMap<u32, Commitment>,
    pub shares: HashMap<(u32, u32), Scalar>, // (dealer, recipient) -> share
    pub disqualified: HashSet<u32>,
    pub complaints: Vec<Complaint>,
}

impl MultiDealerDKG {
    pub fn new(n: u32, t: u32) -> Self {
        Self {
            n,
            t,
            commitments: HashMap::new(),
            shares: HashMap::new(),
            disqualified: HashSet::new(),
            complaints: Vec::new(),
        }
    }

    /// Each dealer runs this to generate its polynomial and distribute shares
    pub fn deal(&mut self, dealer_id: u32) -> Vec<Share> {
        let mut rng = OsRng;
        let mut coeffs = Vec::with_capacity(self.t as usize);
        for _ in 0..self.t {
            coeffs.push(Scalar::random(&mut rng));
        }

        let g = G2Projective::generator();
        let commitments: Vec<G2Projective> = coeffs.iter().map(|a| g * a).collect();

        self.commitments.insert(dealer_id, Commitment {
            dealer: dealer_id,
            commitments,
        });

        let mut shares = Vec::new();
        for i in 1..=self.n {
            let x = Scalar::from(i as u64);
            let mut y = Scalar::ZERO;
            let mut pow = Scalar::ONE;
            for &c in &coeffs {
                y += c * pow;
                pow *= x;
            }
            shares.push(Share { index: i, value: y });
            self.shares.insert((dealer_id, i), y);
        }
        shares
    }

    /// Local verification of a received share
    pub fn verify_share(&self, dealer: u32, share: &Share) -> bool {
        let Some(cmt) = self.commitments.get(&dealer) else { return false };
        let g = G2Projective::generator();

        let mut rhs = G2Projective::identity();
        let mut pow = Scalar::ONE;
        let x = Scalar::from(share.index as u64);
        for c in &cmt.commitments {
            rhs += c * pow;
            pow *= x;
        }
        g * share.value == rhs
    }

    pub fn file_complaint(&mut self, complaint: Complaint) {
        if !self.disqualified.contains(&complaint.against) {
            self.complaints.push(complaint);
        }
    }

    pub fn resolve_and_disqualify(&mut self) {
        let mut counts: HashMap<u32, u32> = HashMap::new();
        for c in &self.complaints {
            *counts.entry(c.against).or_insert(0) += 1;
        }
        for (dealer, cnt) in counts {
            if cnt > self.t {
                self.disqualified.insert(dealer);
                self.commitments.remove(&dealer);
                self.shares.retain(|&(d, _), _| d != dealer);
            }
        }
        self.complaints.clear();
    }

    /// Final share for a recipient = sum of shares from all surviving dealers
    pub fn final_share(&self, recipient: u32) -> Option<Scalar> {
        let mut sum = Scalar::ZERO;
        let mut found = false;
        for ((dealer, rec), val) in &self.shares {
            if *rec == recipient && !self.disqualified.contains(dealer) {
                sum += val;
                found = true;
            }
        }
        if found { Some(sum) } else { None }
    }
}
