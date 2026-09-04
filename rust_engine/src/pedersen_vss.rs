use bls12_381::{G2Projective, Scalar};
use ff::Field;
use group::Curve;

/// Verifies a participant's secret share against the publicly broadcasted Feldman commitments.
/// If this check passes, the share is mathematically bound to the master public key (commitments[0]).
pub fn verify_feldman_share(
    participant_id: u32,
    secret_share: &Scalar,
    public_commitments: &[G2Projective]
) -> bool {
    let mut expected_pk = G2Projective::identity();
    let x = Scalar::from(participant_id as u64);
    let mut current_x_pow = Scalar::one();

    // Evaluate the public commitment polynomial at x = participant_id
    for commitment in public_commitments {
        expected_pk += commitment * current_x_pow;
        current_x_pow *= x;
    }

    let actual_pk = G2Projective::generator() * secret_share;
    actual_pk == expected_pk
}
