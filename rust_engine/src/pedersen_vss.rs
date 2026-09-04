use bls12_381::{G2Projective, Scalar};
use ff::Field;
use group::Curve;

/// Canonical evaluation domain mapping ensuring strict synchronization between DKG share generation
/// and Feldman VSS verification (1-indexed to protect secret constant coefficient a_0 at x = 0).
#[inline]
pub fn evaluation_point(node_id: u32) -> Scalar {
    Scalar::from((node_id + 1) as u64)
}

/// Verifies a participant's secret share against the publicly broadcasted Feldman commitments
/// using the exact same canonical evaluation domain as the DKG session.
pub fn verify_feldman_share(
    participant_id: u32,
    secret_share: &Scalar,
    public_commitments: &[G2Projective]
) -> bool {
    let mut expected_pk = G2Projective::identity();
    let x = evaluation_point(participant_id);
    let mut current_x_pow = Scalar::one();

    for commitment in public_commitments {
        expected_pk += commitment * current_x_pow;
        current_x_pow *= x;
    }

    let actual_pk = G2Projective::generator() * secret_share;
    actual_pk == expected_pk
}
