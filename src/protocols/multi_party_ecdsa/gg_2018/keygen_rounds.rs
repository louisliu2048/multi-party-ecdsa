use crate::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};

use curv::{
    arithmetic::traits::*,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};

use paillier::EncryptionKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalPartySaveData {
    pub party_keys: Keys,
    pub shared_keys: SharedKeys,
    pub party_id: u16,
    pub vss_scheme_vec:  Vec<VerifiableSS<Secp256k1>>,
    pub paillier_key_vector: Vec<EncryptionKey>,
    pub y_sum: Point<Secp256k1>,
}
