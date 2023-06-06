// For integration tests, please add your tests in /tests instead

use crate::protocols::two_party_ecdsa::lindell_2017::party_one::{
    EphEcKeyPair, EphKeyGenFirstMsg, Party1Private, Signature,
};
use crate::protocols::two_party_ecdsa::lindell_2017::party_two::{EphKeyGenSecondMsg, PartialSig};
use crate::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
use curv::BigInt;
use paillier::{
    Decrypt, EncryptionKey, MinimalEncryptionKey, Paillier, RawCiphertext,
};
use serde::{Deserialize, Serialize};

#[test]
fn test_d_log_proof_party_two_party_one() {
    let (party_one_first_message, comm_witness, _ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();
    let (party_two_first_message, _ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");
}

#[test]

fn test_full_key_gen() {
    let (party_one_first_message, comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments_with_fixed_secret_share(
            Scalar::<Secp256k1>::from(&BigInt::sample(253)),
        );
    let (party_two_first_message, _ec_key_pair_party2) =
        party_two::KeyGenFirstMsg::create_with_fixed_secret_share(Scalar::<Secp256k1>::from(
            &BigInt::from(10),
        ));
    let party_one_second_message = party_one::KeyGenSecondMsg::verify_and_decommit(
        comm_witness,
        &party_two_first_message.d_log_proof,
    )
    .expect("failed to verify and decommit");

    let _party_two_second_message = party_two::KeyGenSecondMsg::verify_commitments_and_dlog_proof(
        &party_one_first_message,
        &party_one_second_message,
    )
    .expect("failed to verify commitments and DLog proof");

    // init paillier keypair:
    let paillier_key_pair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    let party_one_private =
        party_one::Party1Private::set_private_key(&ec_key_pair_party1, &paillier_key_pair);

    let party_two_paillier = party_two::PaillierPublic {
        ek: paillier_key_pair.ek.clone(),
        encrypted_secret_share: paillier_key_pair.encrypted_share.clone(),
    };

    // zk proof of correct paillier key
    let correct_key_proof =
        party_one::PaillierKeyPair::generate_ni_proof_correct_key(&paillier_key_pair);
    party_two::PaillierPublic::verify_ni_proof_correct_key(
        correct_key_proof,
        &party_two_paillier.ek,
    )
    .expect("bad paillier key");

    //zk_pdl

    let (pdl_statement, pdl_proof, composite_dlog_proof) =
        party_one::PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
    party_two::PaillierPublic::pdl_verify(
        &composite_dlog_proof,
        &pdl_statement,
        &pdl_proof,
        &party_two_paillier,
        &party_one_second_message.comm_witness.public_share,
    )
    .expect("PDL error");
}

#[test]
fn test_two_party_sign() {
    // assume party1 and party2 engaged with KeyGen in the past resulting in
    // party1 owning private share and paillier key-pair
    // party2 owning private share and paillier encryption of party1 share

    // ec_key_pair: 自己随机生成的<x, y> = <x, g^x>
    let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
        party_one::KeyGenFirstMsg::create_commitments();

    // ec_key_pair：自己随机生成的<x, y> = <x, g^x>
    let (party_two_private_share_gen, ec_key_pair_party2) = party_two::KeyGenFirstMsg::create();

    // let pre_params = Paillier::keypair();
    // 生成paillier加密公私钥，并且对x1进行同态加密：Enc(x_1)
    let keypair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1);

    // =============================== signing ==============================
    #[derive(Serialize, Deserialize)]
    pub struct Round1Result {
        pub eph_party_one_first_message: EphKeyGenFirstMsg,
        pub eph_ec_key_pair_party1: EphEcKeyPair,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Round2Input {
        #[serde(with = "paillier::serialize::bigint")]
        pub paillier_n: BigInt,
        #[serde(with = "paillier::serialize::bigint")]
        pub encrypted_share: BigInt,
        pub ec_key_pair_party2: party_two::EcKeyPair,
        #[serde(with = "paillier::serialize::bigint")]
        pub message: BigInt,
        pub eph_party_one_first_message: EphKeyGenFirstMsg,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Round2Result {
        pub eph_party_two_first_message: party_two::EphKeyGenFirstMsg,
        pub eph_party_two_second_message: EphKeyGenSecondMsg,
        pub partial_sig: PartialSig,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Round3Input {
        #[serde(with = "paillier::serialize::bigint")]
        pub plain_sign: BigInt,
        pub r1_rst: Round1Result,
        pub r2_rst: Round2Result,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Round3Result {
        pub signature: Signature,
    }

    // round1
    // creating the ephemeral private shares:
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();
    let rst1 = Round1Result {
        eph_party_one_first_message: eph_party_one_first_message.clone(),
        eph_ec_key_pair_party1: eph_ec_key_pair_party1.clone(),
    };
    let rst1_str = serde_json::to_string(&rst1).unwrap();
    println!("result1: {}", rst1_str);
    // end round1

    let message = BigInt::from(1234);

    // round2
    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);

    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness,
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");

    let ek = EncryptionKey::from(MinimalEncryptionKey {
        n: keypair.ek.n.clone(),
    });
    let partial_sig = party_two::PartialSig::compute_add(
        &ek,                                               // node1的paillier公钥
        &keypair.encrypted_share.clone(),                  // node1的Enc(x_1)
        &party2_private,                                   // node2的私钥x2
        &eph_ec_key_pair_party2,                           // 包含了k2
        &eph_party_one_first_message.public_share.clone(), // 包含了R1 = g^k1
        &message,
    );

    let input2 = Round2Input {
        paillier_n: keypair.ek.n.clone(),
        encrypted_share: keypair.encrypted_share.clone(),
        ec_key_pair_party2,
        message: message.clone(),
        eph_party_one_first_message,
    };
    let round2_input_str = serde_json::to_string(&input2).unwrap();
    println!("input2: {}", round2_input_str);

    let rst2 = Round2Result {
        eph_party_two_first_message: eph_party_two_first_message.clone(),
        eph_party_two_second_message: eph_party_two_second_message.clone(),
        partial_sig: partial_sig.clone(),
    };
    let rst2_str = serde_json::to_string(&rst2).unwrap();
    println!("result2: {}", rst2_str);
    // end round2

    let party1_private =
        party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair.clone());
    let party1_key_str = serde_json::to_string(&party1_private.clone()).unwrap();
    println!("party1_private: {}", party1_key_str);

    let s_tag = Paillier::decrypt(
        &party1_private.paillier_priv,
        &RawCiphertext::from(partial_sig.c3),
    )
    .0;

    // round3
    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message.clone(),
        )
        .expect("failed to verify commitments and DLog proof");

    let signature = party_one::Signature::compute_with_plain_msg(
        &s_tag,
        &eph_ec_key_pair_party1,                                 // 包含k1
        &eph_party_two_second_message.comm_witness.public_share, // 包含了R2 = g^k2
    );

    let input3 = Round3Input {
        plain_sign: s_tag.clone().into_owned(),
        r1_rst: rst1,
        r2_rst: rst2,
    };
    let round3_input_str = serde_json::to_string(&input3).unwrap();
    println!("input3: {}", round3_input_str);

    let rst3 = Round3Result {
        signature: signature.clone(),
    };
    let rst3_str = serde_json::to_string(&rst3).unwrap();
    println!("result3: {}", rst3_str);
    // end round3

    let pubkey = party_one::compute_add_pubkey(
        &ec_key_pair_party1.public_share,
        &party_two_private_share_gen.public_share,
    );
    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
}
