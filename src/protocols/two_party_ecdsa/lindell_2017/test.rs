// For integration tests, please add your tests in /tests instead

use crate::protocols::two_party_ecdsa::lindell_2017::{party_one, party_two};
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar};
use curv::BigInt;
use paillier::{KeyGeneration, Paillier};

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

    let preParams = Paillier::keypair();
    // init paillier keypair:
    let paillier_key_pair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1, preParams);

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

    let preParams = Paillier::keypair();
    // 生成paillier加密公私钥，并且对x1进行同态加密：Enc(x_1)
    let keypair =
        party_one::PaillierKeyPair::generate_keypair_and_encrypted_share(&ec_key_pair_party1, preParams);

    // creating the ephemeral private shares:
    // 这是干了啥？貌似做了随机生成k1和k2以及对应的R1=g^k1和R2=g^k2
    let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
        party_two::EphKeyGenFirstMsg::create_commitments();
    let (eph_party_one_first_message, eph_ec_key_pair_party1) =
        party_one::EphKeyGenFirstMsg::create();

    let eph_party_two_second_message = party_two::EphKeyGenSecondMsg::verify_and_decommit(
        eph_comm_witness, // 这是p2本来应该传递给p1的
        &eph_party_one_first_message,
    )
    .expect("party1 DLog proof failed");
    let _eph_party_one_second_message =
        party_one::EphKeyGenSecondMsg::verify_commitments_and_dlog_proof(
            &eph_party_two_first_message,
            &eph_party_two_second_message,
        )
        .expect("failed to verify commitments and DLog proof");

    let party2_private = party_two::Party2Private::set_private_key(&ec_key_pair_party2);
    let message = BigInt::from(1234);
    let partial_sig = party_two::PartialSig::compute(
        &keypair.ek, // node1的paillier公钥
        &keypair.encrypted_share, // node1的Enc(x_1)
        &party2_private, // node2的私钥x2
        &eph_ec_key_pair_party2, // 包含了k2
        &eph_party_one_first_message.public_share, // 包含了R1 = g^k1
        &message,
    );

    let party1_private = party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

    let signature = party_one::Signature::compute(
        &party1_private,
        &partial_sig.c3,
        &eph_ec_key_pair_party1, // 包含k1
        &eph_party_two_second_message.comm_witness.public_share, // 包含了R2 = g^k2
    );

    let pubkey =
        party_one::compute_pubkey(&party1_private, &party_two_private_share_gen.public_share);
    party_one::verify(&signature, &pubkey, &message).expect("Invalid signature")
}
