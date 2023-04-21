use criterion::criterion_main;

mod bench {
    use std::{env, fs};
    use criterion::{criterion_group, Criterion};
    use curv::BigInt;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::{Point, Scalar, Secp256k1};
    use futures::future::ok;
    use paillier::{KeyGeneration, Paillier};
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::keygen_rounds::LocalPartySaveData;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::{EcKeyPair, PaillierKeyPair};
    use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::*;

    fn generate_party_one_key() -> (EcKeyPair, PaillierKeyPair) {
        let (_party_one_private_share_gen, _comm_witness, ec_key_pair_party1) =
            party_one::KeyGenFirstMsg::create_commitments();

        let preParams = Paillier::keypair();
        let keypair = PaillierKeyPair::generate_keypair_and_encrypted_share(
            &ec_key_pair_party1,preParams,
        );

        (
            ec_key_pair_party1,
            keypair,
        )
    }

    fn generate_party_two_key() -> party_two::EcKeyPair{
        let (_party_two_private_share_gen, ec_key_pair_party2) =
            party_two::KeyGenFirstMsg::create();

        return ec_key_pair_party2
    }

    fn load_party_one_key_from_gg18(i: u16, s_l: &[u16]) -> (EcKeyPair, PaillierKeyPair) {
        let proj_dir = env::current_dir().expect("not found path");
        let file_path = format!("benches/multi_party_ecdsa/gg18/keys{}.store",  i+1);
        let data = fs::read_to_string(proj_dir.join(file_path).to_str().unwrap())
            .expect("Unable to load keys, did you run keygen first? ");
        let local_data: LocalPartySaveData = serde_json::from_str(&data).unwrap();

        let g_w_i = additive_sharing(local_data.clone(), i, s_l);
        let keygen = EcKeyPair{
            public_share: local_data.shared_keys.y,
            secret_share: g_w_i,
        };

        let keypair = PaillierKeyPair::generate_encrypted_share_from_fixed_paillier_keypair(
            &local_data.party_keys.ek.clone(),
            &local_data.party_keys.dk.clone(),
            &keygen,
        );

        return (
            keygen,
            keypair,
        )
    }

    fn load_party_two_key_from_gg18(i: u16, s_l: &[u16]) -> party_two::EcKeyPair{
        let proj_dir = env::current_dir().expect("not found path");
        let file_path = format!("benches/multi_party_ecdsa/gg18/keys{}.store",  i+1);
        let data = fs::read_to_string(proj_dir.join(file_path).to_str().unwrap())
            .expect("Unable to load keys, did you run keygen first? ");
        let local_data: LocalPartySaveData = serde_json::from_str(&data).unwrap();

        let g_w_i = additive_sharing(local_data.clone(), i, s_l);
        return party_two::EcKeyPair{
            public_share: local_data.shared_keys.y,
            secret_share: g_w_i,
        }
    }

    fn additive_sharing(key: LocalPartySaveData, index: u16, s_l: &[u16]) -> Scalar<Secp256k1> {
        let li =
            VerifiableSS::<Secp256k1>::map_share_to_new_params(&key.vss_scheme_vec[index as usize].parameters, index, s_l);
        return li * key.shared_keys.x_i;

       //  let mut li = 1;
       //  for i in s_l {
       //      if i != index {
       //          li = li *(0-i)/(index - i);
       //      }
       //  }
       //
       // return comm*Scalar::from(li);
    }

    pub fn bench_full_sign_party_one_two(c: &mut Criterion) {
        // let (ec_key_pair_party1, keypair) = generate_party_one_key();
        // let ec_key_pair_party2= generate_party_two_key();

        let (ec_key_pair_party1, keypair) = load_party_one_key_from_gg18(0, &[0,1]);
        let ec_key_pair_party2= load_party_two_key_from_gg18(1, &[0,1]);

        let message = BigInt::from(1234);
        c.bench_function("sign lindell", move |b| {
            b.iter(|| {
                // creating the ephemeral private shares:
                lindell_sign(ec_key_pair_party1.clone(), keypair.clone(),
                             ec_key_pair_party2.clone(), message.clone());
            })
        });
    }

    fn lindell_sign(ec_key_pair_party1: party_one::EcKeyPair, keypair: PaillierKeyPair,
                    ec_key_pair_party2: party_two::EcKeyPair, message: BigInt) {

        let (eph_party_two_first_message, eph_comm_witness, eph_ec_key_pair_party2) =
            party_two::EphKeyGenFirstMsg::create_commitments();
        let (eph_party_one_first_message, eph_ec_key_pair_party1) =
            party_one::EphKeyGenFirstMsg::create();
        let eph_party_two_second_message =
            party_two::EphKeyGenSecondMsg::verify_and_decommit(
                eph_comm_witness,
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
        let party1_private =
            party_one::Party1Private::set_private_key(&ec_key_pair_party1, &keypair);

        let partial_sig = party_two::PartialSig::compute(
            &keypair.ek,
            &keypair.encrypted_share,
            &party2_private,
            &eph_ec_key_pair_party2,
            &eph_party_one_first_message.public_share,
            &message,
        );

        let signature = party_one::Signature::compute(
            &party1_private,
            &partial_sig.c3,
            &eph_ec_key_pair_party1,
            &eph_party_two_second_message.comm_witness.public_share,
        );

        // let pubkey = party_one::compute_pubkey(
        //     &party1_private,
        //     &ec_key_pair_party2.public_share,
        // );

        party_one::verify(&signature, &ec_key_pair_party2.public_share, &message).expect("Invalid signature")
    }

    criterion_group! {
    name = sign;
    config = Criterion::default().sample_size(10);
    targets =self::bench_full_sign_party_one_two}
}

criterion_main!(bench::sign);
