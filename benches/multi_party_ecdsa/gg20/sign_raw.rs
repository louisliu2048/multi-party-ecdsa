use criterion::criterion_main;

mod bench {
    use criterion::{Criterion, criterion_group};
    use std::{env, fs};
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::blame::{
        GlobalStatePhase5, GlobalStatePhase6, GlobalStatePhase7, LocalStatePhase5, LocalStatePhase6,
    };
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
        KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, LocalSignature, Parameters, SharedKeys,
        SignKeys,
    };
    use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
    use curv::arithmetic::traits::Converter;

    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;
    use multi_party_ecdsa::utilities::zk_pdl_with_slack::PDLwSlackProof;
    use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
    use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
    use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
    use paillier::*;
    use sha2::Sha256;
    use zk_paillier::zkproofs::DLogStatement;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;

    use std::time::Instant;
    use futures::future::ok;
    use secp256k1::{Message, PublicKey, SECP256K1, Signature};

    fn load_data(s: Vec<usize>) -> Result<
        (
            Vec<DecryptionKey>,
            Vec<SharedKeys>,
            Vec<Vec<Point<Secp256k1>>>,
            Point<Secp256k1>,
            Vec<VerifiableSS<Secp256k1>>,
            Vec<Vec<EncryptionKey>>,
            Vec<Vec<DLogStatement>>,
        ),
        ErrorType,
    > {
        let mut party_keys_vec = Vec::new();
        let mut shared_keys_vec = Vec::new();
        let mut pk_vec = Vec::new();
        let mut vss_scheme_vec = Vec::new();
        let mut ek_vec = Vec::new();
        let mut dlog_statement_vec = Vec::new();
        let mut y: Point<Secp256k1> = Point::zero();

        let proj_dir = env::current_dir().expect("not found path");
        for i in s.clone() {
            // read key file
            let file_path = format!("benches/multi_party_ecdsa/gg20/local-share{}.json",  i + 1);

            let data = fs::read_to_string(proj_dir.join(file_path).to_str().unwrap())
                .expect("Unable to load keys, did you run keygen first? ");
            let local_data :LocalKey<Secp256k1> = serde_json::from_str(&data).unwrap();

            party_keys_vec.push(local_data.paillier_dk);
            shared_keys_vec.push(local_data.keys_linear);
            pk_vec.push(local_data.pk_vec);
            vss_scheme_vec.push(local_data.vss_scheme);
            ek_vec.push(local_data.paillier_key_vec);
            dlog_statement_vec.push(local_data.h1_h2_n_tilde_vec);
            y = local_data.y_sum_s;
        }

        Ok((
            party_keys_vec,
            shared_keys_vec,
            pk_vec,
            y,
            vss_scheme_vec,
            ek_vec,
            dlog_statement_vec,
        ))
    }

    pub fn bench_full_sign_party_one_three_raw_serial(c: &mut Criterion) {
        let data = load_data(vec![0, 1]);
        c.bench_function("gg20: sign t=1 n=3, Serial - raw", move |b| {
            b.iter(|| {
                sign_t_n_parties(1, 3,vec![0, 1], data.clone());
            })
        });
    }

    fn sign_t_n_parties(
        t: u16,
        n: u16,
        s: Vec<usize>, //participant list indexed from zero
        data: Result<(
            Vec<DecryptionKey>,
            Vec<SharedKeys>,
            Vec<Vec<Point<Secp256k1>>>,
            Point<Secp256k1>,
            Vec<VerifiableSS<Secp256k1>>,
            Vec<Vec<EncryptionKey>>,
            Vec<Vec<DLogStatement>>,
        ),
            ErrorType,>
    ) -> Result<SignatureRecid, ErrorType> {
        let (party_keys_vec,shared_keys_vec,pk_vec,y,vss_scheme_vec,ek_vec,dlog_statement_vec ) = data.unwrap();

        // let start = Instant::now();
        // transform the t,n share to t,t+1 share. Get the public keys for the same.
        let g_w_vec = SignKeys::g_w_vec(&pk_vec[0], &s[..], &vss_scheme_vec[0]);

        let private_vec = (0..shared_keys_vec.len())
            .map(|i| shared_keys_vec[i].x_i.clone())
            .collect::<Vec<_>>();

        let ttag = s.len() as usize;

        // each party creates a signing key. This happens in parallel IRL. In this test we
        // create a vector of signing keys, one for each party.
        // throughout i will index parties
        let sign_keys_vec = (0..ttag)
            .map(|i| SignKeys::create(&private_vec[s[i]], &vss_scheme_vec[i], s[i], &s))
            .collect::<Vec<SignKeys>>();

        // each party computes [Ci,Di] = com(g^gamma_i) and broadcast the commitments
        let (bc1_vec, decommit_vec1): (Vec<_>, Vec<_>) =
            sign_keys_vec.iter().map(|k| k.phase1_broadcast()).unzip();

        // each signer's dlog statement. in reality, parties prove statements
        // using only other parties' h1,h2,N_tilde. here we also use own parameters for simplicity
        let signers_dlog_statements = (0..ttag)
            .map(|i| dlog_statement_vec[i][s[i]].clone())
            .collect::<Vec<DLogStatement>>();

        // each party i BROADCASTS encryption of k_i under her Paillier key
        // m_a_vec = [ma_0;ma_1;,...]
        // we assume here that party sends the same encryption to all other parties.
        // It should be changed to different encryption (randomness) to each counter party
        let m_a_vec: Vec<_> = sign_keys_vec
            .iter()
            .enumerate()
            .map(|(i, k)| MessageA::a(&k.k_i, &ek_vec[i][s[i]], &signers_dlog_statements))
            .collect();

        // #each party i sends responses to m_a_vec she received (one response with input gamma_i and one with w_i)
        // #m_b_gamma_vec_all is a matrix where column i is a vector of message_b's that were sent to party i

        // aggregation of the n messages of all parties
        let mut m_b_gamma_vec_all = Vec::new();
        let mut beta_vec_all = Vec::new();
        let mut m_b_w_vec_all = Vec::new();
        let mut ni_vec_all = Vec::new();
        let mut beta_randomness_vec_all = Vec::new(); //should be accessible in case of blame
        let mut beta_tag_vec_all = Vec::new(); //should be accessible in case of blame

        // m_b_gamma and m_b_w are BROADCAST
        for i in 0..ttag {
            let mut m_b_gamma_vec = Vec::new();
            let mut beta_vec = Vec::new();
            let mut beta_randomness_vec = Vec::new();
            let mut beta_tag_vec = Vec::new();
            let mut m_b_w_vec = Vec::new();
            let mut ni_vec = Vec::new();

            for j in 0..ttag - 1 {
                let ind = if j < i { j } else { j + 1 };
                let (m_b_gamma, beta_gamma, beta_randomness, beta_tag) = MessageB::b(
                    &sign_keys_vec[ind].gamma_i,
                    &ek_vec[j][s[i]],
                    m_a_vec[i].0.clone(),
                    &signers_dlog_statements,
                )
                    .expect("Alice's range proofs in MtA failed");
                let (m_b_w, beta_wi, _, _) = MessageB::b(
                    &sign_keys_vec[ind].w_i,
                    &ek_vec[j][s[i]],
                    m_a_vec[i].0.clone(),
                    &signers_dlog_statements,
                )
                    .expect("Alice's range proofs in MtA failed");

                m_b_gamma_vec.push(m_b_gamma);
                beta_vec.push(beta_gamma);
                beta_randomness_vec.push(beta_randomness);
                beta_tag_vec.push(beta_tag);
                m_b_w_vec.push(m_b_w);
                ni_vec.push(beta_wi);
            }
            m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
            beta_vec_all.push(beta_vec.clone());
            beta_tag_vec_all.push(beta_tag_vec.clone());
            beta_randomness_vec_all.push(beta_randomness_vec.clone());
            m_b_w_vec_all.push(m_b_w_vec.clone());
            ni_vec_all.push(ni_vec.clone());
        }

        // Here we complete the MwA protocols by taking the mb matrices and starting with the first column,
        // generating the appropriate message. The first column is the answers of party 1 to mb sent from other parties.
        // The second column is the answers that party 2 is sending and so on.

        // TODO: simulate as IRL
        let mut alpha_vec_all = Vec::new();
        let mut miu_vec_all = Vec::new();
        let mut miu_bigint_vec_all = Vec::new(); //required for the phase6 IA sub protocol

        for i in 0..ttag {
            let mut alpha_vec = Vec::new();
            let mut miu_vec = Vec::new();
            let mut miu_bigint_vec = Vec::new(); //required for the phase6 IA sub protocol

            let m_b_gamma_vec_i = &m_b_gamma_vec_all[i];
            let m_b_w_vec_i = &m_b_w_vec_all[i];

            // in case
            for j in 0..ttag - 1 {
                let ind = if j < i { j } else { j + 1 };
                let m_b = m_b_gamma_vec_i[j].clone();

                // TODO: identify these errors
                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(&party_keys_vec[s[i]], &sign_keys_vec[i].k_i)
                    .expect("wrong dlog or m_b");
                let m_b = m_b_w_vec_i[j].clone();
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(&party_keys_vec[s[i]], &sign_keys_vec[i].k_i)
                    .expect("wrong dlog or m_b");

                // since we actually run two MtAwc each party needs to make sure that the values B are the same as the public values
                // here for b=w_i the parties already know W_i = g^w_i  for each party so this check is done here. for b = gamma_i the check will be later when g^gamma_i will become public
                // currently we take the W_i from the other parties signing keys
                // TODO: use pk_vec (first change from x_i to w_i) for this check.
                assert_eq!(m_b.b_proof.pk, sign_keys_vec[ind].g_w_i);

                alpha_vec.push(alpha_ij_gamma.0);
                miu_vec.push(alpha_ij_wi.0);
                miu_bigint_vec.push(alpha_ij_wi.1);
            }
            alpha_vec_all.push(alpha_vec.clone());
            miu_vec_all.push(miu_vec.clone());
            miu_bigint_vec_all.push(miu_bigint_vec.clone());
        }

        let mut delta_vec = Vec::new();
        let mut sigma_vec = Vec::new();

        for i in 0..ttag {
            // prepare beta_vec of party_i:
            let beta_vec = (0..ttag - 1)
                .map(|j| {
                    let ind1 = if j < i { j } else { j + 1 };
                    let ind2 = if j < i { i - 1 } else { i };

                    beta_vec_all[ind1][ind2].clone()
                })
                .collect::<Vec<Scalar<Secp256k1>>>();

            // prepare ni_vec of party_i:
            let ni_vec = (0..ttag - 1)
                .map(|j| {
                    let ind1 = if j < i { j } else { j + 1 };
                    let ind2 = if j < i { i - 1 } else { i };
                    ni_vec_all[ind1][ind2].clone()
                })
                .collect::<Vec<Scalar<Secp256k1>>>();

            let mut delta = sign_keys_vec[i].phase2_delta_i(&alpha_vec_all[i], &beta_vec);
            let mut sigma = sign_keys_vec[i].phase2_sigma_i(&miu_vec_all[i], &ni_vec);
            delta_vec.push(delta);
            sigma_vec.push(sigma);
        }

        // all parties broadcast delta_i and compute delta_i ^(-1)
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        // all parties broadcast T_i:
        let mut T_vec = Vec::new();
        let mut l_vec = Vec::new();
        let mut T_proof_vec = Vec::new();
        for i in 0..ttag {
            let (T_i, l_i, T_proof_i) = SignKeys::phase3_compute_t_i(&sigma_vec[i]);
            T_vec.push(T_i);
            l_vec.push(l_i);
            T_proof_vec.push(T_proof_i);
        }
        // verify T_proof_vec
        for i in 0..ttag {
            assert_eq!(T_vec[i], T_proof_vec[i].com.clone());
            PedersenProof::verify(&T_proof_vec[i]).expect("error T proof");
        }
        // de-commit to g^gamma_i from phase1, test comm correctness, and that it is the same value used in MtA.
        // Return R

        let R_vec = (0..ttag)
            .map(|i| {
                // each party i tests all B = g^b = g ^ gamma_i she received.
                let m_b_gamma_vec = &m_b_gamma_vec_all[i];
                let b_proof_vec = (0..ttag - 1)
                    .map(|j| &m_b_gamma_vec[j].b_proof)
                    .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
                SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec, i)
                    .expect("") //TODO: propagate the error
            })
            .collect::<Vec<Point<Secp256k1>>>();

        //new phase 5
        // all parties broadcast R_dash = k_i * R.
        let R_dash_vec = (0..ttag)
            .map(|i| &R_vec[i] * &sign_keys_vec[i].k_i)
            .collect::<Vec<Point<Secp256k1>>>();

        // each party sends first message to all other parties
        let mut phase5_proofs_vec: Vec<Vec<PDLwSlackProof>> = vec![Vec::new(); ttag];
        for i in 0..ttag {
            for j in 0..ttag - 1 {
                let ind = if j < i { j } else { j + 1 };
                let proof = LocalSignature::phase5_proof_pdl(
                    &R_dash_vec[i],
                    &R_vec[i],
                    &m_a_vec[i].0.c,
                    &ek_vec[j][s[i]],
                    &sign_keys_vec[i].k_i,
                    &m_a_vec[i].1,
                    &dlog_statement_vec[j][s[ind]],
                );

                phase5_proofs_vec[i].push(proof);
            }
        }

        for i in 0..ttag {
            let phase5_verify_zk = LocalSignature::phase5_verify_pdl(
                &phase5_proofs_vec[i],
                &R_dash_vec[i],
                &R_vec[i],
                &m_a_vec[i].0.c,
                &ek_vec[i][s[i]],
                &dlog_statement_vec[i][..],
                &s,
                i,
            );
            if phase5_verify_zk.is_err() {
                return Err(phase5_verify_zk.err().unwrap());
            }
        }

        //each party must run the test
        let phase5_check = LocalSignature::phase5_check_R_dash_sum(&R_dash_vec);
        if phase5_check.is_err() {
            // initiate phase 5 blame protocol to learn which parties acted maliciously.
            // each party generates local state and share with other parties.
            // assuming sync communication - if a message was failed to arrive from a party -
            // this party should automatically be blamed
            let mut local_state_vec = Vec::new();
            for i in 0..ttag {
                // compose beta tag vector:
                let mut beta_tag_vec_to_test = Vec::new();
                let mut beta_randomness_vec_to_test = Vec::new();
                for j in 0..ttag - 1 {
                    let ind1 = if j < i { j } else { j + 1 };
                    let ind2 = if j < i { i - 1 } else { i };
                    beta_tag_vec_to_test.push(beta_tag_vec_all[ind1][ind2].clone());
                    beta_randomness_vec_to_test.push(beta_randomness_vec_all[ind1][ind2].clone());
                }

                let local_state = LocalStatePhase5 {
                    k: sign_keys_vec[i].k_i.clone(),
                    k_randomness: m_a_vec[i].1.clone(),
                    gamma: sign_keys_vec[i].gamma_i.clone(),
                    beta_randomness: beta_randomness_vec_to_test,
                    beta_tag: beta_tag_vec_to_test,
                    encryption_key: ek_vec[i][s[i]].clone(),
                };
                local_state_vec.push(local_state);
            }
            //g_gamma_vec:
            let g_gamma_vec = (0..decommit_vec1.len())
                .map(|i| decommit_vec1[i].g_gamma_i.clone())
                .collect::<Vec<Point<Secp256k1>>>();
            //m_a_vec
            let m_a_vec = (0..m_a_vec.len())
                .map(|i| m_a_vec[i].0.clone())
                .collect::<Vec<MessageA>>();

            // reduce ek vec to only ek of participants :
            let ek_vec = (0..ttag)
                .map(|k| ek_vec[k][s[k]].clone())
                .collect::<Vec<EncryptionKey>>();
            let global_state = GlobalStatePhase5::local_state_to_global_state(
                &ek_vec[..],
                &delta_vec,
                &g_gamma_vec[..],
                &m_a_vec[..],
                m_b_gamma_vec_all,
                &local_state_vec[..],
            );
            global_state.phase5_blame()?;
        }

        let mut S_vec = Vec::new();
        let mut homo_elgamal_proof_vec = Vec::new();
        for i in 0..ttag {
            let (S_i, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
                &R_vec[i],
                &T_vec[i],
                &sigma_vec[i],
                &l_vec[i],
            );
            S_vec.push(S_i);
            homo_elgamal_proof_vec.push(homo_elgamal_proof);
        }

        LocalSignature::phase6_verify_proof(&S_vec, &homo_elgamal_proof_vec, &R_vec, &T_vec)?;

        let phase6_check = LocalSignature::phase6_check_S_i_sum(&y, &S_vec);
        if phase6_check.is_err() {
            // initiate phase 6 blame protocol to learn which parties acted maliciously.
            // each party generates local state and share with other parties.
            // assuming sync communication - if a message was failed to arrive from a party -
            // this party should automatically be blamed

            let mut local_state_vec = Vec::new();
            for i in 0..ttag {
                let mut miu_randomness_vec = Vec::new();
                for j in 0..ttag - 1 {
                    let rand = GlobalStatePhase6::extract_paillier_randomness(
                        &m_b_w_vec_all[i][j].c,
                        &party_keys_vec[s[i]],
                    );
                    miu_randomness_vec.push(rand);
                }
                let proof = GlobalStatePhase6::ecddh_proof(&sigma_vec[i], &R_vec[i], &S_vec[i]);
                let local_state = LocalStatePhase6 {
                    k: sign_keys_vec[i].k_i.clone(),
                    k_randomness: m_a_vec[i].1.clone(),
                    miu: miu_bigint_vec_all[i].clone(),
                    miu_randomness: miu_randomness_vec,
                    proof_of_eq_dlog: proof,
                };
                local_state_vec.push(local_state);
            }

            //m_a_vec
            let m_a_vec = (0..m_a_vec.len())
                .map(|i| m_a_vec[i].0.clone())
                .collect::<Vec<MessageA>>();

            // reduce ek vec to only ek of participants :
            let ek_vec = (0..ttag)
                .map(|k| ek_vec[k][s[k]].clone())
                .collect::<Vec<EncryptionKey>>();

            let global_state = GlobalStatePhase6::local_state_to_global_state(
                &ek_vec[..],
                &S_vec[..],
                &g_w_vec[..],
                &m_a_vec[..],
                m_b_w_vec_all,
                &local_state_vec[..],
            );
            global_state.phase6_blame(&R_vec[0])?;
        }

        let message: [u8; 4] = [79, 77, 69, 82];
        let message_bn = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(&message[..]))
            .result_bigint();
        let mut local_sig_vec = Vec::new();
        let mut s_vec = Vec::new();
        // each party computes s_i
        for i in 0..ttag {
            let local_sig = LocalSignature::phase7_local_sig(
                &sign_keys_vec[i].k_i,
                &message_bn,
                &R_vec[i],
                &sigma_vec[i],
                &y,
            );
            s_vec.push(local_sig.s_i.clone());
            local_sig_vec.push(local_sig);
        }

        let sig = local_sig_vec[0].output_signature(&s_vec[1..]);

        // test
        assert_eq!(local_sig_vec[0].y, y);
        //error in phase 7:
        if sig.is_err() {
            let global_state = GlobalStatePhase7 {
                s_vec,
                r: local_sig_vec[0].r.clone(),
                R_dash_vec,
                m: local_sig_vec[0].m.clone(),
                R: local_sig_vec[0].R.clone(),
                S_vec,
            };
            global_state.phase7_blame()?;
        }
        //for testing purposes: checking with a second verifier:

        // let duration = start.elapsed();
        // let ms = duration.as_millis();
        // println!("done! duration: {:?}ms",ms);

        let sig = sig.unwrap();
        // check_sig(&sig.r, &sig.s, &local_sig_vec[0].m, &y);
        Ok(sig)
    }

    fn check_sig(r: &Scalar<Secp256k1>, s: &Scalar<Secp256k1>, msg: &BigInt, pk: &Point<Secp256k1>) {
        let raw_msg = BigInt::to_bytes(msg);
        let mut msg: Vec<u8> = Vec::new(); // padding
        msg.extend(vec![0u8; 32 - raw_msg.len()]);
        msg.extend(raw_msg.iter());

        let msg = Message::from_slice(msg.as_slice()).unwrap();
        let slice = pk.to_bytes(false);
        let mut raw_pk = Vec::new();
        if slice.len() != 65 {
            // after curv's pk_to_key_slice return 65 bytes, this can be removed
            raw_pk.insert(0, 4u8);
            raw_pk.extend(vec![0u8; 64 - slice.len()]);
            raw_pk.extend(slice.as_ref());
        } else {
            raw_pk.extend(slice.as_ref());
        }

        assert_eq!(raw_pk.len(), 65);

        let pk = PublicKey::from_slice(&raw_pk).unwrap();

        let mut compact: Vec<u8> = Vec::new();
        let bytes_r = &r.to_bytes()[..];
        compact.extend(vec![0u8; 32 - bytes_r.len()]);
        compact.extend(bytes_r.iter());

        let bytes_s = &s.to_bytes()[..];
        compact.extend(vec![0u8; 32 - bytes_s.len()]);
        compact.extend(bytes_s.iter());

        let secp_sig = Signature::from_compact(compact.as_slice()).unwrap();

        let is_correct = SECP256K1.verify(&msg, &secp_sig, &pk).is_ok();
        assert!(is_correct);
    }

    criterion_group! {
    name = sign;
    config = Criterion::default().sample_size(10);
    targets = self::bench_full_sign_party_one_three_raw_serial}
}

criterion_main!(bench::sign);
