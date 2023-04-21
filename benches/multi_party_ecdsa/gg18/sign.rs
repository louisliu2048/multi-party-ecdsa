use criterion::criterion_main;

mod bench {
    use std::collections::HashMap;
    use criterion::{criterion_group, Criterion};
    use criterion::async_executor::FuturesExecutor;
    use curv::arithmetic::Converter;
    use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
    use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
    use curv::BigInt;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::*;
    use std::{env, fs};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use uuid::Uuid;

    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::keygen_rounds::LocalPartySaveData;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::msg::Message;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::sign_rounds::{
        LocalParty, OnlineR,
    };
    use std::time::Instant;

    fn load_party_data(t: u16) -> Vec<LocalPartySaveData> {
        let mut save_data = Vec::new();
        for i in 1..t+2 {
            // read key file
            let proj_dir = env::current_dir().expect("not found path");
            let file_path = format!("benches/multi_party_ecdsa/gg18/keys{}.store",  i);
            let data = fs::read_to_string(proj_dir.join(file_path).to_str().unwrap())
                .expect("Unable to load keys, did you run keygen first? ");
            let local_data: LocalPartySaveData = serde_json::from_str(&data).unwrap();
            save_data.push(local_data);
        }

        return save_data
    }

    pub fn bench_full_sign_party_one_three_serial(c: &mut Criterion) {
        let data = load_party_data(1);
        c.bench_function("sign t=1 n=3, Serial", move |b| {
            b.iter(|| {
                sign_t_n_parties(1, 3, data.clone());
            })
        });
    }

    // pub fn bench_full_sign_party_one_three_parallel(c: &mut Criterion) {
    //     c.bench_function("sign t=1 n=3, Parallel",  move |b| {
    //         b.to_async(FuturesExecutor).iter(||  async { sign_parallel(1, 3).await } )
    //     });
    // }

    // // Here we have an async function to benchmark
    // async fn sign_parallel(t: u16, n: u16) {
    //     // Do something async with the size
    //     sign_t_n_parties(t, n);
    // }

    pub fn sign_t_n_parties(t: u16, n: u16, data: Vec<LocalPartySaveData>) {
        if t + 2 > n {
            panic!("invalid param of t: {} - n: {}", t, n);
        }

        let message_bn = BigInt::from_bytes(b"Cobo");

        let (msg_sender, msg_receiver) = mpsc::channel();
        let (end_sender, end_receiver) = mpsc::channel();

        let mut party_round_map = HashMap::new();
        for i in 1..t + 2 {
            let uuid = Uuid::new_v4().to_string();

            let local_party = LocalParty::new(
                data[(i-1) as usize].clone(),
                t as u16,
                i,
                uuid,
                message_bn.clone(),
                msg_sender.clone(),
                end_sender.clone(),
            );

           let round = local_party.start().map(OnlineR::R0).unwrap();

            party_round_map.insert(i, round);
        }

        let mut cnt = 0;
        for received in msg_receiver {
            if received.is_broadcast {
                for idx in 1..t+2 {
                    if idx != received.from.clone() {
                        let next =  gg18_round(party_round_map.get(&idx).unwrap().clone(), received.data.clone());
                        party_round_map.insert(idx, next);
                    }
                }
            } else {
                let next = gg18_round(party_round_map.get(&received.to).unwrap().clone(), received.data);
                party_round_map.insert(received.to, next);
            }

            if received.round == "round9" {
                cnt += 1;

                if cnt == t + 1 {
                    break;
                }
            }
        }

        // return;
        // for end in end_receiver {
        //     check_sig(&end.r, &end.s, &message_bn.clone(), &y_sum);
        // }
    }

    fn gg18_round(current_round: OnlineR, msg: String) -> OnlineR {
        let mut round_ans_vec = Vec::new();
        round_ans_vec.push(msg);

        // let start = Instant::now();
        match current_round {
            OnlineR::R0(round) => {
                let s = round.update(&round_ans_vec).map(OnlineR::R1).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round0! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R1(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R2).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round1! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R2(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R3).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round2! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R3(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R4).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round3! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R4(round) => {
                let s = round.update(&round_ans_vec).map(OnlineR::R5).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round4! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R5(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R6).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round5! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R6(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R7).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round6! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R7(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R8).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round7! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R8(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::R9).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round8! duration: {:?}ms",ms);

                return s
            }
            OnlineR::R9(round) => {
                let s =  round.update(&round_ans_vec).map(OnlineR::Finished).unwrap();

                // let duration = start.elapsed();
                // let ms = duration.as_millis();
                // println!("round9! duration: {:?}ms",ms);

                return s
            }
            s @ OnlineR::Finished(_) | s @ OnlineR::Gone => {
                return s;
            }
        }
    }

    pub fn check_sig(
        r: &Scalar<Secp256k1>,
        s: &Scalar<Secp256k1>,
        msg: &BigInt,
        pk: &Point<Secp256k1>,
    ) {
        use secp256k1::{Message, PublicKey, Signature, SECP256K1};

        let raw_msg = BigInt::to_bytes(msg);
        let mut msg: Vec<u8> = Vec::new(); // padding
        msg.extend(vec![0u8; 32 - raw_msg.len()]);
        msg.extend(raw_msg.iter());

        let msg = Message::from_slice(msg.as_slice()).unwrap();
        let mut raw_pk = pk.to_bytes(false).to_vec();
        if raw_pk.len() == 64 {
            raw_pk.insert(0, 4u8);
        }
        let pk = PublicKey::from_slice(&raw_pk).unwrap();

        let mut compact: Vec<u8> = Vec::new();
        let bytes_r = &r.to_bytes().to_vec();
        compact.extend(vec![0u8; 32 - bytes_r.len()]);
        compact.extend(bytes_r.iter());

        let bytes_s = &s.to_bytes().to_vec();
        compact.extend(vec![0u8; 32 - bytes_s.len()]);
        compact.extend(bytes_s.iter());

        let secp_sig = Signature::from_compact(compact.as_slice()).unwrap();

        let is_correct = SECP256K1.verify(&msg, &secp_sig, &pk).is_ok();
        assert!(is_correct);
    }

    criterion_group! {
    name = sign;
    config = Criterion::default().sample_size(10);
    targets = self::bench_full_sign_party_one_three_serial}
}

criterion_main!(bench::sign);
