use criterion::criterion_main;

mod bench {
    use std::collections::HashMap;
    use std::{env, fs};
    use anyhow::Context;
    use criterion::{criterion_group, Criterion};
    use criterion::async_executor::FuturesExecutor;

    use curv::arithmetic::Converter;
    use curv::BigInt;
    use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
    use curv::elliptic::curves::Secp256k1;
    use round_based::dev::Simulation;
    use sha2::Sha256;

    use super::*;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::verify;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{CompletedOfflineStage, OfflineStage, SignManual};

    pub fn bench_full_sign_party_one_three_serial(c: &mut Criterion) {
        let local_keys = load_party_data(1);
        c.bench_function("gg20: sign t=1 n=3, Serial", move |b| {
            b.iter(|| {
                let offline_stage = simulate_offline_stage(local_keys.clone(), &[1, 2]);
                simulate_signing(offline_stage.clone(), b"ZenGo")
            })
        });
    }

    // pub fn sign_t_n_parties(t: u16, n: u16) {
    //     if t + 2 > n {
    //         panic!("invalid param of t: {} - n: {}", t, n);
    //     }
    //
    //     let local_keys = load_party_data(t);
    //     let offline_stage = simulate_offline_stage(local_keys, &[1, 2]);
    //     simulate_signing(offline_stage, b"ZenGo")
    // }

    fn simulate_offline_stage(
        local_keys: Vec<LocalKey<Secp256k1>>,
        s_l: &[u16],
    ) -> Vec<CompletedOfflineStage> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(false);

        for (i, &keygen_i) in (1..).zip(s_l) {
            simulation.add_party(
                OfflineStage::new(
                    i,
                    s_l.to_vec(),
                    local_keys[usize::from(keygen_i - 1)].clone(),
                )
                    .unwrap(),
            );
        }

        let stages = simulation.run().unwrap();

        // println!("Benchmark results:");
        // println!("{:#?}", simulation.benchmark_results().unwrap());

        stages
    }

    fn simulate_signing(offline: Vec<CompletedOfflineStage>, message: &[u8]) {
        let message = Sha256::new()
            .chain_bigint(&BigInt::from_bytes(message))
            .result_bigint();
        let pk = offline[0].public_key().clone();

        let parties = offline
            .iter()
            .map(|o| SignManual::new(message.clone(), o.clone()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (parties, local_sigs): (Vec<_>, Vec<_>) = parties.into_iter().unzip();
        // parties.remove(0).complete(&local_sigs[1..]).unwrap();
        let local_sigs_except = |i: usize| {
            let mut v = vec![];
            v.extend_from_slice(&local_sigs[..i]);
            if i + 1 < local_sigs.len() {
                v.extend_from_slice(&local_sigs[i + 1..]);
            }
            v
        };

        assert!(parties
            .into_iter()
            .enumerate()
            .map(|(i, p)| p.complete(&local_sigs_except(i)).unwrap())
            .all(|signature| verify(&signature, &pk, &message).is_ok()));
    }

    fn load_party_data(t: u16) -> Vec<LocalKey<Secp256k1>>{
        let mut save_data = Vec::new();
        for i in 1..t+2 {
            // read key file
            let proj_dir = env::current_dir().expect("not found path");
            let file_path = format!("benches/multi_party_ecdsa/gg20/local-share{}.json",  i);

            let data = fs::read_to_string(proj_dir.join(file_path).to_str().unwrap())
                .expect("Unable to load keys, did you run keygen first? ");
            let local_data= serde_json::from_str(&data).unwrap();

            save_data.push(local_data);
        }

        return save_data
    }

    criterion_group! {
    name = sign;
    config = Criterion::default().sample_size(10);
    targets = self::bench_full_sign_party_one_three_serial}
}

criterion_main!(bench::sign);
