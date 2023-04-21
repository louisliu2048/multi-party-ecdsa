use criterion::criterion_main;

mod bench {
    use criterion::{Criterion, criterion_group};
    use curv::elliptic::curves::Secp256k1;
    use paillier::{KeyGeneration, Paillier};
    use round_based::dev::Simulation;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::PreParams;
    use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::{Keygen, LocalKey};

    pub fn simulate_keygen(t: u16, n: u16, pre_params_vec: Vec<PreParams>) -> Vec<LocalKey<Secp256k1>> {
        let mut simulation = Simulation::new();
        simulation.enable_benchmarks(true);

        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n, pre_params_vec[(i-1) as usize].clone()).unwrap());
        }

        let keys = simulation.run().unwrap();

        println!("Benchmark results:");
        println!("{:#?}", simulation.benchmark_results().unwrap());

        keys
    }

    pub fn bench_full_keygen_party_one_three_serial(c: &mut Criterion) {
        let mut pre_params_vec = Vec::new();
        for i in 0..3 {
            let  pre_params = PreParams{
                paillier_param: Paillier::keypair_safe_primes(),
                range_proof_param: Paillier::keypair_safe_primes()
            };
            pre_params_vec.push(pre_params);
        }

        c.bench_function("gg20: keygen t=1 n=3, Serial", move |b| {
            b.iter(|| {
                simulate_keygen(1, 3, pre_params_vec.clone());
            })
        });
    }

    criterion_group! {
    name = keygen;
    config = Criterion::default().sample_size(10);
    targets = self::bench_full_keygen_party_one_three_serial}
}

criterion_main!(bench::keygen);
