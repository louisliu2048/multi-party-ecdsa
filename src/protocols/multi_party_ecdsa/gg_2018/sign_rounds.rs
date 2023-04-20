use crate::protocols::multi_party_ecdsa::gg_2018::keygen_rounds::LocalPartySaveData;
use crate::protocols::multi_party_ecdsa::gg_2018::msg::Message;
use crate::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};
use crate::utilities::mta::{MessageA, MessageB};
use curv::arithmetic::{Converter, Zero};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{Curve, Point, Scalar, Secp256k1};
use curv::{BigInt, HashChoice};
use sha2::Sha256;
use std::sync::mpsc;
use thiserror::Error;

#[derive(Clone)]
pub struct LocalParty {
    pub data: LocalPartySaveData,

    // params
    pub threshold: u16,
    pub party_num_int: u16,
    pub uuid: String,
    pub message_bn: BigInt,

    // channels
    pub out: mpsc::Sender<Message>,
    pub end: mpsc::Sender<SignatureRecid>,
}

impl LocalParty {
    pub fn new(
        data: LocalPartySaveData,
        threshold: u16,
        party_num_int: u16,
        uuid: String,
        message_bn: BigInt,
        out: mpsc::Sender<Message>,
        end: mpsc::Sender<SignatureRecid>,
    ) -> Self {
        LocalParty {
            data,
            threshold,
            party_num_int,
            uuid,
            message_bn,
            out,
            end,
        }
    }

    pub fn start(self) -> Result<Round0> {
        // maybe we should do something initial here.
        self.out
            .send(Message {
                from: self.party_num_int,
                to: 0,
                round: "round0".to_string(),
                data: serde_json::to_string(&self.data.party_id).unwrap(),
                sender_uuid: self.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round0 { local_data: self });
    }
}

// pub trait GG18Round {
//     fn update(self, round_ans_vec: &Vec<String>) -> Result<OnlineR>;
// }

#[derive(Clone)]
pub struct Round0 {
    pub local_data: LocalParty,
}

impl Round0 {
    pub fn update(self, round0_ans_vec: &Vec<String>) -> Result<Round1> {
        let mut j = 0;
        let mut signers_vec: Vec<u16> = Vec::new();
        for i in 1..=self.local_data.threshold + 1 {
            if i == self.local_data.party_num_int {
                signers_vec.push(self.local_data.data.party_id - 1);
            } else {
                let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
                signers_vec.push(signer_j - 1);
                j += 1;
            }
        }

        let private = PartyPrivate::set_private(
            self.local_data.data.party_keys.clone(),
            self.local_data.data.shared_keys.clone(),
        );

        let sign_keys: SignKeys = SignKeys::create(
            &private,
            &self.local_data.data.vss_scheme_vec
                [usize::from(signers_vec[usize::from(self.local_data.party_num_int - 1)])],
            signers_vec[usize::from(self.local_data.party_num_int - 1)],
            &signers_vec,
        );

        let (com, decommit) = sign_keys.phase1_broadcast(); // com: 关于g^γ的hash承诺, decommit: [tmp || g^γ_x || g^γ_y]
        let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &self.local_data.data.party_keys.ek, &[]); // 关于ki的Paillier加密Enk(Ki)

        self.local_data
            .out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round1".to_string(),
                data: serde_json::to_string(&(com.clone(), m_a_k)).unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round1 {
            local_data: self.local_data,
            signers_vec,
            sign_keys,
            com,
            decommit,
        });
    }
}

#[derive(Clone)]
pub struct Round1 {
    pub local_data: LocalParty,
    pub signers_vec: Vec<u16>, // 建议全局
    pub sign_keys: SignKeys,   // 建议全局

    pub com: SignBroadcastPhase1, // 只给round1用了

    // 搬运工
    pub decommit: SignDecommitPhase1, // 给round3和round4用了
}

impl Round1 {
    pub fn update(self, round1_ans_vec: &Vec<String>) -> Result<Round2> {
        let mut j = 0;
        let mut bc1_vec = Vec::new();
        let mut m_a_vec: Vec<MessageA> = Vec::new(); // 存储对方的Enk(Ki)

        for i in 1..self.local_data.threshold + 2 {
            if i == self.local_data.party_num_int {
                bc1_vec.push(self.com.clone()); // 所有g^γ的hash承诺
                                                                //   m_a_vec.push(m_a_k.clone());
            } else {
                //     if signers_vec.contains(&(i as usize)) {
                let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                    serde_json::from_str(&round1_ans_vec[j]).unwrap();
                bc1_vec.push(bc1_j);
                m_a_vec.push(m_a_party_j);

                j += 1;
                //       }
            }
        }
        assert_eq!(self.signers_vec.len(), bc1_vec.len());

        let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
        let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
        let mut beta_vec = Vec::new();
        let mut ni_vec = Vec::new();
        let mut j = 0;
        for i in 1..self.local_data.threshold + 2 {
            if i != self.local_data.party_num_int {
                // 别人的Enc(kj)和我的γi，计算Enc(Kj)*Enc(γi) = Enc(a + β)，其中a = Kj*γi + β，我留下-β
                let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                    &self.sign_keys.gamma_i, // 我的γi
                    &self.local_data.data.paillier_key_vector
                        [usize::from(self.signers_vec[usize::from(i - 1)])], // 别人的Paillier pubkey
                    m_a_vec[j].clone(), // 别人的Enk(Ki)
                    &[],
                )
                .unwrap();

                // 别人的Enc(kj)和我的wi，计算Enc(Kj)*Enc(wi) = Enc(μ + v)，其中μ = Kj*wi + v，我留下-v
                let (m_b_w, beta_wi, _, _) = MessageB::b(
                    &self.sign_keys.w_i, // 我的wi
                    &self.local_data.data.paillier_key_vector
                        [usize::from(self.signers_vec[usize::from(i - 1)])], // 别人的 Paillier pubkey
                    m_a_vec[j].clone(), // 别人的Enk(Ki)
                    &[],
                )
                .unwrap();

                m_b_gamma_send_vec.push(m_b_gamma); // 给别人的a = Enc(Kj)*Enc(γi) + Enc(β)
                m_b_w_send_vec.push(m_b_w); // 给别人的μ = Enc(Kj)*Enc(wi) + Enc(v)

                beta_vec.push(beta_gamma); // 我自己留下的-β
                ni_vec.push(beta_wi); // 我自己留下的-v
                j += 1;
            }
        }

        let mut j = 0;
        for i in 1..self.local_data.threshold + 2 {
            if i != self.local_data.party_num_int {
                self.local_data
                    .out
                    .send(Message {
                        from: self.local_data.party_num_int,
                        to: i,
                        round: "round2".to_string(),
                        data: serde_json::to_string(&(
                            m_b_gamma_send_vec[j].clone(), // 给别人的a =  Enc(Kj)*Enc(γi) + Enc(β)
                            m_b_w_send_vec[j].clone(),     // 给别人的μ = Enc(Kj)*Enc(wi) + Enc(v)
                        ))
                        .unwrap(),
                        sender_uuid: self.local_data.uuid.clone(),
                        is_broadcast: false,
                    })
                    .expect("fail to send msg out");
                j += 1;
            }
        }

        return Ok(Round2 {
            local_data: self.local_data,
            signers_vec: self.signers_vec,
            sign_keys: self.sign_keys,
            beta_vec,
            ni_vec,
            decommit: self.decommit,
            bc1_vec,
        });
    }
}

#[derive(Clone)]
pub struct Round2 {
    pub local_data: LocalParty,
    pub signers_vec: Vec<u16>, // 建议全局
    pub sign_keys: SignKeys,   // 建议全局

    pub beta_vec: Vec<Scalar<Secp256k1>>, // 只给round2用了
    pub ni_vec: Vec<Scalar<Secp256k1>>,   // 只给round2用了

    // 搬运工
    pub decommit: SignDecommitPhase1,      // 给round3和round4用了
    pub bc1_vec: Vec<SignBroadcastPhase1>, // 只给round4用了
}

impl Round2 {
    pub fn update(self, round2_ans_vec: &Vec<String>) -> Result<Round3> {
        let mut m_b_gamma_rec_vec = Vec::new();
        let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

        for i in 0..self.local_data.threshold {
            //  if signers_vec.contains(&(i as usize)) {
            let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
                serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
            m_b_gamma_rec_vec.push(m_b_gamma_i); // 别人给我的的 a = Enc(Ki)*Enc(γj) + Enc(β)
            m_b_w_rec_vec.push(m_b_w_i); // 别人给我的的 μ = Enc(Ki)*Enc(wj) + Enc(β)
                                         //     }
        }

        let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let xi_com_vec: Vec<Point<Secp256k1>> =
            Keys::get_commitments_to_xi(&self.local_data.data.vss_scheme_vec);

        let mut j = 0;
        for i in 1..self.local_data.threshold + 2 {
            if i != self.local_data.party_num_int {
                let m_b = m_b_gamma_rec_vec[j].clone(); // 别人给我的的 a = Enc(Ki)*Enc(γj) + Enc(β)
                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(
                        &self.local_data.data.party_keys.dk,
                        &self.sign_keys.k_i,
                    )
                    .expect("wrong dlog or m_b");

                let m_b = m_b_w_rec_vec[j].clone(); // 别人给我的的 μ = Enc(Ki)*Enc(wj) + Enc(β)
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(
                        &self.local_data.data.party_keys.dk,
                        &self.sign_keys.k_i,
                    )
                    .expect("wrong dlog or m_b");

                alpha_vec.push(alpha_ij_gamma.0); // 别人发过来的ki*γj + βj
                miu_vec.push(alpha_ij_wi.0); // 别人发过来的Ki*wj + βj，注意，和上面的βj不同，都是随机生成的

                let g_w_i = Keys::update_commitments_to_xi(
                    &xi_com_vec[usize::from(self.signers_vec[usize::from(i - 1)])],
                    &self.local_data.data.vss_scheme_vec
                        [usize::from(self.signers_vec[usize::from(i - 1)])],
                    self.signers_vec[usize::from(i - 1)],
                    &self.signers_vec,
                );
                assert_eq!(m_b.b_proof.pk, g_w_i); // 校验别人的用的Paillier是不是正确的
                j += 1;
            }
        }

        let delta_i = self.sign_keys.phase2_delta_i(&alpha_vec, &self.beta_vec); // 计算自己得到的 δ = deltai = ∑kiγj
        let sigma = self.sign_keys.phase2_sigma_i(&miu_vec, &self.ni_vec); // 计算自己得到的 σ = sigmai = ∑kiwj

        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round3".to_string(),
                data: serde_json::to_string(&delta_i.clone()).unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round3 {
            local_data: self.local_data,
            sign_keys: self.sign_keys,
            decommit: self.decommit,
            delta_i,
            bc1_vec: self.bc1_vec,
            m_b_gamma_rec_vec,
            sigma,
        });
    }
}

#[derive(Clone)]
pub struct Round3 {
    pub local_data: LocalParty,
    pub sign_keys: SignKeys, // 建议全局

    pub decommit: SignDecommitPhase1, // 给round3和round4用了
    pub delta_i: Scalar<Secp256k1>,   // 只给round3用了

    // 搬运工
    pub bc1_vec: Vec<SignBroadcastPhase1>, // 只给round4用了
    pub m_b_gamma_rec_vec: Vec<MessageB>,  // 只给round4用了
    pub sigma: Scalar<Secp256k1>,          // 只给round4用了
}

impl Round3 {
    pub fn update(self, round3_ans_vec: &Vec<String>) -> Result<Round4> {
        let mut delta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        format_vec_from_reads(
            &round3_ans_vec,
            self.local_data.party_num_int as usize,
            self.delta_i.clone(),
            &mut delta_vec,
        );
        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec); // 计算(∑δi)^-1 = (∑kiγj)^-1

        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round4".to_string(),
                data: serde_json::to_string(&self.decommit).unwrap(), // 自己的g^γ的decommit
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round4 {
            local_data: self.local_data,
            sign_keys: self.sign_keys,
            decommit: self.decommit,
            bc1_vec: self.bc1_vec,
            m_b_gamma_rec_vec: self.m_b_gamma_rec_vec,
            sigma: self.sigma,
            delta_inv,
        });
    }
}

#[derive(Clone)]
pub struct Round4 {
    pub local_data: LocalParty,
    pub sign_keys: SignKeys, // 建议全局

    pub decommit: SignDecommitPhase1,      // 给round3和round4用了
    pub bc1_vec: Vec<SignBroadcastPhase1>, // 只给round4用了
    pub m_b_gamma_rec_vec: Vec<MessageB>,  // 只给round4用了
    pub sigma: Scalar<Secp256k1>,          // 只给round4用了
    pub delta_inv: Scalar<Secp256k1>,      // 只给round4用了
}

impl Round4 {
    pub fn update(self, round4_ans_vec: &Vec<String>) -> Result<Round5> {
        let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
        format_vec_from_reads(
            &round4_ans_vec,
            self.local_data.party_num_int as usize,
            self.decommit.clone(),
            &mut decommit_vec,
        );
        let decomm_i = decommit_vec.remove(usize::from(self.local_data.party_num_int - 1)); // 别人给的[tmp || g^γ_x || g^γ_y]
        let mut bc1_vec = self.bc1_vec.clone();
        bc1_vec.remove(usize::from(self.local_data.party_num_int - 1)); // 别人计算的Hash(tmp || g^γ_x || g^γ_y)

        let b_proof_vec = (0..self.m_b_gamma_rec_vec.len()) // 别人给我的的 a = Enc(Ki)*Enc(γj) + Enc(β)
            .map(|i| &self.m_b_gamma_rec_vec[i].b_proof)
            .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();
        let mut big_r = SignKeys::phase4(&self.delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
            .expect("bad gamma_i decommit");

        // adding local g_gamma_i
        big_r = big_r.clone() + decomm_i.g_gamma_i * self.delta_inv.clone(); // ok，算出了R

        // we assume the message is already hashed (by the signer).
        let local_sig = LocalSignature::phase5_local_sig(
            &self.sign_keys.k_i,
            &self.local_data.message_bn,
            &big_r,
            &self.sigma,
            &self.local_data.data.y_sum,
        );

        let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
            local_sig.phase5a_broadcast_5b_zkproof();
        // self.phase5_com = phase5_com; // Hash(tmp || Vi || Ai || Bi)
        // self.phase_5a_decom = phase_5a_decom; // [Vi, Ai, Bi, tmp]
        // self.helgamal_proof = helgamal_proof;
        // self.dlog_proof_rho = dlog_proof_rho; // ρi的范围证明

        // phase (5A)  broadcast commit
        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round5".to_string(),
                data: serde_json::to_string(&phase5_com.clone()).unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round5 {
            local_data: self.local_data,
            sign_keys: self.sign_keys,
            local_sig,
            phase5_com,
            phase_5a_decom,
            helgamal_proof,
            dlog_proof_rho,
            big_r,
        });
    }
}

#[derive(Clone)]
pub struct Round5 {
    pub local_data: LocalParty,
    pub sign_keys: SignKeys,       // 建议全局
    pub local_sig: LocalSignature, // 建议全局

    pub phase5_com: Phase5Com1,        // 只给round5用了
    pub phase_5a_decom: Phase5ADecom1, // 给round5和round6使用了
    pub helgamal_proof: HomoELGamalProof<Secp256k1, Sha256>, // 给round5和round6使用了
    pub dlog_proof_rho: DLogProof<Secp256k1, Sha256>, // 给round5和round6使用了

    // 搬运工
    pub big_r: Point<Secp256k1>, // 给round6用了
}

impl Round5 {
    pub fn update(self, round5_ans_vec: &Vec<String>) -> Result<Round6> {
        let mut commit5a_vec = Vec::new();
        format_vec_from_reads(
            &round5_ans_vec,
            self.local_data.party_num_int as usize,
            self.phase5_com.clone(),
            &mut commit5a_vec,
        );

        //phase (5B)  broadcast decommit and (5B) ZK proof
        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round6".to_string(),
                data: serde_json::to_string(&(
                    self.phase_5a_decom.clone(),
                    self.helgamal_proof.clone(),
                    self.dlog_proof_rho.clone(),
                ))
                .unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round6 {
            local_data: self.local_data,
            local_sig: self.local_sig,
            big_r: self.big_r,
            phase_5a_decom: self.phase_5a_decom,
            helgamal_proof: self.helgamal_proof,
            dlog_proof_rho: self.dlog_proof_rho,
            commit5a_vec,
        });
    }
}

#[derive(Clone)]
pub struct Round6 {
    pub local_data: LocalParty,
    pub local_sig: LocalSignature, // 建议全局

    pub big_r: Point<Secp256k1>,       // 给round6用了
    pub phase_5a_decom: Phase5ADecom1, // 给round5和round6使用了
    pub helgamal_proof: HomoELGamalProof<Secp256k1, Sha256>, // 给round5和round6使用了
    pub dlog_proof_rho: DLogProof<Secp256k1, Sha256>, // 给round5和round6使用了
    pub commit5a_vec: Vec<Phase5Com1>, // 只给round6用了
}

impl Round6 {
    pub fn update(self, round6_ans_vec: &Vec<String>) -> Result<Round7> {
        let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(
            Phase5ADecom1,
            HomoELGamalProof<Secp256k1, Sha256>,
            DLogProof<Secp256k1, Sha256>,
        )> = Vec::new();
        format_vec_from_reads(
            &round6_ans_vec,
            self.local_data.party_num_int as usize,
            (
                self.phase_5a_decom.clone(),
                self.helgamal_proof.clone(),
                self.dlog_proof_rho.clone(),
            ),
            &mut decommit5a_and_elgamal_and_dlog_vec,
        );
        let decommit5a_and_elgamal_and_dlog_vec_includes_i =
            decommit5a_and_elgamal_and_dlog_vec.clone();

        decommit5a_and_elgamal_and_dlog_vec.remove(usize::from(self.local_data.party_num_int - 1));
        let mut commit5a_vec = self.commit5a_vec.clone();
        commit5a_vec.remove(usize::from(self.local_data.party_num_int - 1));

        let phase_5a_decomm_vec = (0..self.local_data.threshold)
            .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
            .collect::<Vec<Phase5ADecom1>>();

        let phase_5a_elgamal_vec = (0..self.local_data.threshold)
            .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
            .collect::<Vec<HomoELGamalProof<Secp256k1, Sha256>>>();

        let phase_5a_dlog_vec = (0..self.local_data.threshold)
            .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
            .collect::<Vec<DLogProof<Secp256k1, Sha256>>>();

        let (phase5_com2, phase_5d_decom2) = self
            .local_sig
            .phase5c(
                &phase_5a_decomm_vec,
                &commit5a_vec,
                &phase_5a_elgamal_vec,
                &phase_5a_dlog_vec,
                &self.phase_5a_decom.V_i,
                &self.big_r,
            )
            .expect("error phase5");
        // self.phase5_com2 = phase5_com2;
        // self.phase_5d_decom2 = phase_5d_decom2;

        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round7".to_string(),
                data: serde_json::to_string(&phase5_com2.clone()).unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round7 {
            local_data: self.local_data,
            local_sig: self.local_sig,
            phase5_com2,
            phase_5d_decom2,
            decommit5a_and_elgamal_and_dlog_vec_includes_i,
        });
    }
}

#[derive(Clone)]
pub struct Round7 {
    pub local_data: LocalParty,
    pub local_sig: LocalSignature, // 建议全局

    pub phase5_com2: Phase5Com2,        // 只给round7用了
    pub phase_5d_decom2: Phase5DDecom2, // 给round7和round8使用了

    // 搬运工
    pub decommit5a_and_elgamal_and_dlog_vec_includes_i: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )>, // 只给round8用了
}

impl Round7 {
    pub fn update(self, round7_ans_vec: &Vec<String>) -> Result<Round8> {
        let mut commit5c_vec = Vec::new();
        format_vec_from_reads(
            &round7_ans_vec,
            self.local_data.party_num_int as usize,
            self.phase5_com2.clone(),
            &mut commit5c_vec,
        );

        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round8".to_string(),
                data: serde_json::to_string(&self.phase_5d_decom2.clone()).unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round8 {
            local_data: self.local_data,
            local_sig: self.local_sig,
            decommit5a_and_elgamal_and_dlog_vec_includes_i: self
                .decommit5a_and_elgamal_and_dlog_vec_includes_i,
            phase_5d_decom2: self.phase_5d_decom2,
            commit5c_vec,
        });
    }
}

#[derive(Clone)]
pub struct Round8 {
    pub local_data: LocalParty,
    pub local_sig: LocalSignature, // 建议全局

    pub decommit5a_and_elgamal_and_dlog_vec_includes_i: Vec<(
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>,
    )>, // 只给round8用了
    pub phase_5d_decom2: Phase5DDecom2, // 给round7和round8使用了
    pub commit5c_vec: Vec<Phase5Com2>,  // 只给round8用了
}

impl Round8 {
    pub fn update(self, round8_ans_vec: &Vec<String>) -> Result<Round9> {
        let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
        format_vec_from_reads(
            &round8_ans_vec,
            self.local_data.party_num_int as usize,
            self.phase_5d_decom2.clone(),
            &mut decommit5d_vec,
        );

        let phase_5a_decomm_vec_includes_i = (0..=self.local_data.threshold)
            .map(|i| {
                self.decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                    .0
                    .clone()
            })
            .collect::<Vec<Phase5ADecom1>>();
        let s_i = self
            .local_sig
            .phase5d(
                &decommit5d_vec,
                &self.commit5c_vec,
                &phase_5a_decomm_vec_includes_i,
            )
            .expect("bad com 5d");

        self.local_data.out
            .send(Message {
                from: self.local_data.party_num_int,
                to: 0,
                round: "round9".to_string(),
                data: serde_json::to_string(&s_i.clone()).unwrap(),
                sender_uuid: self.local_data.uuid.clone(),
                is_broadcast: true,
            })
            .expect("fail to send msg out");

        return Ok(Round9 {
            local_data: self.local_data,
            local_sig: self.local_sig,
            s_i,
        });
    }
}

#[derive(Clone)]
pub struct Round9 {
    pub local_data: LocalParty,
    pub local_sig: LocalSignature, // 建议全局

    pub s_i: Scalar<Secp256k1>, // 只给round9用了
}

impl Round9 {
    pub fn update(self, round9_ans_vec: &Vec<String>) -> Result<CompletedOnlineStage> {
        let mut s_i_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        format_vec_from_reads(
            &round9_ans_vec,
            self.local_data.party_num_int as usize,
            self.s_i.clone(),
            &mut s_i_vec,
        );

        s_i_vec.remove(usize::from(self.local_data.party_num_int - 1));
        let sig = self
            .local_sig
            .output_signature(&s_i_vec)
            .expect("verification failed");

        // println!(
        //     "party {:?} Output Signature: \n",
        //     self.local_data.party_num_int
        // );
        // println!("R: {:?}", sig.r);
        // println!("s: {:?} \n", sig.s);
        // println!("recid: {:?} \n", sig.recid.clone());

        self.local_data.end.send(sig.clone()).expect("fail to send signature out");

        return Ok(CompletedOnlineStage { sig });
    }
}

#[derive(Clone)]
pub struct CompletedOnlineStage {
    pub sig: SignatureRecid,
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a [String],
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j += 1;
        }
    }
}

#[derive(Clone)]
pub enum OnlineR {
    R0(Round0),
    R1(Round1),
    R2(Round2),
    R3(Round3),
    R4(Round4),
    R5(Round5),
    R6(Round6),
    R7(Round7),
    R8(Round8),
    R9(Round9),
    Finished(CompletedOnlineStage),
    Gone,
}

// #[derive(Copy, PartialEq, Eq, Clone, Debug)]
// pub enum Error {
//     InvalidKey,
//     InvalidSS,
//     InvalidCom,
//     InvalidSig,
//     Phase5BadSum,
//     Phase6Error,
// }

type Result<T, E = Error> = std::result::Result<T, E>;
#[derive(Debug, Error)]
pub enum Error {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(ErrorType),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: verify proof: {0:?}")]
    Round6VerifyProof(ErrorType),
    #[error("round 6: check sig: {0:?}")]
    Round6CheckSig(ErrorType),
    #[error("round 7: {0:?}")]
    Round7(ErrorType),
    #[error("round 8: {0:?}")]
    Round8(ErrorType),
    #[error("round 9: {0:?}")]
    Round9(ErrorType),
}

#[derive(Clone, Debug)]
pub struct ErrorType {
    error_type: String,
    bad_actors: Vec<usize>,
}
