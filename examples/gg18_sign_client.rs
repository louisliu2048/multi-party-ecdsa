#![allow(non_snake_case)]

use curv::arithmetic::Converter;
use curv::BigInt;
use reqwest::Client;
use std::sync::mpsc;
use std::{env, fs, time};
use std::sync::mpsc::Receiver;

mod common;
use common::{
    broadcast, check_sig, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params, PartySignup,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::keygen_rounds::LocalPartySaveData;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::msg::Message;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::SignatureRecid;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::sign_rounds::{LocalParty, OnlineR};

#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }

    let message_str = env::args().nth(3).unwrap_or_else(|| "".to_string());
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let message_bn = BigInt::from_bytes(message);

    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let local_data: LocalPartySaveData = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    //signup:
    let client = Client::new();
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let (msg_sender, msg_receiver) = mpsc::channel();
    let (end_sender, end_receiver) = mpsc::channel();

    let local_party:LocalParty = LocalParty::new(local_data, THRESHOLD, party_num_int, uuid.clone(),
                                  message_bn.clone(), msg_sender, end_sender);

    run_tss_sign(local_party, client, msg_receiver, end_receiver)
}

fn run_tss_sign(local_party: LocalParty, client: Client, msg_receiver: Receiver<Message>, end_receiver: Receiver<SignatureRecid>) {
    // delay:
    let delay = time::Duration::from_millis(15);

    let threshold = local_party.threshold.clone();
    let party_num_int = local_party.party_num_int.clone();
    let uuid = local_party.uuid.clone();
    let message_bn = local_party.message_bn.clone();
    let y_sum = local_party.data.y_sum.clone();

    // ====== start
    let mut next_state: OnlineR;
    next_state = local_party.start().map(OnlineR::R0).unwrap();

    // ====== round0 - round9
    let mut isBroadcast: bool = true;
    let mut round_ans_vec: Vec<String>;
    let mut cnt: u16 = 0;
    let mut round_name : String = "round0".to_string();
    loop {
        cnt = 0;
        loop {
           let msg: Message= msg_receiver.recv().unwrap();
            round_name = msg.round.clone();
            isBroadcast = msg.is_broadcast;
            if msg.is_broadcast {
                assert!(broadcast(
                    &client,
                    msg.from,
                    msg.round.as_str(),
                    msg.data,
                    msg.sender_uuid.clone()
                ).is_ok());
                break;
            } else {
                cnt += 1;
                assert!(sendp2p(
                    &client,
                    msg.from,
                    msg.to,
                    msg.round.as_str(),
                    msg.data,
                    msg.sender_uuid
                ).is_ok());

                if cnt == threshold{
                    break;
                }
            }
        }

        if isBroadcast {
            round_ans_vec = poll_for_broadcasts(
                &client,
                party_num_int,
                threshold + 1,
                delay,
                round_name.as_str(),
                uuid.clone(),
            );
        } else {
            round_ans_vec = poll_for_p2p(
                &client,
                party_num_int,
                threshold + 1,
                delay,
                round_name.as_str(),
                uuid.clone(),
            );
        }

        match next_state {
            OnlineR::R0(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R1).unwrap();
            }
            OnlineR::R1(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R2).unwrap();
            }
            OnlineR::R2(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R3).unwrap();
            }
            OnlineR::R3(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R4).unwrap();
            }
            OnlineR::R4(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R5).unwrap();
            }
            OnlineR::R5(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R6).unwrap();
            }
            OnlineR::R6(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R7).unwrap();
            }
            OnlineR::R7(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R8).unwrap();
            }
            OnlineR::R8(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::R9).unwrap();
            }
            OnlineR::R9(round) => {
                next_state = round.update(&round_ans_vec).map(OnlineR::Finished).unwrap();
            }
            s @ OnlineR::Finished(_) | s @ OnlineR::Gone => {
                break;
            }
        }

        if matches!(&next_state, OnlineR::Finished(_)) {
            break;
        }
    }

    // ====== finalize
    let sig: SignatureRecid = end_receiver.recv().unwrap();
    // check sig against secp256k1
    check_sig(&sig.r, &sig.s, &message_bn.clone(), &y_sum);

    // let sign_json = serde_json::to_string(&(
    //     "r",
    //     BigInt::from_bytes(sig.r.to_bytes().as_ref()).to_str_radix(16),
    //     "s",
    //     BigInt::from_bytes(sig.s.to_bytes().as_ref()).to_str_radix(16),
    // ))
    //     .unwrap();

    // fs::write("signature".to_string(), sign_json).expect("Unable to save !");
}

pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-sign".to_string();

    let res_body = postb(client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
