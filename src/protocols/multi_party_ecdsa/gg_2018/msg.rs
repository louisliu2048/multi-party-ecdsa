use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message {
    pub from: u16,
    pub to: u16,
    pub round: String,
    pub data: String,
    pub sender_uuid: String,
    pub is_broadcast: bool
}
