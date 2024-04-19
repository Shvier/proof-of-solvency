use serde::{Deserialize, Serialize};

pub(crate) mod gadgets;

#[derive(Serialize, Deserialize)]
pub(crate) struct BenchConfig {
    num_of_users: u32,
    num_of_bits: u32,
    num_of_groups: usize,
}
