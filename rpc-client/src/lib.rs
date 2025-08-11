pub mod client;
pub mod pathfinder;
pub mod state_reader;
mod utils;
mod types;

pub use client::RpcClient;

use starknet_types_core::felt::Felt;
use starknet_os_types::hash::Hash;

/// Simplified hash function trait for our use case
pub trait SimpleHashFunction {
    fn hash(left: &Felt, right: &Felt) -> Hash;
}
