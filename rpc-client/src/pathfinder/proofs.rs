use serde::{Deserialize, Serialize};
// use starknet_os::config::DEFAULT_STORAGE_TREE_HEIGHT;
// use starknet_os::crypto::pedersen::PedersenHash;
// use starknet_os::crypto::poseidon::PoseidonHash;
// use starknet_os::starkware_utils::commitment_tree::base_types::{Height, Length, NodePath};
// use starknet_os::starkware_utils::commitment_tree::patricia_tree::nodes::{BinaryNodeFact, EdgeNodeFact};
// use starknet_os::storage::dict_storage::DictStorage;
// use starknet_os::storage::storage::{Fact, HashFunctionType};
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, Poseidon, StarkHash};
use num_bigint::BigInt;

use crate::SimpleHashFunction;
pub const DEFAULT_STORAGE_TREE_HEIGHT: u64 = 251;

#[derive(Debug, Copy, Clone, PartialEq, Default, Eq, Hash, Serialize, Deserialize)]
pub struct Height(pub u64);
use cairo_vm::Felt252;
use starknet_os_types::hash::Hash;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct EdgePath {
    pub len: u64,
    pub value: Felt,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum TrieNode {
    #[serde(rename = "binary")]
    Binary { 
        left: Felt, 
        right: Felt,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
    #[serde(rename = "edge")]
    Edge { 
        child: Felt, 
        path: EdgePath,
        #[serde(skip_serializing_if = "Option::is_none")]
        node_hash: Option<Felt>,
    },
}

// TODO: the hashing is not right here, solve this before proceeding
impl TrieNode {
    pub fn hash<H: SimpleHashFunction>(&self) -> Hash {
        match self {
            TrieNode::Binary { left, right, node_hash: _ } => {
                H::hash(left, right)
            }
            TrieNode::Edge { child, path, node_hash: _ } => {
                // For edge nodes, we hash the child with the path value
                // This is a simplified implementation
                let bottom_path_hash = H::hash(child, &path.value);
                let hash_value = Felt252::from_bytes_be_slice(&bottom_path_hash) + path.len;
                Hash::from_bytes_be(hash_value.to_bytes_le())
            }
        }
    }

    pub fn node_hash(&self) -> Option<Felt> {
        match self {
            TrieNode::Binary { node_hash, .. } => *node_hash,
            TrieNode::Edge { node_hash, .. } => *node_hash,
        }
    }
}

// impl TrieNode {
//     pub fn hash<H: HashFunctionType>(&self) -> Felt {
//         match self {
//             TrieNode::Binary { left, right } => {
//                 let fact = BinaryNodeFact::new((*left).into(), (*right).into())
//                     .expect("storage proof endpoint gave us an invalid binary node");
//
//                 // TODO: the hash function should probably be split from the Fact trait.
//                 //       we use a placeholder for the Storage trait in the meantime.
//                 Felt::from(<BinaryNodeFact as Fact<DictStorage, H>>::hash(&fact))
//             }
//             TrieNode::Edge { child, path } => {
//                 let fact = EdgeNodeFact::new((*child).into(), NodePath(path.value.to_biguint()), Length(path.len))
//                     .expect("storage proof endpoint gave us an invalid edge node");
//                 // TODO: the hash function should probably be split from the Fact trait.
//                 //       we use a placeholder for the Storage trait in the meantime.
//                 Felt::from(<EdgeNodeFact as Fact<DictStorage, H>>::hash(&fact))
//             }
//         }
//     }
// }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ContractData {
    /// Root of the Contract state tree
    pub root: Felt,
    /// The proofs associated with the queried storage values
    pub storage_proofs: Vec<Vec<TrieNode>>,
}

#[derive(thiserror::Error, Debug)]
pub enum ProofVerificationError<'a> {
    #[error("Non-inclusion proof for key {}. Height {}.", key.to_hex_string(), height.0)]
    NonExistenceProof { key: Felt, height: Height, proof: &'a [TrieNode] },

    #[error("Proof verification failed, node_hash {node_hash:x} != parent_hash {parent_hash:x}")]
    InvalidChildNodeHash { node_hash: Felt, parent_hash: Felt },

    #[error("Proof is empty")]
    EmptyProof,

    #[error("Conversion error")]
    ConversionError,
}

pub struct PedersenHash;
impl SimpleHashFunction for PedersenHash {
    fn hash(left: &Felt, right: &Felt) -> Hash {
        Hash::from_bytes_be(Pedersen::hash(left, right).to_bytes_le())
    }
}

/// Implementation for Poseidon hash
pub struct PoseidonHash;
impl SimpleHashFunction for PoseidonHash {
    fn hash(left: &Felt, right: &Felt) -> Hash {
        Hash::from_bytes_be(Poseidon::hash(left, right).to_bytes_le())
    }
}

impl ContractData {
    /// Verifies that each contract state proof is valid.
    pub fn verify(&self, storage_keys: &[Felt]) -> Result<(), Vec<ProofVerificationError>> {
        let mut errors = vec![];

        for (index, storage_key) in storage_keys.iter().enumerate() {
            if let Err(e) = verify_proof::<PedersenHash>(*storage_key, self.root, &self.storage_proofs[index]) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Verify the storage proofs and handle errors.
/// Returns a list of additional keys to fetch to fill gaps in the tree that will make the OS
/// crash otherwise.
/// This function will panic if the proof contains an invalid node hash (i.e. the hash of a child
/// node does not match the one specified in the parent).
pub fn verify_storage_proof(contract_data: &ContractData, keys: &[Felt]) -> Vec<Felt> {
    let mut additional_keys = vec![];
    if let Err(errors) = contract_data.verify(keys) {
        for error in errors {
            match error {
                ProofVerificationError::NonExistenceProof { key, height, proof } => {
                    if let Some(TrieNode::Edge { child: _, path, .. }) = proof.last() {
                        if height.0 < DEFAULT_STORAGE_TREE_HEIGHT {
                            let modified_key = get_key_following_edge(key, height, path);
                            log::trace!(
                                "Fetching modified key {} for key {}",
                                modified_key.to_hex_string(),
                                key.to_hex_string()
                            );
                            additional_keys.push(modified_key);
                        }
                    }
                }
                _ => {
                    panic!("Proof verification failed: {}", error);
                }
            }
        }
    }

    additional_keys
}


/// Returns a modified key that follows the specified edge path.
/// This function is used to work around an issue where the OS fails if it encounters a
/// write to 0 and the last node in the storage proof is an edge node of length 1.
/// In this situation the OS will still look up the node in the preimage and will fail
/// on a "Edge bottom not found in preimage" error.
/// To resolve this, we fetch the storage proof for a node that follows this edge in order
/// to get the bottom node in the preimage and resolve the issue.
///
/// For example, if following a key 0x00A0 we encounter an edge 0xB0 starting from height 8
/// to height 4 (i.e. the length of the edge is 4), then the bottom node of the edge will
/// not be included in the proof as the key does not follow the edge. We need to compute a key
/// that will follow the edge in order to get that bottom node. For example, the key 0x00B0 will
/// follow that edge.
///
/// An important note is that heigh = 0 at the level of leaf nodes (as opposed to the rest of the OS)
///
/// To achieve this, we zero the part of the key at the height of the edge and then replace it
/// with the path of the edge. This is achieved with bitwise operations. For our example,
/// this function will compute the new key as `(key & 0xFF0F) | 0x00B0`.
fn get_key_following_edge(key: Felt, height: Height, edge_path: &EdgePath) -> Felt {
    assert!(height.0 < DEFAULT_STORAGE_TREE_HEIGHT);

    let shift = height.0;
    let clear_mask = ((BigInt::from(1) << edge_path.len) - BigInt::from(1)) << shift;
    let mask = edge_path.value.to_bigint() << shift;
    let new_key = (key.to_bigint() & !clear_mask) | mask;

    Felt::from(new_key)
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct PathfinderProof {
    pub state_commitment: Option<Felt>,
    pub contract_commitment: Felt,
    pub class_commitment: Option<Felt>,
    pub contract_proof: Vec<TrieNode>,
    pub contract_data: Option<ContractData>,
}

#[allow(dead_code)]
#[derive(Clone, Deserialize)]
pub struct PathfinderClassProof {
    pub class_commitment: Felt,
    pub class_proof: Vec<TrieNode>,
}


/// This function goes through the tree from top to bottom and verifies that
/// the hash of each node is equal to the corresponding hash in the parent node.
pub fn verify_proof<H: SimpleHashFunction>(
    key: Felt,
    commitment: Felt,
    proof: &[TrieNode],
) -> Result<(), ProofVerificationError> {
    let bits = key.to_bits_be();

    let mut parent_hash = commitment;

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;

    for node in proof.iter() {
        println!("the node here is: {:?}", node);
        let node_hash = Felt::from(node.hash::<H>());
        if node_hash != parent_hash {
            return Err(ProofVerificationError::InvalidChildNodeHash { node_hash, parent_hash });
        }

        match node {
            TrieNode::Binary { left, right, .. } => {
                parent_hash = if bits[index as usize] { *right } else { *left };
                index += 1;
            }
            TrieNode::Edge { child, path, .. } => {
                let path_len_usize: usize = path.len.try_into().map_err(|_| ProofVerificationError::ConversionError)?;
                let index_usize: usize = index.try_into().map_err(|_| ProofVerificationError::ConversionError)?;

                let path_bits = path.value.to_bits_be();
                let relevant_path_bits = &path_bits[path_bits.len() - path_len_usize..];
                let key_bits_slice = &bits[index_usize..(index_usize + path_len_usize)];

                parent_hash = *child;
                index += path.len;

                if relevant_path_bits != key_bits_slice {
                    // If paths don't match, we've found a proof of non-membership because:
                    // 1. We correctly moved towards the target as far as possible, and
                    // 2. Hashing all the nodes along the path results in the root hash, which means
                    // 3. The target definitely does not exist in this tree
                    return Err(ProofVerificationError::NonExistenceProof {
                        key,
                        height: Height(DEFAULT_STORAGE_TREE_HEIGHT - (index - start)),
                        proof,
                    });
                }
            }
        }
    }

    Ok(())
}

impl PathfinderClassProof {
    pub fn verify(&self, class_hash: Felt) -> Result<(), ProofVerificationError> {
        verify_proof::<PoseidonHash>(class_hash, self.class_commitment()?, &self.class_proof)
    }

    /// Gets the "class_commitment" which is aka the root node of the class Merkle tree.
    /// Pathfinder used to provide this explicitly, but stopped doing so in #2452:
    ///
    /// https://github.com/eqlabs/pathfinder/pull/2452
    ///
    /// However, the proof should always start with the root node, which means all we have
    /// to do is hash the first node in the proof to get the same thing.
    ///
    /// NOTE: the v0.8 RPC spec does NOT require the proof to be in order, in which case it is
    ///       much trickier to guess what the root node is.
    pub fn class_commitment(&self) -> Result<Felt, ProofVerificationError> {
        if !self.class_proof.is_empty() {
            let hash = self.class_proof[0].hash::<PoseidonHash>();
            Ok(hash.into())
        } else {
            Err(ProofVerificationError::EmptyProof) // TODO: give an error type or change fn return type
        }
    }
}