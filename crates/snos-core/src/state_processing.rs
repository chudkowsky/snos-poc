use std::collections::{BTreeMap, HashMap};
use starknet_types_core::felt::Felt;
use starknet::core::types::{BlockId, MaybePendingStateUpdate, TransactionTraceWithHash};
use starknet::providers::Provider;
use starknet_api::core::{ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::state::StorageKey;
use starknet_os::io::os_input::{CachedStateInput, OsBlockInput};
use starknet_os_types::deprecated_compiled_class::GenericDeprecatedCompiledClass;
use starknet_os_types::casm_contract_class::GenericCasmContractClass;

use rpc_client::RpcClient;

/// Represents the previous BlockId for the current scope
/// Defaults to None when the current BlockId is 0
pub type PreviousBlockId = Option<BlockId>;

/// Error type for state processing operations
#[derive(Debug, thiserror::Error)]
pub enum StateProcessingError {
    #[error("RPC Error: {0}")]
    RpcError(#[from] starknet::providers::ProviderError),
    #[error("State processing error: {0}")]
    ProcessingError(String),
}

/// Formatted state update adapted for the new structure
/// This replaces the old FormattedStateUpdate to work with the new hierarchical input
/// Note: Removed Clone derive because CachedStateInput doesn't implement Clone
#[derive(Debug)]
pub struct ProcessedStateUpdate {
    /// Data for CachedStateInput
    pub cached_state_input: CachedStateInput,
    /// Compiled classes for StarknetOsInput (Sierra/CASM)  
    pub compiled_classes: BTreeMap<ClassHash, GenericCasmContractClass>,
    /// Deprecated compiled classes for StarknetOsInput (Cairo 0)
    pub deprecated_compiled_classes: BTreeMap<ClassHash, GenericDeprecatedCompiledClass>,
    /// Data for OsBlockInput - declared class component hashes
    pub declared_class_hash_component_hashes: HashMap<ClassHash, Vec<Felt>>, // Simplified for now
}

/// Port of the get_formatted_state_update function adapted for new structure
/// 
/// Original location: ../snos/crates/bin/prove_block/src/state_utils.rs:31-92
/// 
/// This function:
/// 1. Fetches transaction traces and state updates from RPC
/// 2. Processes the data into the new hierarchical structure
/// 3. Returns data ready for OsBlockInput and CachedStateInput
pub async fn get_processed_state_update(
    rpc_client: &RpcClient,
    previous_block_id: PreviousBlockId,
    block_id: BlockId,
) -> Result<(ProcessedStateUpdate, Vec<TransactionTraceWithHash>), StateProcessingError> {
    // Step 1: Get transaction traces (same as old implementation)
    let traces = rpc_client
        .starknet_rpc()
        .trace_block_transactions(block_id)
        .await
        .map_err(StateProcessingError::RpcError)?;

    // Step 2: Process state updates if we have a previous block
    if let Some(previous_block_id) = previous_block_id {
        // Get state update from RPC
        let state_update = match rpc_client
            .starknet_rpc()
            .get_state_update(block_id)
            .await
            .map_err(StateProcessingError::RpcError)?
        {
            MaybePendingStateUpdate::Update(update) => update,
            MaybePendingStateUpdate::PendingUpdate(_) => {
                return Err(StateProcessingError::ProcessingError(
                    "Block is still pending!".to_string(),
                ));
            }
        };

        let state_diff = state_update.state_diff;

        // Step 3: Build the new CachedStateInput structure
        let mut cached_state_input = CachedStateInput {
            storage: HashMap::new(),
            address_to_class_hash: HashMap::new(),
            address_to_nonce: HashMap::new(),
            class_hash_to_compiled_class_hash: HashMap::new(),
        };

        // Process storage changes from state_diff
        // Fix: Correct iteration over ContractStorageDiffItem
        for storage_diff_item in state_diff.storage_diffs {
            let contract_address = storage_diff_item.address;
            let storage_updates = storage_diff_item.storage_entries;
            
            let mut contract_storage = HashMap::new();
            for storage_entry in storage_updates {
                let storage_key = StorageKey::try_from(storage_entry.key)
                    .map_err(|e| StateProcessingError::ProcessingError(format!("Invalid storage key: {}", e)))?;
                contract_storage.insert(storage_key, storage_entry.value);
            }
            if !contract_storage.is_empty() {
                let contract_addr = ContractAddress::try_from(contract_address)
                    .map_err(|e| StateProcessingError::ProcessingError(format!("Invalid contract address: {}", e)))?;
                cached_state_input.storage.insert(contract_addr, contract_storage);
            }
        }

        // Process deployed contracts
        for deployed_contract in state_diff.deployed_contracts {
            let contract_addr = ContractAddress::try_from(deployed_contract.address)
                .map_err(|e| StateProcessingError::ProcessingError(format!("Invalid contract address: {}", e)))?;
            let class_hash = ClassHash(deployed_contract.class_hash);
            cached_state_input.address_to_class_hash.insert(contract_addr, class_hash);
        }

        // Process replaced classes
        for replaced_class in state_diff.replaced_classes {
            let contract_addr = ContractAddress::try_from(replaced_class.contract_address)
                .map_err(|e| StateProcessingError::ProcessingError(format!("Invalid contract address: {}", e)))?;
            let class_hash = ClassHash(replaced_class.class_hash);
            cached_state_input.address_to_class_hash.insert(contract_addr, class_hash);
        }

        // Process nonce updates
        // Fix: Correct iteration over NonceUpdate
        for nonce_update in state_diff.nonces {
            let contract_address = nonce_update.contract_address;
            let nonce = nonce_update.nonce;
            
            let contract_addr = ContractAddress::try_from(contract_address)
                .map_err(|e| StateProcessingError::ProcessingError(format!("Invalid contract address: {}", e)))?;
            cached_state_input.address_to_nonce.insert(contract_addr, Nonce(nonce));
        }

        // Process declared classes - this is simplified for now
        // TODO: In the full implementation, we need to:
        // 1. Fetch contract classes from RPC 
        // 2. Compile Sierra classes to CASM
        // 3. Process deprecated classes
        // 4. Build component hashes
        let mut class_hash_to_compiled_class_hash = HashMap::new();
        let mut declared_class_hash_component_hashes = HashMap::new();
        
        for declared_class in &state_diff.declared_classes {
            let class_hash = ClassHash(declared_class.class_hash);
            let compiled_class_hash = CompiledClassHash(declared_class.compiled_class_hash);
            class_hash_to_compiled_class_hash.insert(class_hash, compiled_class_hash);
            
            // TODO: Process component hashes - simplified for now
            declared_class_hash_component_hashes.insert(class_hash, vec![declared_class.class_hash]);
        }

        cached_state_input.class_hash_to_compiled_class_hash = class_hash_to_compiled_class_hash;

        // TODO: Build compiled_classes and deprecated_compiled_classes
        // This requires significant logic from the old implementation
        let compiled_classes = BTreeMap::new();
        let deprecated_compiled_classes = BTreeMap::new();

        Ok((
            ProcessedStateUpdate {
                cached_state_input,
                compiled_classes,
                deprecated_compiled_classes,
                declared_class_hash_component_hashes,
            },
            traces,
        ))
    } else {
        // Genesis block case - return empty data
        Ok((
            ProcessedStateUpdate {
                cached_state_input: CachedStateInput::default(),
                compiled_classes: BTreeMap::new(),
                deprecated_compiled_classes: BTreeMap::new(),
                declared_class_hash_component_hashes: HashMap::new(),
            },
            traces,
        ))
    }
}

/// Helper function to create OsBlockInput with processed state data
/// 
/// This combines state processing with other block data to create a complete OsBlockInput
pub fn create_os_block_input_with_state(
    _processed_state: &ProcessedStateUpdate,
    _block_number: u64,
    // TODO: Add other required parameters:
    // - block_info: BlockInfo
    // - transactions: Vec<Transaction>
    // - tx_execution_infos: Vec<CentralTransactionExecutionInfo>
    // - prev_block_hash: BlockHash
    // - new_block_hash: BlockHash
    // - commitment info from our commitment_utils
) -> OsBlockInput {
    // TODO: Complete implementation with real block data
    // For now, return a default instance to keep the code compiling
    OsBlockInput::default()
}

/// Helper function to create a complete CachedStateInput
/// 
/// This can combine multiple state updates if needed
pub fn merge_cached_state_inputs(inputs: &[CachedStateInput]) -> CachedStateInput {
    let mut merged = CachedStateInput {
        storage: HashMap::new(),
        address_to_class_hash: HashMap::new(),
        address_to_nonce: HashMap::new(),
        class_hash_to_compiled_class_hash: HashMap::new(),
    };

    for input in inputs {
        // Merge storage
        for (address, storage) in &input.storage {
            merged.storage.entry(*address).or_default().extend(storage.clone());
        }

        // Merge other mappings (later entries overwrite earlier ones)
        merged.address_to_class_hash.extend(&input.address_to_class_hash);
        merged.address_to_nonce.extend(&input.address_to_nonce);
        merged.class_hash_to_compiled_class_hash.extend(&input.class_hash_to_compiled_class_hash);
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_cached_state_inputs_empty() {
        let merged = merge_cached_state_inputs(&[]);
        assert!(merged.storage.is_empty());
        assert!(merged.address_to_class_hash.is_empty());
        assert!(merged.address_to_nonce.is_empty());
        assert!(merged.class_hash_to_compiled_class_hash.is_empty());
    }

    #[test]
    fn test_processed_state_update_structure() {
        let processed = ProcessedStateUpdate {
            cached_state_input: CachedStateInput::default(),
            compiled_classes: BTreeMap::new(),
            deprecated_compiled_classes: BTreeMap::new(),
            declared_class_hash_component_hashes: HashMap::new(),
        };
        
        // Test that structure is correctly organized
        assert!(processed.compiled_classes.is_empty());
        assert!(processed.deprecated_compiled_classes.is_empty());
    }

    // TODO: Add integration tests with RPC client
    // This would require setting up test infrastructure
}

// TODO: Functions to implement for full functionality:
// 1. get_subcalled_contracts_from_tx_traces() - Extract contract addresses from traces
// 2. build_compiled_class_and_maybe_update_class_hash_to_compiled_class_hash() - Class compilation
// 3. format_declared_classes() - Format declared classes for OS consumption
// 4. compile_contract_class() - Compile Sierra to CASM
// 5. Full integration with commitment_utils for creating complete OsBlockInput 