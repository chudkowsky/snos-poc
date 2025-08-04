mod api_to_blockifier_conversion;
mod rpc_utils;
mod commitment_utils;
mod state_update;

use std::collections::{BTreeMap, HashMap};
use blockifier::blockifier::config::TransactionExecutorConfig;
use blockifier::blockifier::transaction_executor::{TransactionExecutor, TransactionExecutorError};
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use cairo_vm::types::layout_name::LayoutName;
use starknet_api::core::{ChainId, ClassHash, CompiledClassHash, ContractAddress, Nonce};
use starknet_api::deprecated_contract_class::ContractClass;
use cairo_lang_starknet_classes::casm_contract_class::CasmContractClass;
use starknet::core::types::{L1DataAvailabilityMode, MaybePendingStateUpdate};
use starknet::providers::{Provider, ProviderError};
use starknet_api::state::StorageKey;
use starknet_os::{
    hint_processor::panicking_state_reader::PanickingStateReader,
    io::os_input::{OsBlockInput, OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os,
};
use blockifier::context::{BlockContext, ChainInfo, FeeTokenAddresses};
use blockifier::test_utils::maybe_dummy_block_hash_and_number;
use blockifier::transaction::objects::TransactionExecutionInfo;
use starknet_os::io::os_input::{CachedStateInput, CommitmentInfo, ContractClassComponentHashes};
use rpc_client::RpcClient;
use rpc_client::state_reader::AsyncRpcStateReader;
use starknet_types_core::felt::Felt;


use starknet::core::types::{BlockId, MaybePendingBlockWithTxHashes, MaybePendingBlockWithTxs, StarknetError, BlockWithTxs, Transaction};
use starknet_api::block::{BlockHash, BlockHashAndNumber, BlockInfo, BlockNumber, BlockTimestamp, GasPrice, GasPrices, GasPriceVector, StarknetVersion};
use starknet_api::{contract_address, felt, patricia_key};
use blockifier::transaction::transaction_execution::Transaction as BlockifierTransaction;
use cairo_vm::Felt252;
use shared_execution_objects::central_objects::CentralTransactionExecutionInfo;
use starknet_patricia::hash::hash_trait::HashOutput;
use starknet_patricia::patricia_merkle_tree::types::SubTreeHeight;
use crate::api_to_blockifier_conversion::starknet_rs_to_blockifier;


const DEFAULT_COMPILED_OS: &[u8] = include_bytes!("../build/os_0_14_0.json");
pub const STORED_BLOCK_HASH_BUFFER: u64 = 10;
use thiserror::Error;
use rpc_client::pathfinder::proofs::{PathfinderClassProof, PathfinderProof, ProofVerificationError};
use crate::commitment_utils::{format_commitment_facts, PedersenHash, PoseidonHash};
use crate::rpc_utils::{get_class_proofs, get_storage_proofs};
use crate::state_update::{get_formatted_state_update, get_subcalled_contracts_from_tx_traces};

#[derive(Error, Debug)]
pub enum FeltConversionError {
    #[error("Overflow Error: Felt exceeds u128 max value")]
    OverflowError,
    #[error("{0}")]
    CustomError(String),
}


fn compute_class_commitment(
    previous_class_proofs: &HashMap<Felt, PathfinderClassProof>,
    class_proofs: &HashMap<Felt, PathfinderClassProof>,
    previous_root: Felt,
    updated_root: Felt,
) -> CommitmentInfo {
    // TODO: verification is skipped for now, add it
    // for (class_hash, previous_class_proof) in previous_class_proofs {
    //     if let Err(e) = previous_class_proof.verify(*class_hash) {
    //         match e {
    //             ProofVerificationError::NonExistenceProof { .. } | ProofVerificationError::EmptyProof => {}
    //             _ => panic!("Previous class proof verification failed"),
    //         }
    //     }
    // }
    //
    // for (class_hash, class_proof) in class_proofs {
    //     if let Err(e) = class_proof.verify(*class_hash) {
    //         match e {
    //             ProofVerificationError::NonExistenceProof { .. } => {}
    //             _ => panic!("Current class proof verification failed"),
    //         }
    //     }
    // }

    let previous_class_proofs: Vec<_> = previous_class_proofs.values().cloned().collect();
    let class_proofs: Vec<_> = class_proofs.values().cloned().collect();

    let previous_class_proofs: Vec<_> = previous_class_proofs.into_iter().map(|proof| proof.class_proof).collect();
    let class_proofs: Vec<_> = class_proofs.into_iter().map(|proof| proof.class_proof).collect();

    let previous_class_commitment_facts = format_commitment_facts::<PoseidonHash>(&previous_class_proofs);
    let current_class_commitment_facts = format_commitment_facts::<PoseidonHash>(&class_proofs);

    let class_commitment_facts: HashMap<_, _> =
        previous_class_commitment_facts.into_iter().chain(current_class_commitment_facts)
        .map(|(k, v)| (HashOutput(k), v))
        .collect();

    log::debug!("previous class trie root: {}", previous_root.to_hex_string());
    log::debug!("current class trie root: {}", updated_root.to_hex_string());

    CommitmentInfo {  previous_root: HashOutput(previous_root), updated_root: HashOutput(updated_root), tree_height: SubTreeHeight(251), commitment_facts: class_commitment_facts }
}

pub fn chain_id_from_felt(felt: Felt) -> ChainId {
    // Skip leading zeroes
    let chain_id_bytes: Vec<_> = felt.to_bytes_be().into_iter().skip_while(|byte| *byte == 0u8).collect();
    let chain_id_str = String::from_utf8_lossy(&chain_id_bytes);
    ChainId::from(chain_id_str.into_owned())
}

pub fn build_block_context(
    chain_id: ChainId,
    block: &BlockWithTxs,
    starknet_version: StarknetVersion,
) -> Result<BlockContext, FeltConversionError> {
    let sequencer_address_hex = block.sequencer_address.to_hex_string();
    let sequencer_address = contract_address!(sequencer_address_hex.as_str());
    let use_kzg_da = match block.l1_da_mode {
        L1DataAvailabilityMode::Blob => true,
        L1DataAvailabilityMode::Calldata => false,
    };

    let block_info = BlockInfo {
        block_number: BlockNumber(block.block_number),
        block_timestamp: BlockTimestamp(block.timestamp),
        sequencer_address,
        gas_prices: GasPrices {
            // eth_l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_wei)?,
            // strk_l1_gas_price: felt_to_gas_price(&block.l1_gas_price.price_in_fri)?,
            // eth_l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_wei)?,
            // strk_l1_data_gas_price: felt_to_gas_price(&block.l1_data_gas_price.price_in_fri)?,
            eth_gas_prices: GasPriceVector::default(), //TODO: update the gas prices for the right block info
            strk_gas_prices: GasPriceVector::default()
        },
        use_kzg_da,
    };

    let chain_info = ChainInfo {
        chain_id,
        // cf. https://docs.starknet.io/tools/important-addresses/
        fee_token_addresses: FeeTokenAddresses {
            strk_fee_token_address: contract_address!(
                "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
            ),
            eth_fee_token_address: contract_address!(
                "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
            ),
        },
    };

    let versioned_constants = VersionedConstants::get(&starknet_version).expect("issue while getting version constant");
    let bouncer_config = BouncerConfig::max();

    Ok(BlockContext::new(block_info, chain_info, versioned_constants.clone(), bouncer_config))
}


async fn collect_single_block_info(block_number: u64, rpc_client: RpcClient, state_reader: AsyncRpcStateReader) -> (OsBlockInput, BTreeMap<ClassHash, CasmContractClass>, BTreeMap<ClassHash, ContractClass>) {
    println!("📋 collect_single_block_info: Starting for block {}", block_number);
    let block_id = BlockId::Number(block_number);
    let previous_block_id = if block_number == 0 { None } else { Some(BlockId::Number(block_number - 1)) };
    println!("⚙️  Block IDs configured: current={}, previous={:?}", block_number, previous_block_id.map(|id| format!("{:?}", id)).unwrap_or("None".to_string()));

    // Step 1: build the block context
    println!("🔗 Step 1: Getting chain ID...");
    let res = rpc_client.starknet_rpc().chain_id().await;
    println!("the result is: {:?}", res);
    let chain_id = chain_id_from_felt(res.expect("issue here"));
    log::debug!("provider's chain_id: {}", chain_id);
    println!("✅ Chain ID retrieved: {}", chain_id);
    
    println!("📦 Step 2: Fetching block with transactions...");
    let block_with_txs = match rpc_client.starknet_rpc().get_block_with_txs(block_id).await.expect("block with txns issue") {
        MaybePendingBlockWithTxs::Block(block_with_txs) => block_with_txs,
        MaybePendingBlockWithTxs::PendingBlock(_) => {
            panic!("Block is still pending!");
        }
    };
    println!("✅ Block with {} transactions fetched", block_with_txs.transactions.len());

    let starknet_version = StarknetVersion::V0_14_0; // TODO: get it from the txns itself
    log::debug!("Starknet version: {:?}", starknet_version);
    println!("🔢 Starknet version set to: {:?}", starknet_version);

    println!("⏮️  Step 3: Fetching previous block...");
    let previous_block = match previous_block_id {
        Some(previous_block_id) => match rpc_client.starknet_rpc().get_block_with_tx_hashes(previous_block_id).await.expect("block with txn hashes issue") {
            MaybePendingBlockWithTxHashes::Block(block_with_txs) => Some(block_with_txs),
            MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                panic!("Block is still pending!");
            }
        },
        None => None,
    };

    // We only need to get the older block number and hash. No need to fetch all the txs
    // This is a workaorund to catch the case where the block number is less than the buffer and still preserve the check
    // The OS will also handle the case where the block number is less than the buffer.
    let older_block_number =
        if block_number <= STORED_BLOCK_HASH_BUFFER { 0 } else { block_number - STORED_BLOCK_HASH_BUFFER };

    let older_block =
        match rpc_client.starknet_rpc().get_block_with_tx_hashes(BlockId::Number(older_block_number)).await.expect("issue with older block number indeed") {
            MaybePendingBlockWithTxHashes::Block(block_with_txs_hashes) => block_with_txs_hashes,
            MaybePendingBlockWithTxHashes::PendingBlock(_) => {
                panic!("Block is still pending!");
            }
        };
    let old_block_number = Felt::from(older_block.block_number);
    let old_block_hash = older_block.block_hash;

    println!("previous block: {:?}, older block: {:?}", previous_block, older_block);
    println!("✅ Previous and older blocks fetched");

    println!("🏗️  Step 4: Building block context...");
    let block_context = build_block_context(chain_id.clone(), &block_with_txs, starknet_version).expect("issue while building the context");
    println!("✅ Block context built successfully");
    
    println!("🔍 Step 5: Getting transaction traces...");
    let traces =
        rpc_client.starknet_rpc().trace_block_transactions(block_id).await.expect("Failed to get block tx traces");
    println!("✅ Got {} transaction traces", traces.len());

    // Extract other contracts used in our block from the block trace
    // We need this to get all the class hashes used and correctly feed address_to_class_hash
    println!("🔄 Step 6: Extracting accessed contracts and classes...");
    let (accessed_addresses, accessed_classes) = get_subcalled_contracts_from_tx_traces(&traces);
    println!("✅ Found {} accessed addresses and {} accessed classes", accessed_addresses.len(), accessed_classes.len());
    
    println!("the addressea are: {:?}", accessed_addresses);
    println!("the classes are: {:?}", accessed_classes);
    println!("📊 Step 7: Getting formatted state update...");
    let processed_state_update = get_formatted_state_update(&rpc_client, previous_block_id, block_id, accessed_addresses, accessed_classes).await.expect("issue while calling formatted state update");
    println!("✅ State update processed successfully");
    println!("🔄 Step 8: Converting transactions to blockifier format...");
    let mut txs = Vec::new();
    for (i, (tx, trace)) in block_with_txs.transactions.iter().zip(traces.iter()).enumerate() {
        let transaction =
            starknet_rs_to_blockifier(tx, trace, &block_context.block_info().gas_prices, &rpc_client, block_number, chain_id.clone())
                .await.expect("core to blockifier txn failed");
        txs.push(transaction);
        if (i + 1) % 10 == 0 || i == block_with_txs.transactions.len() - 1 {
            println!("  📝 Converted {}/{} transactions", i + 1, block_with_txs.transactions.len());
        }
    }
    println!("✅ All transactions converted to blockifier format");

    let blockifier_txns: Vec<_> = txs.iter().map(|txn_result| txn_result.blockifier_tx.clone()).collect();
    let starknet_api_txns: Vec<_> = txs.iter().map(|txn_result| txn_result.starknet_api_tx.clone()).collect();

    let block_number_hash_pair= maybe_dummy_block_hash_and_number(block_context.block_info().block_number);

    println!("⚡ Step 9: Creating transaction executor...");
    let config = TransactionExecutorConfig::default();
    let blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), previous_block_id.expect("previous block id is required"));
    let mut executor = TransactionExecutor::pre_process_and_create(
        blockifier_state_reader,
        block_context.clone(),
        block_number_hash_pair,
        config,
    )
        .expect("Failed to create transaction executor.");
    println!("✅ Transaction executor created");
        
    println!("🔥 Step 10: Executing {} transactions...", blockifier_txns.len());
    let execution_deadline = None;
    let execution_outputs: Vec<_> = executor
        .execute_txs(&blockifier_txns, execution_deadline)
        .into_iter()
        .collect::<Result<_, TransactionExecutorError>>()
        .expect("Unexpected error during execution.");
    println!("✅ All transactions executed successfully");

    let txn_execution_infos: Vec<TransactionExecutionInfo> = execution_outputs
        .into_iter()
        .map(|(execution_info, _)| execution_info)
        .collect();

    let central_txn_execution_infos: Vec<CentralTransactionExecutionInfo> = txn_execution_infos.clone()
        .into_iter()
        .map(|execution_info| execution_info.clone().into())
        .collect();

    println!("🗃️  Step 11: Fetching storage proofs...");
    let storage_proofs = get_storage_proofs(&rpc_client, block_number, &txn_execution_infos, old_block_number)
        .await
        .expect("Failed to fetch storage proofs");
    println!("✅ Got {} storage proofs", storage_proofs.len());

    println!("📚 Step 12: Fetching previous storage proofs...");
    let previous_storage_proofs = match previous_block_id {
        Some(BlockId::Number(previous_block_id)) => {
            get_storage_proofs(&rpc_client, previous_block_id, &txn_execution_infos, old_block_number)
                .await
                .expect("Failed to fetch storage proofs")
        }
        None => get_storage_proofs(&rpc_client, 0, &txn_execution_infos, old_block_number)
            .await
            .expect("Failed to fetch storage proofs"),
        _ => {
            let mut map = HashMap::new();
            // We add a default proof for the block hash contract
            map.insert(
                Felt::ONE,
                PathfinderProof {
                    state_commitment: Default::default(),
                    class_commitment: None,
                    contract_proof: Vec::new(),
                    contract_data: None,
                },
            );
            map
        }
    };
    println!("✅ Got {} previous storage proofs", previous_storage_proofs.len());

    println!("🏭 Step 13: Processing contract storage commitments...");
    let mut contract_address_to_class_hash = HashMap::new();
    let mut address_to_storage_commitment_info: HashMap<ContractAddress, CommitmentInfo> = HashMap::new();

    for (contract_address, storage_proof) in storage_proofs.clone() {
        let contract_address: Felt  = contract_address;
        let previous_storage_proof =
            previous_storage_proofs.get(&contract_address).expect("failed to find previous storage proof");
        let previous_contract_commitment_facts = format_commitment_facts::<PedersenHash>(&vec![previous_storage_proof.contract_proof.clone()]);
        let current_contract_commitment_facts = format_commitment_facts::<PedersenHash>(&vec![storage_proof.contract_proof.clone()]);
        let global_contract_commitment_facts: HashMap<HashOutput, Vec<Felt252>> =
            previous_contract_commitment_facts
                .into_iter()
                .chain(current_contract_commitment_facts)
                .map(|(key, value)| (HashOutput(key.into()), value))
                .collect();

        let previous_contract_storage_root: Felt = previous_storage_proof
            .contract_data
            .as_ref()
            .map(|contract_data| contract_data.root)
            .unwrap_or(Felt::ZERO)
            .into();

        let current_contract_storage_root: Felt = storage_proof
            .contract_data
            .as_ref()
            .map(|contract_data| contract_data.root)
            .unwrap_or(Felt::ZERO)
            .into();

        let contract_state_commitment_info = CommitmentInfo {
            previous_root: HashOutput(previous_contract_storage_root),
            updated_root: HashOutput(current_contract_storage_root),
            tree_height: SubTreeHeight(251),
            commitment_facts: global_contract_commitment_facts,
        };

        address_to_storage_commitment_info.insert(ContractAddress::try_from(contract_address).unwrap(), contract_state_commitment_info);

        log::debug!(
            "Storage root 0x{:x} for contract 0x{:x}",
            Into::<Felt252>::into(previous_contract_storage_root),
            contract_address
        );
        println!("the contract address: {:?} and the block-id: {:?}", contract_address, block_id);
        
        // TODO: Check this special case handling once again - why does contract address 0x1 need class hash 0x0?
        let class_hash = if contract_address == Felt::ONE {
            println!("🔧 Special case: Contract address 0x1 detected, setting class hash to 0x0 without RPC call");
            Felt::ZERO
        } else {
            rpc_client.starknet_rpc().get_class_hash_at(block_id, contract_address).await.expect("issue with the class hash thingy")
        };
        
        contract_address_to_class_hash.insert(contract_address, class_hash);

    }
    println!("✅ Processed {} contract storage commitments", address_to_storage_commitment_info.len());

    let compiled_classes = processed_state_update.compiled_classes;
    let deprecated_compiled_classes = processed_state_update.deprecated_compiled_classes;
    let declared_class_hash_component_hashes: HashMap<ClassHash, ContractClassComponentHashes> = processed_state_update
        .declared_class_hash_component_hashes
        .into_iter()
        .map(|(class_hash, component_hashes)| (ClassHash(class_hash), component_hashes.to_os_format()))
        .collect();

    let class_hash_to_compiled_class_hash = processed_state_update.class_hash_to_compiled_class_hash;
    // query storage proofs for each accessed contract
    let class_hashes: Vec<&Felt252> = class_hash_to_compiled_class_hash.keys().collect();
    println!("🏷️  Step 14: Fetching class proofs for {} class hashes...", class_hashes.len());
    // TODO: we fetch proofs here for block-1, but we probably also need to fetch at the current
    //       block, likely for contracts that are deployed in this block
    let class_proofs =
        get_class_proofs(&rpc_client, block_number, &class_hashes[..]).await.expect("Failed to fetch class proofs");
    println!("✅ Got {} class proofs", class_proofs.len());
        
    println!("📖 Step 15: Fetching previous class proofs...");
    let previous_class_proofs = match previous_block_id {
        Some(BlockId::Number(previous_block_id)) => get_class_proofs(&rpc_client, previous_block_id, &class_hashes[..])
            .await
            .expect("Failed to fetch previous class proofs"),
        _ => Default::default(),
    };
    println!("✅ Got {} previous class proofs", previous_class_proofs.len());

    // We can extract data from any storage proof, use the one of the block hash contract
    let block_hash_storage_proof =
        storage_proofs.get(&Felt::ONE).expect("there should be a storage proof for the block hash contract");
    let previous_block_hash_storage_proof = previous_storage_proofs
        .get(&Felt::ONE)
        .expect("there should be a previous storage proof for the block hash contract");

    // The root of the class commitment tree for previous and current block
    // Using requested storage proof instead of getting them from class proofs
    // If the block doesn't contain transactions, `class_proofs` will be empty
    // Pathfinder will send a None on class_commitment when the tree is not initialized, ie, root is zero
    let updated_root = block_hash_storage_proof.class_commitment.unwrap_or(Felt::ZERO);
    let previous_root = previous_block_hash_storage_proof.class_commitment.unwrap_or(Felt::ZERO);

    // On devnet and until block 10, the storage_root_idx might be None and that means that contract_proof is empty
    let previous_contract_trie_root = match previous_block_hash_storage_proof.contract_proof.first() {
        Some(proof) => proof.hash::<PedersenHash>(),
        None => Felt252::ZERO,
    };
    let current_contract_trie_root = match block_hash_storage_proof.contract_proof.first() {
        Some(proof) => proof.hash::<PedersenHash>(),
        None => Felt252::ZERO,
    };

    let previous_contract_proofs: Vec<_> =
        previous_storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let previous_state_commitment_facts = format_commitment_facts::<PedersenHash>(&previous_contract_proofs);
    let current_contract_proofs: Vec<_> = storage_proofs.values().map(|proof| proof.contract_proof.clone()).collect();
    let current_state_commitment_facts = format_commitment_facts::<PedersenHash>(&current_contract_proofs);

    let global_state_commitment_facts: HashMap<_, _> =
        previous_state_commitment_facts.into_iter().chain(current_state_commitment_facts)
        .map(|(k, v)| (HashOutput(k), v))
        .collect();

    let contract_state_commitment_info = CommitmentInfo {
        previous_root: HashOutput(previous_contract_trie_root),
        updated_root: HashOutput(current_contract_trie_root),
        tree_height: SubTreeHeight(251),
        commitment_facts: global_state_commitment_facts,
    };

    println!("🔨 Step 16: Computing class commitments...");
    let contract_class_commitment_info =
        compute_class_commitment(&previous_class_proofs, &class_proofs, previous_root, updated_root);
    println!("✅ Class commitment computed");

    println!("🔄 Step 17: Converting compiled classes to BTreeMap...");
    let compiled_classes_btree: BTreeMap<ClassHash, CasmContractClass> = compiled_classes
        .into_iter()
        .map(|(k, v)| {
            let cairo_lang_class = v.get_cairo_lang_contract_class()
                .expect("Failed to get cairo-lang contract class")
                .clone();
            (ClassHash(k), cairo_lang_class)
        })
        .collect();
    
    let deprecated_compiled_classes_btree: BTreeMap<ClassHash, ContractClass> = deprecated_compiled_classes
        .into_iter()
        .map(|(k, v)| {
            let starknet_api_class = v.to_starknet_api_contract_class()
                .expect("Failed to convert to starknet-api contract class");
            (ClassHash(k), starknet_api_class)
                 })
         .collect();
    println!("✅ Converted {} compiled classes and {} deprecated classes", compiled_classes_btree.len(), deprecated_compiled_classes_btree.len());

    println!("🎯 Step 18: Building final OsBlockInput...");
    let os_block_input = OsBlockInput {
        contract_state_commitment_info,
        contract_class_commitment_info ,
        address_to_storage_commitment_info,
        transactions: starknet_api_txns,
        tx_execution_infos: central_txn_execution_infos,
        declared_class_hash_to_component_hashes: declared_class_hash_component_hashes,
        block_info: block_context.block_info().clone(),
        prev_block_hash: BlockHash(previous_block.unwrap().block_hash),
        new_block_hash: BlockHash(block_with_txs.block_hash),
        old_block_number_and_hash: Some((BlockNumber(older_block_number), BlockHash(old_block_hash))),
    };
    
    println!("🏁 collect_single_block_info: Completed successfully for block {}", block_number);
    (os_block_input, compiled_classes_btree, deprecated_compiled_classes_btree)
}

#[tokio::main]
async fn main() {
    println!("🚀 Starting SNOS PoC application...");
    let rpc_client = RpcClient::new("https://pathfinder-madara-ci.d.karnot.xyz");
    println!("🌐 RPC client initialized for pathfinder-madara-ci.d.karnot.xyz");

    let blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), BlockId::Number(1309254));
    println!("📖 State reader created for block 1309254");
    
    println!("🔍 Starting to collect block info for block 1309254...");
    let (block_input, compiled_classes, deprecated_compiled_classes) = collect_single_block_info(1309254, rpc_client.clone(), blockifier_state_reader.clone()).await;
    println!("✅ Block info collection completed!");

    // println!("the block_input: {:?}", block_input);
    // println!("the compiled_classes: {:?}", compiled_classes);
    // println!("the deprecated_compiled_classes: {:?}", deprecated_compiled_classes);

    println!("📋 Preparing OS inputs...");
    let os_block_inputs = vec![block_input];
    let cached_state_inputs = vec![CachedStateInput::default()];
    println!("✅ OS inputs prepared with {} block inputs and {} cached state inputs", os_block_inputs.len(), cached_state_inputs.len());

    println!("⚙️  Building OS hints configuration...");
    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: true,
            full_output: true,
            use_kzg_da: false,
            chain_info: OsChainInfo {
                chain_id: ChainId::Sepolia,
                strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked("0xabcd")).expect("issue while converting the contract address"),
            },
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes,
            compiled_classes,
        },
    };
    println!("✅ OS hints configuration built successfully");

    println!("🚀 Step 19: Starting OS execution...");
    println!("🔧 Using layout: {:?}", LayoutName::all_cairo);
    run_os(
        DEFAULT_COMPILED_OS,
        LayoutName::all_cairo,
        os_hints,
        vec![blockifier_state_reader],
    ).expect("Failed to run OS");
    println!("🎉 OS execution completed successfully!");
}
