use std::path::Path;
use std::collections::{HashMap, HashSet};
use cairo_vm::types::layout_name::LayoutName;
use starknet_api::core::{ChainId, ContractAddress, ClassHash};
use starknet_api::state::StorageKey;
use starknet::core::types::BlockId;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os,
};
use starknet_os::runner::run_os_stateless;
use rpc_client::RpcClient;
use rpc_client::state_reader::AsyncRpcStateReader;
use starknet_types_core::felt::Felt;

use snos_poc::block_processor::collect_single_block_info;
use snos_poc::cached_state::generate_cached_state_input;

#[tokio::main]
async fn main() {
    env_logger::init();
    println!("Starting SNOS PoC application with multi-block support");
    let rpc_client = RpcClient::new("https://pathfinder-madara-ci.d.karnot.xyz");
    println!("RPC client initialized for pathfinder-madara-ci.d.karnot.xyz");

    // Define the blocks to process
    let blocks = vec![1309254, 1309255, 1309256];
    println!("Processing blocks: {:?}", blocks);

    let mut os_block_inputs = Vec::new();
    let mut cached_state_inputs = Vec::new();
    let mut all_compiled_classes = std::collections::BTreeMap::new();
    let mut all_deprecated_compiled_classes = std::collections::BTreeMap::new();

    // Process each block
    for (index, block_number) in blocks.iter().enumerate() {
        println!("\n=== Processing block {} ===", block_number);
        
        let blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), BlockId::Number(*block_number));
        println!("State reader created for block {}", block_number);
        
        println!("Starting to collect block info for block {}", block_number);
        let (block_input, compiled_classes, deprecated_compiled_classes, accessed_addresses, accessed_classes, accessed_keys_by_address, _previous_block_id) = 
            collect_single_block_info(*block_number, rpc_client.clone()).await;
        println!("Block info collection completed for block {}", block_number);

        // Add block input to our collection
        os_block_inputs.push(block_input);

        // Merge compiled classes (these are shared across blocks)
        all_compiled_classes.extend(compiled_classes);
        all_deprecated_compiled_classes.extend(deprecated_compiled_classes);


        // println!("Generating cached state input for block {} using state from block {}", block_number, state_block_number);
        let cached_state_input = generate_cached_state_input(
            &rpc_client,
            BlockId::Number(block_number - 1),
            &accessed_addresses,
            &accessed_classes,
            &accessed_keys_by_address,
        ).await.expect("Failed to generate cached state input");
        
        cached_state_inputs.push(cached_state_input);
        println!("Block {} processed successfully", block_number);
    }

    println!("\n=== Finalizing multi-block processing ===");
    println!("OS inputs prepared with {} block inputs and {} cached state inputs", 
             os_block_inputs.len(), cached_state_inputs.len());

    println!("Building OS hints configuration for multi-block processing");
    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: true,
            full_output: false,
            use_kzg_da: true,
            chain_info: OsChainInfo {
                chain_id: ChainId::Sepolia,
                strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d")).expect("issue while converting the contract address"),
            },
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes: all_deprecated_compiled_classes,
            compiled_classes: all_compiled_classes,
        },
    };
    println!("OS hints configuration built successfully for {} blocks", blocks.len());

    println!("Starting OS execution for multi-block processing");
    println!("Using layout: {:?}", LayoutName::all_cairo);
    let output = run_os_stateless(
        LayoutName::all_cairo,
        os_hints,
    ).expect("Failed to run OS");
    println!("Multi-block output generated successfully!");
    let _ = output.cairo_pie.run_validity_checks();
    println!("Cairo pie validation done!! Now writing it to the zip file!!");

    let _ = output.cairo_pie.write_zip_file(Path::new("cairo_pie_multi_blocks_1309254_1309256_stateless.zip"), true);

    println!("Multi-block OS execution completed successfully for blocks 1309254-1309256");
}
