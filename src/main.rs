use cairo_vm::types::layout_name::LayoutName;
use starknet_api::core::{ChainId, ContractAddress};
use starknet::core::types::BlockId;
use starknet_os::{
    io::os_input::{OsChainInfo, OsHints, OsHintsConfig, StarknetOsInput},
    runner::run_os,
};
use rpc_client::RpcClient;
use rpc_client::state_reader::AsyncRpcStateReader;
use starknet_types_core::felt::Felt;

use snos_poc::block_processor::collect_single_block_info;
use snos_poc::cached_state::generate_cached_state_input;



#[tokio::main]
async fn main() {
    env_logger::init();
    println!("Starting SNOS PoC application");
    let rpc_client = RpcClient::new("https://pathfinder-madara-ci.d.karnot.xyz");
    println!("RPC client initialized for pathfinder-madara-ci.d.karnot.xyz");

    let blockifier_state_reader = AsyncRpcStateReader::new(rpc_client.clone(), BlockId::Number(1309254));
    println!("State reader created for block 1309254");
    
    println!("Starting to collect block info for block 1309254");
    let (block_input, compiled_classes, deprecated_compiled_classes, accessed_addresses, accessed_classes, accessed_keys_by_address, _previous_block_id) = collect_single_block_info(1309254, rpc_client.clone()).await;
    println!("Block info collection completed");

    println!("Preparing OS inputs");
    let os_block_inputs = vec![block_input];

    println!("Generating cached state input from accessed data");
    let cached_state_input = generate_cached_state_input(
        &rpc_client,
        BlockId::Number(1309253), // Use previous block for state
        &accessed_addresses,
        &accessed_classes,
        &accessed_keys_by_address,
    ).await.expect("Failed to generate cached state input");
    
    let cached_state_inputs = vec![cached_state_input];
    println!("OS inputs prepared with {} block inputs and {} cached state inputs", os_block_inputs.len(), cached_state_inputs.len());

    println!("Building OS hints configuration");
    let os_hints = OsHints {
        os_hints_config: OsHintsConfig {
            debug_mode: true,
            full_output: true,
            use_kzg_da: false,
            chain_info: OsChainInfo {
                chain_id: ChainId::Sepolia,
                strk_fee_token_address: ContractAddress::try_from(Felt::from_hex_unchecked("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d")).expect("issue while converting the contract address"),
            },
        },
        os_input: StarknetOsInput {
            os_block_inputs,
            cached_state_inputs,
            deprecated_compiled_classes,
            compiled_classes,
        },
    };
    println!("OS hints configuration built successfully");

    println!("Starting OS execution");
    println!("Using layout: {:?}", LayoutName::all_cairo);
    run_os(
        LayoutName::all_cairo,
        os_hints,
        vec![blockifier_state_reader],
    ).expect("Failed to run OS");
    println!("OS execution completed successfully");
}
