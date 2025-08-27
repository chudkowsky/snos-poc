use cairo_vm::Felt252;
use snos_core::{generate_pie, ChainConfig, OsHintsConfiguration, PieGenerationInput};
use starknet_api::core::ContractAddress;
use starknet_os_types::chain_id::chain_id_from_felt;
use starknet_crypto::Felt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    println!("Starting SNOS PoC application with clean architecture");

    let chain_id = chain_id_from_felt(Felt::from_hex_unchecked("0x7465737435"));
    let chain_config = ChainConfig::new(chain_id, ContractAddress::try_from(Felt::from_hex_unchecked(
                "0x2e7442625bab778683501c0eadbc1ea17b3535da040a12ac7d281066e915eea",
            ))
            .expect("Valid contract address"));
    // Build the input configuration
    let input = PieGenerationInput {
        rpc_url: "http://localhost:5050".to_string(),
        blocks: vec![1],
        chain_config, // Uses Sepolia defaults
        os_hints_config: OsHintsConfiguration::default(), // Uses sensible defaults
        output_path: None,
    };

    println!("Configuration:");
    println!("  RPC URL: {}", input.rpc_url);
    println!("  Blocks: {:?}", input.blocks);
    println!("  Chain ID: {:?}", input.chain_config.chain_id);
    println!("  Output: {:?}", input.output_path);

    // Call the core PIE generation function
    match generate_pie(input).await {
        Ok(result) => {
            println!("\n🎉 PIE generation completed successfully!");
            println!("  Blocks processed: {:?}", result.blocks_processed);
            if let Some(output_path) = result.output_path {
                println!("  Output written to: {}", output_path);
            }
        }
        Err(e) => {
            eprintln!("\n❌ PIE generation failed: {}", e);
            return Err(e.into());
        }
    }

    println!("\n✅ SNOS execution completed successfully!");
    Ok(())
}
