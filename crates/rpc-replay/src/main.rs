use std::fs;
use std::time::Duration;

use chrono::Utc;
use clap::Parser;
use log::{error, info, warn};
use starknet::core::types::BlockId;
use starknet::providers::Provider;
use tokio::time::sleep;

use rpc_client::RpcClient;
use snos_core::{
    generate_pie, ChainConfig, OsHintsConfiguration, PieGenerationError, PieGenerationInput,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Starting block number
    #[arg(short, long)]
    start_block: u64,

    /// RPC URL to connect to
    #[arg(short, long)]
    rpc_url: String,

    /// Interval between block checks in seconds (default: 1)
    #[arg(short, long, default_value_t = 1)]
    interval: u64,

    /// Output directory for PIE files (default: current directory)
    #[arg(short, long, default_value = ".")]
    output_dir: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();
    let args = Args::parse();

    info!("🚀 Starting RPC Replay service");
    info!("Configuration:");
    info!("  Start block: {}", args.start_block);
    info!("  RPC URL: {}", args.rpc_url);
    info!("  Check interval: {} seconds", args.interval);
    info!("  Output directory: {}", args.output_dir);

    // Create output directory if it doesn't exist
    fs::create_dir_all(&args.output_dir)?;

    // Initialize RPC client for block checking
    let rpc_client = RpcClient::new(&args.rpc_url);

    let mut current_block = args.start_block;

    info!("🔄 Starting infinite block processing loop");

    loop {
        let block_set = [current_block];
        info!("📋 Processing block set: {:?}", block_set);

        // Check if all 1 blocks exist
        match check_blocks_exist(&rpc_client, &block_set).await {
            Ok(true) => {
                info!(
                    "✅ All blocks in set {:?} exist, proceeding with PIE generation",
                    block_set
                );

                // Generate PIE for this block set
                match process_block_set(&args, &block_set).await {
                    Ok(output_path) => {
                        info!(
                            "🎉 Successfully generated PIE for blocks {:?} -> {}",
                            block_set, output_path
                        );
                        current_block += 1; // Move to next set of 3 blocks
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to generate PIE for blocks {:?}: {}",
                            block_set, e
                        );

                        // Write error to file
                        let error_file =
                            format!("{}/error_blocks_{}.txt", args.output_dir, block_set[0]);
                        write_error_to_file(&error_file, &block_set, &e).await?;

                        // Move to next set anyway to avoid getting stuck
                        current_block += 1;
                    }
                }
            }
            Ok(false) => {
                info!(
                    "⏳ Not all blocks in set {:?} exist yet, waiting {} seconds",
                    block_set, args.interval
                );
                sleep(Duration::from_secs(args.interval)).await;
            }
            Err(e) => {
                warn!(
                    "⚠️ Error checking blocks {:?}: {}, retrying in {} seconds",
                    block_set, e, args.interval
                );
                sleep(Duration::from_secs(args.interval)).await;
            }
        }
    }
}

/// Check if all blocks in the set exist
async fn check_blocks_exist(
    rpc_client: &RpcClient,
    blocks: &[u64; 1],
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    for &block_num in blocks {
        match rpc_client
            .starknet_rpc()
            .get_block_with_tx_hashes(BlockId::Number(block_num))
            .await
        {
            Ok(_) => {
                // Block exists, continue checking
                continue;
            }
            Err(e) => {
                // Check if it's a "block not found" error
                let error_str = format!("{:?}", e);
                if error_str.contains("BlockNotFound") || error_str.contains("block not found") {
                    info!("📋 Block {} not found yet", block_num);
                    return Ok(false);
                } else {
                    // Other error, propagate it
                    return Err(e.into());
                }
            }
        }
    }
    Ok(true)
}

/// Process a set of 1 block and generate PIE
async fn process_block_set(args: &Args, blocks: &[u64; 1]) -> Result<String, PieGenerationError> {
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let output_filename = format!("cairo_pie_blocks_{}_{}.zip", blocks[0], timestamp);

    let input = PieGenerationInput {
        rpc_url: args.rpc_url.clone(),
        blocks: blocks.to_vec(),
        chain_config: ChainConfig::default(),
        os_hints_config: OsHintsConfiguration::default(),
        output_path: None, // we don't want a lots of zips just yet
    };

    info!("🔄 Starting PIE generation for blocks {:?}", blocks);

    match generate_pie(input).await {
        Ok(result) => {
            info!(
                "✅ PIE generation completed for blocks {:?}",
                result.blocks_processed
            );
            Ok(output_filename)
        }
        Err(e) => {
            error!("❌ PIE generation failed for blocks {:?}: {}", blocks, e);
            Err(e)
        }
    }
}

/// Write error details to a file
async fn write_error_to_file(
    file_path: &str,
    blocks: &[u64; 1],
    error: &PieGenerationError,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let error_content = format!(
        "Error Report\n\
         ============\n\
         Timestamp: {}\n\
         Blocks: {:?}\n\
         Error: {}\n\
         Error Debug: {:?}\n\n",
        timestamp, blocks, error, error
    );

    fs::write(file_path, error_content)?;
    error!("📝 Error details written to: {}", file_path);
    Ok(())
}
