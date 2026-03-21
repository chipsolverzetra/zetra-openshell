use anyhow::Result;
use clap::{Parser, Subcommand};

mod graph;
mod patterns;
mod monitor;
mod enforce;
mod ocsf;

use graph::{Path, BehavioralGraph, GraphEdge};
use enforce::{analyze_path, calculate_bes};
use ocsf::DetectionFindingEvent;

#[derive(Parser)]
#[command(name = "zetra")]
#[command(about = "Behavioral security layer for NVIDIA OpenShell")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Monitor a running sandbox
    Monitor {
        #[arg(long)]
        sandbox: String,
    },
    /// Analyze a behavioral graph from a JSON file
    Analyze {
        #[arg(long)]
        file: String,
    },
    /// Show current BES score from a JSON file
    Score {
        #[arg(long)]
        file: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Monitor { sandbox } => {
            println!("[ZETRA] Monitoring sandbox {}...", sandbox);
            println!("[ZETRA] Waiting for OCSF events...");
        }

        Commands::Analyze { file } => {
            println!("[ZETRA] Analyzing {}...", file);

            let contents = std::fs::read_to_string(&file)?;
            let demo: serde_json::Value = serde_json::from_str(&contents)?;

            let mut paths: Vec<Path> = serde_json::from_value(
                demo["paths"].clone()
            )?;

            for path in &mut paths {
                analyze_path(path, 3);
            }

            let summary = calculate_bes(&paths);

            println!("\n[ZETRA] === ANALYSIS RESULTS ===");
            println!("[ZETRA] Total paths:  {}", summary.total_paths);
            println!("[ZETRA] Benign:       {}", summary.benign);
            println!("[ZETRA] Unintended:   {}", summary.unintended);
            println!("[ZETRA] Malicious:    {}", summary.malicious);
            println!("[ZETRA] BES Score:    {:.2}", summary.bes);

            for path in &paths {
                if !path.flags.is_empty() {
                    println!("\n[ZETRA] PATH {} FLAGGED:", path.id);
                    for flag in &path.flags {
                        println!("  → {}: {}", flag.rule, flag.detail);
                    }
                    let event = DetectionFindingEvent::from_path(path, &summary);
                    println!("\n[ZETRA] OCSF DetectionFindingEvent:");
                    println!("{}", event.to_json());
                }
            }
        }

        Commands::Score { file } => {
            let contents = std::fs::read_to_string(&file)?;
            let demo: serde_json::Value = serde_json::from_str(&contents)?;

            let mut paths: Vec<Path> = serde_json::from_value(
                demo["paths"].clone()
            )?;

            for path in &mut paths {
                analyze_path(path, 3);
            }

            let summary = calculate_bes(&paths);
            println!("[ZETRA] BES Score: {:.2}", summary.bes);
        }
    }

    Ok(())
}