mod client;
mod commands;

use clap::Parser;
use client::DaemonClient;
use commands::{Cli, Commands, handle_response};
use sysrag_common::ipc::{DaemonRequest, DaemonResponse};
use anyhow::{Result, Context};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

const SOCKET_PATH: &str = "/tmp/sysrag.sock";

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Parse terminal arguments
    let cli = Cli::parse();

    // 2. Instantiate the socket client
    let daemon_client = DaemonClient::new(SOCKET_PATH);

    // 3. Handle Commands
    match cli.command {
        Commands::Status => {
            let resp = daemon_client.send_request(DaemonRequest::Status).await?;
            handle_response(resp);
        }
        Commands::Anomalies { tail } => {
            let resp = daemon_client.send_request(DaemonRequest::GetAnomalies { tail }).await?;
            handle_response(resp);
        }
        Commands::Investigate { id } => {
            // STEP 1: Determine the ID (either provided or fetched)
            let target_id = match id {
                Some(val) => val,
                None => {
                    let resp = daemon_client.send_request(DaemonRequest::GetAnomalies { tail: 1 }).await?;
                    if let DaemonResponse::AnomaliesList(list) = resp {
                        list.first()
                            .map(|a| a.id.clone())
                            .context("No anomalies found to investigate!")?
                    } else {
                        anyhow::bail!("Unexpected response from daemon while fetching latest anomaly.");
                    }
                }
            };

            // STEP 2: The "Zero Cool" ASCII UI
            let ascii_banner = r#"
            ███████╗██╗   ██╗███████╗██████╗  █████╗  ██████╗ 
         ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝ 
         ███████╗ ╚████╔╝ ███████╗██████╔╝███████║██║  ███╗
         ╚════██║  ╚██╔╝  ╚════██║██╔══██╗██╔══██║██║   ██║
         ███████║   ██║   ███████║██║  ██║██║  ██║╚██████╔╝
         ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ "#;

            // Clear the screen for dramatic effect
            print!("{}[2J{}[1;1H", 27 as char, 27 as char);

            // Print the Banner in Cyan
            println!("{}", ascii_banner.cyan().bold());
            
            // The framed box (like "DADE MURPHY" in your image)
            println!("      {}", "████████████████████████████████████".cyan());
            println!("      {}  {}  {}", "██".cyan(), "A N O M A L Y   I N D E X".bold().white(), "██".cyan());
            println!("      {}          {}          {}", "██".cyan(), target_id.white(), "██".cyan());
            println!("      {}", "████████████████████████████████████".cyan());
            println!();

            // The emoji bullet points with dimmed text
            println!("🏆 {}", "Caught via zero-overhead eBPF ring buffer".truecolor(150, 150, 150));
            println!("🚫 {}", "Mathematical vector baseline deviated severely".truecolor(150, 150, 150));
            println!("💻 {}", "Awaiting Neural Network verification...".truecolor(150, 150, 150));
            println!();

            println!("💬 {} says:", "SysRAG".white().bold());
            
            // The Spinner
            let spinner = ProgressBar::new_spinner();
            spinner.set_style(
                ProgressStyle::default_spinner()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                    .template("{spinner:.cyan} {msg}")
                    .unwrap(),
            );
            spinner.set_message(format!("\"Hack the planet!\" (Analyzing kernel logs...)"));
            spinner.enable_steady_tick(Duration::from_millis(80));

            // Run the actual network investigation
            let resp = daemon_client.send_request(DaemonRequest::Investigate { id: target_id }).await?;
            
            // Stop spinner
            spinner.finish_and_clear();

            // The Output
            if let DaemonResponse::InvestigationResult(analysis) = resp {
                println!("{}", "\"Analysis Complete.\"".cyan());
                println!("  - Llama 3");
                println!();
                println!("💡 {}", "Use `kill -9 <PID>` to terminate the threat.".truecolor(150, 150, 150));
                println!("💡 {}", "See `sysrag status` for complete background dossier.".truecolor(150, 150, 150));
                println!();
                
                // Print the actual LLM analysis with a left border
                for line in analysis.lines() {
                    println!("{} {}", "█".cyan(), line.yellow());
                }
                println!();
            } else {
                println!("{}", "Error: Unexpected response format.".red());
            }
        }
    }

    Ok(())
}