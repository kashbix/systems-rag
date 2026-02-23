use clap::{Parser, Subcommand};
use sysrag_common::ipc::DaemonResponse;

/// The "Systems RAG": OS-Level Log Anomaly Detector
#[derive(Parser)]
#[command(name = "sysrag")]
#[command(about = "Interact with the sysragd background AI daemon", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands for the sysrag CLI
#[derive(Subcommand)]
pub enum Commands {
    Status,
    Anomalies { 
        #[arg(short, long, default_value_t = 10)]
        tail: usize 
    }, 
    Investigate { 
        // THIS IS THE CRUCIAL FIX: Make the ID optional!
        id: Option<String>, 
    },
}

/// Formats the daemon's JSON response into beautiful terminal output
pub fn handle_response(res: DaemonResponse) {
    match res {
        DaemonResponse::StatusOk { uptime_seconds, events_processed, db_size } => {
            println!("🟢 SYSRAG DAEMON STATUS: ONLINE");
            println!("---------------------------------");
            println!("Uptime:           {} seconds", uptime_seconds);
            println!("Kernel Events:    {}", events_processed);
            println!("Vector DB Size:   {} baselines", db_size);
        }
        DaemonResponse::AnomaliesList(anomalies) => {
            if anomalies.is_empty() {
                println!("✅ No anomalies detected recently. System is clean.");
                return;
            }
            
            println!("🚨 RECENT SYSTEM ANOMALIES 🚨");
            for anomaly in anomalies {
                println!("--------------------------------------------------");
                println!("ID:       {}", anomaly.id);
                println!("Command:  {}", anomaly.command);
                println!("PID:      {}", anomaly.pid);
                println!("Score:    {:.2} (Lower is worse)", anomaly.similarity_score);
                println!("Hint: Run `sysrag investigate {}` for AI analysis.", anomaly.id);
            }
            println!("--------------------------------------------------");
        }
        DaemonResponse::InvestigationResult(analysis) => {
            println!("🧠 LLM THREAT ANALYSIS 🧠");
            println!("---------------------------------");
            println!("{}", analysis);
            println!("---------------------------------");
        }
        DaemonResponse::Error(err_msg) => {
            eprintln!("❌ DAEMON ERROR: {}", err_msg);
        }
    }
}