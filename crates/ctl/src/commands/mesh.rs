use std::io::Write;

use anyhow::Result;
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::Cli;

pub(crate) fn cmd_mesh_enable(cli: &Cli) -> Result<()> {
    let agent_cfg = cli.agent_config.clone();
    let content = std::fs::read_to_string(&agent_cfg).unwrap_or_default();

    if content.contains("[mesh]") && content.contains("enabled = true") {
        println!("Mesh network is already enabled.");
        return Ok(());
    }

    if content.contains("[mesh]") {
        let updated = content.replace("enabled = false", "enabled = true");
        std::fs::write(&agent_cfg, updated)?;
    } else {
        let mut f = std::fs::OpenOptions::new().append(true).open(&agent_cfg)?;
        writeln!(
            f,
            "\n[mesh]\nenabled = true\nbind = \"0.0.0.0:8790\"\npoll_secs = 30\nauto_broadcast = true"
        )?;
    }

    println!("✅ Mesh network enabled.");
    println!("   Listening on port 8790 for peer connections.");
    println!("   Add peers: innerwarden mesh add-peer https://peer:8790");
    println!("   Restart agent to apply: sudo systemctl restart innerwarden-agent");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "mesh_enable".to_string(),
        target: "mesh".to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_mesh_disable(cli: &Cli) -> Result<()> {
    let agent_cfg = cli.agent_config.clone();
    let content = std::fs::read_to_string(&agent_cfg).unwrap_or_default();

    if !content.contains("[mesh]") || content.contains("enabled = false") {
        println!("Mesh network is already disabled.");
        return Ok(());
    }

    let updated = content.replace("enabled = true", "enabled = false");
    std::fs::write(&agent_cfg, updated)?;

    println!("✅ Mesh network disabled.");
    println!("   Restart agent to apply: sudo systemctl restart innerwarden-agent");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "mesh_disable".to_string(),
        target: "mesh".to_string(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_mesh_add_peer(cli: &Cli, endpoint: &str, label: Option<&str>) -> Result<()> {
    let agent_cfg = cli.agent_config.clone();
    let content = std::fs::read_to_string(&agent_cfg).unwrap_or_default();

    if !content.contains("[mesh]") {
        println!("Mesh not configured. Run 'innerwarden mesh enable' first.");
        return Ok(());
    }

    if content.contains(endpoint) {
        println!("Peer {} already configured.", endpoint);
        return Ok(());
    }

    let mut f = std::fs::OpenOptions::new().append(true).open(&agent_cfg)?;
    if let Some(lbl) = label {
        writeln!(
            f,
            "\n[[mesh.peers]]\nendpoint = \"{}\"\npublic_key = \"\"\nlabel = \"{}\"",
            endpoint, lbl
        )?;
    } else {
        writeln!(
            f,
            "\n[[mesh.peers]]\nendpoint = \"{}\"\npublic_key = \"\"",
            endpoint
        )?;
    }

    println!("✅ Peer added: {}", endpoint);
    if let Some(lbl) = label {
        println!("   Label: {}", lbl);
    }
    println!("   Identity will be discovered automatically via ping.");
    println!("   Restart agent to apply: sudo systemctl restart innerwarden-agent");

    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "mesh_add_peer".to_string(),
        target: endpoint.to_string(),
        parameters: serde_json::json!({ "label": label }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    Ok(())
}

pub(crate) fn cmd_mesh_status(cli: &Cli) -> Result<()> {
    let data_dir = cli.data_dir.clone();
    let state_path = data_dir.join("mesh-state.json");

    if !state_path.exists() {
        println!("Mesh network: not initialized");
        println!("Run 'innerwarden mesh enable' to get started.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&state_path)?;
    let state: serde_json::Value = serde_json::from_str(&content)?;

    let identity_path = data_dir.join("mesh-identity.key");
    let has_identity = identity_path.exists();

    println!("═══════════════════════════════════════════════════");
    println!("  MESH NETWORK STATUS");
    println!("═══════════════════════════════════════════════════");
    println!();
    println!(
        "  Identity: {}",
        if has_identity {
            "active"
        } else {
            "not generated"
        }
    );

    let peers = state["peers"].as_array().map(|a| a.len()).unwrap_or(0);
    let reputations = state["reputations"].as_array();

    println!("  Peers: {}", peers);
    println!();

    if let Some(reps) = reputations {
        for rep in reps {
            let node_id = rep["node_id"].as_str().unwrap_or("?");
            let trust = rep["trust_score"].as_f64().unwrap_or(0.0);
            let sent = rep["signals_sent"].as_u64().unwrap_or(0);
            let confirmed = rep["signals_confirmed"].as_u64().unwrap_or(0);
            let short_id = if node_id.len() > 16 {
                &node_id[..16]
            } else {
                node_id
            };
            println!(
                "  Peer {}...  trust={:.2}  signals={}/{}confirmed",
                short_id, trust, sent, confirmed
            );
        }
    }

    println!();
    println!("═══════════════════════════════════════════════════");
    Ok(())
}
