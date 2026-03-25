//! Firmware & boot integrity collector — detects firmware-level threats.
//!
//! Monitors signals that indicate BIOS/UEFI compromise, bootkit installation,
//! or firmware tampering. Runs periodically (default: every 5 minutes).
//!
//! Detection techniques from:
//!   - Peacock (arxiv:2601.07402, Jan 2025) — UEFI runtime observability
//!   - UEFI Memory Forensics (arxiv:2501.16962, Jan 2025)
//!   - SoK: Security Below the OS (arxiv:2311.03809)
//!   - ESET: BlackLotus, LoJax, MosaicRegressor analysis
//!
//! No hardware dependency — all checks read /sys/, /proc/, /boot/efi/.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use innerwarden_core::{
    entities::EntityRef,
    event::{Event, Severity},
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// EFI System Partition paths to monitor for unauthorized binaries.
const ESP_PATHS: &[&str] = &[
    "/boot/efi/EFI/BOOT",
    "/boot/efi/EFI/ubuntu",
    "/boot/efi/EFI/debian",
    "/boot/efi/EFI/centos",
    "/boot/efi/EFI/fedora",
    "/boot/efi/EFI/Microsoft/Boot",
];

/// UEFI variables that bootkits commonly tamper with.
const WATCHED_EFIVARS: &[&str] = &[
    "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
    "PK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
    "KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c",
];

pub async fn run(tx: mpsc::Sender<Event>, host: String) {
    // Only run on systems with EFI or /boot
    if !Path::new("/sys/firmware").exists() && !Path::new("/boot").exists() {
        info!("firmware_integrity: no firmware paths found, skipping");
        return;
    }

    info!("firmware_integrity collector starting (5-minute interval)");

    // Build initial baselines
    let mut esp_hashes = scan_esp_hashes();
    let mut efivar_hashes = scan_efivar_hashes();
    let mut dmi_baseline = read_dmi_info();
    let mut kernel_tainted_baseline = read_tainted();
    let mut acpi_hashes = scan_acpi_hashes();

    let hash_count = esp_hashes.len() + efivar_hashes.len() + acpi_hashes.len();
    info!(
        esp = esp_hashes.len(),
        efivars = efivar_hashes.len(),
        acpi = acpi_hashes.len(),
        "firmware_integrity: baseline established ({hash_count} items)"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;

        // 1. ESP integrity — detect new/modified .efi binaries
        let new_esp = scan_esp_hashes();
        for (path, hash) in &new_esp {
            match esp_hashes.get(path) {
                None => {
                    // New file appeared — possible bootkit installation
                    let ev = make_event(
                        &host,
                        Severity::Critical,
                        &format!("New EFI binary detected: {path}"),
                        "firmware.esp_new_binary",
                        &[("path", path.as_str()), ("hash", hash.as_str())],
                        &["firmware", "bootkit", "esp"],
                    );
                    let _ = tx.send(ev).await;
                }
                Some(old_hash) if old_hash != hash => {
                    // File modified — possible bootkit or unauthorized update
                    let ev = make_event(
                        &host,
                        Severity::Critical,
                        &format!("EFI binary modified: {path}"),
                        "firmware.esp_modified",
                        &[
                            ("path", path.as_str()),
                            ("old_hash", old_hash.as_str()),
                            ("new_hash", hash.as_str()),
                        ],
                        &["firmware", "bootkit", "esp"],
                    );
                    let _ = tx.send(ev).await;
                }
                _ => {} // unchanged
            }
        }
        // Detect deleted EFI files (bootkit cleaning up)
        for path in esp_hashes.keys() {
            if !new_esp.contains_key(path) {
                let ev = make_event(
                    &host,
                    Severity::High,
                    &format!("EFI binary removed: {path}"),
                    "firmware.esp_removed",
                    &[("path", path.as_str())],
                    &["firmware", "esp"],
                );
                let _ = tx.send(ev).await;
            }
        }
        esp_hashes = new_esp;

        // 2. UEFI variable monitoring — detect SecureBoot/DBX tampering
        let new_efivars = scan_efivar_hashes();
        for (name, hash) in &new_efivars {
            if let Some(old_hash) = efivar_hashes.get(name) {
                if old_hash != hash {
                    let severity = if name.starts_with("SecureBoot") || name.starts_with("dbx") {
                        Severity::Critical
                    } else {
                        Severity::High
                    };
                    let ev = make_event(
                        &host,
                        severity,
                        &format!("UEFI variable changed: {name}"),
                        "firmware.efivar_changed",
                        &[
                            ("variable", name.as_str()),
                            ("old_hash", old_hash.as_str()),
                            ("new_hash", hash.as_str()),
                        ],
                        &["firmware", "uefi", "bootkit"],
                    );
                    let _ = tx.send(ev).await;
                }
            }
        }
        efivar_hashes = new_efivars;

        // 3. ACPI table integrity — detect malicious AML injection
        let new_acpi = scan_acpi_hashes();
        for (table, hash) in &new_acpi {
            if let Some(old_hash) = acpi_hashes.get(table) {
                if old_hash != hash {
                    let ev = make_event(
                        &host,
                        Severity::Critical,
                        &format!("ACPI table modified at runtime: {table}"),
                        "firmware.acpi_modified",
                        &[("table", table.as_str())],
                        &["firmware", "acpi", "rootkit"],
                    );
                    let _ = tx.send(ev).await;
                }
            }
        }
        acpi_hashes = new_acpi;

        // 4. Firmware version — detect BIOS downgrade/replacement
        let new_dmi = read_dmi_info();
        if !dmi_baseline.is_empty() && new_dmi != dmi_baseline {
            let ev = make_event(
                &host,
                Severity::Critical,
                "DMI/SMBIOS firmware info changed at runtime",
                "firmware.dmi_changed",
                &[("old", &dmi_baseline), ("new", &new_dmi)],
                &["firmware", "bios"],
            );
            let _ = tx.send(ev).await;
            dmi_baseline = new_dmi;
        }

        // 5. Kernel tainted flag — detect new taint (unsigned module loaded)
        let new_tainted = read_tainted();
        if new_tainted != kernel_tainted_baseline && new_tainted > kernel_tainted_baseline {
            let added = new_tainted & !kernel_tainted_baseline;
            let mut reasons = Vec::new();
            if added & 1 != 0 {
                reasons.push("proprietary module");
            }
            if added & 4096 != 0 {
                reasons.push("out-of-tree module");
            }
            if added & 8192 != 0 {
                reasons.push("unsigned module");
            }
            if added & 256 != 0 {
                reasons.push("ACPI table overridden");
            }
            if added & 128 != 0 {
                reasons.push("kernel OOPS");
            }

            let severity = if added & (8192 | 128 | 256) != 0 {
                Severity::Critical
            } else {
                Severity::High
            };
            let ev = make_event(
                &host,
                severity,
                &format!(
                    "Kernel tainted flag changed: +{added} ({})",
                    reasons.join(", ")
                ),
                "firmware.kernel_tainted",
                &[
                    ("flags_added", &added.to_string()),
                    ("total", &new_tainted.to_string()),
                ],
                &["kernel", "tainted", "firmware"],
            );
            let _ = tx.send(ev).await;
            kernel_tainted_baseline = new_tainted;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_file(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let hash = Sha256::digest(&data);
    Some(format!("{hash:x}"))
}

fn scan_esp_hashes() -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    for dir in ESP_PATHS {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("efi")
                    || path.extension().and_then(|e| e.to_str()) == Some("EFI")
                {
                    if let Some(hash) = sha256_file(&path) {
                        hashes.insert(path.display().to_string(), hash);
                    }
                }
            }
        }
    }
    hashes
}

fn scan_efivar_hashes() -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    let efivars_dir = Path::new("/sys/firmware/efi/efivars");
    if !efivars_dir.exists() {
        return hashes;
    }
    for name in WATCHED_EFIVARS {
        let path = efivars_dir.join(name);
        if let Some(hash) = sha256_file(&path) {
            hashes.insert(name.to_string(), hash);
        }
    }
    hashes
}

fn scan_acpi_hashes() -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    let acpi_dir = Path::new("/sys/firmware/acpi/tables");
    if !acpi_dir.exists() {
        return hashes;
    }
    for table_name in ["DSDT", "SSDT", "FACP", "APIC", "MCFG", "HPET"] {
        let path = acpi_dir.join(table_name);
        if let Some(hash) = sha256_file(&path) {
            hashes.insert(table_name.to_string(), hash);
        }
    }
    hashes
}

fn read_dmi_info() -> String {
    let mut info = String::new();
    for file in [
        "/sys/firmware/dmi/tables/smbios_entry_point",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/bios_version",
        "/sys/class/dmi/id/bios_date",
    ] {
        if let Ok(content) = fs::read_to_string(file) {
            info.push_str(&content.trim().replace('\n', " "));
            info.push('|');
        }
    }
    info
}

fn read_tainted() -> u64 {
    fs::read_to_string("/proc/sys/kernel/tainted")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn make_event(
    host: &str,
    severity: Severity,
    summary: &str,
    kind: &str,
    details: &[(&str, &str)],
    tags: &[&str],
) -> Event {
    let mut detail_map = serde_json::Map::new();
    for (k, v) in details {
        detail_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    Event {
        ts: Utc::now(),
        host: host.to_string(),
        source: "firmware_integrity".to_string(),
        kind: kind.to_string(),
        severity,
        summary: summary.to_string(),
        details: serde_json::Value::Object(detail_map),
        tags: tags.iter().map(|t| t.to_string()).collect(),
        entities: vec![],
    }
}
