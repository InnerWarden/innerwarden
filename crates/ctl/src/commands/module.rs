use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use innerwarden_core::audit::{append_admin_action, current_operator, AdminActionEntry};

use crate::capability::CapabilityRegistry;
use crate::commands::capability::cmd_enable;
use crate::{
    config_editor, module_manifest, module_package, module_validator, sudoers, systemd, Cli,
};

pub(crate) fn cmd_module_validate(path: &std::path::Path, strict: bool) -> Result<()> {
    let report = module_validator::validate(path, strict)?;
    report.print();
    if report.passed() {
        Ok(())
    } else {
        anyhow::bail!("module validation failed")
    }
}

pub(crate) fn cmd_module_enable(cli: &Cli, path: &std::path::Path, yes: bool) -> Result<()> {
    use module_manifest::{
        generate_module_sudoers_rule, is_module_enabled, module_planned_effects, ModuleManifest,
    };

    // 1. Validate manifest before touching anything
    let report = module_validator::validate(path, false)?;
    if !report.passed() {
        report.print();
        anyhow::bail!("module validation failed - fix errors before enabling");
    }

    // 2. Parse manifest
    let manifest = ModuleManifest::from_path(path)?;

    println!("Enabling module: {} ({})\n", manifest.name, manifest.id);

    // 3. Check if already enabled
    if is_module_enabled(&cli.sensor_config, &cli.agent_config, &manifest) {
        println!(
            "Module '{}' is already enabled. Nothing to do.",
            manifest.id
        );
        return Ok(());
    }

    // 4. Preflight checks
    println!("Preflight checks:");
    let mut any_failed = false;
    for pf in &manifest.preflights {
        let (ok, err_msg) = run_module_preflight(pf);
        if ok {
            println!("  [ok]   {}", pf.reason);
        } else {
            println!("  [fail] {} - {}", pf.reason, err_msg);
            any_failed = true;
        }
    }
    if manifest.preflights.is_empty() {
        println!("  (none required)");
    }
    if any_failed {
        anyhow::bail!("preflight checks failed - no changes applied");
    }

    // 5. Planned effects
    let effects = module_planned_effects(&cli.sensor_config, &cli.agent_config, &manifest);
    println!("\nPlanned changes:");
    for (i, e) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, e);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    // 6. Confirmation
    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    // 7. Apply
    apply_module_enable(cli, &manifest, &generate_module_sudoers_rule)?;

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "module_enable".to_string(),
        target: manifest.id.clone(),
        parameters: serde_json::json!({ "path": path.display().to_string() }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nModule '{}' is now enabled.", manifest.id);
    Ok(())
}

pub(crate) fn cmd_module_disable(cli: &Cli, path: &std::path::Path, yes: bool) -> Result<()> {
    use module_manifest::{is_module_enabled, module_disable_effects, ModuleManifest};

    let manifest = ModuleManifest::from_path(path)?;

    println!("Disabling module: {} ({})\n", manifest.name, manifest.id);

    if !is_module_enabled(&cli.sensor_config, &cli.agent_config, &manifest) {
        println!("Module '{}' is not enabled. Nothing to do.", manifest.id);
        return Ok(());
    }

    let effects = module_disable_effects(&cli.sensor_config, &cli.agent_config, &manifest);
    println!("Changes to apply:");
    for (i, e) in effects.iter().enumerate() {
        println!("  {}. {}", i + 1, e);
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();
    apply_module_disable(cli, &manifest)?;

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "module_disable".to_string(),
        target: manifest.id.clone(),
        parameters: serde_json::json!({ "path": path.display().to_string() }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nModule '{}' is now disabled.", manifest.id);
    Ok(())
}

pub(crate) fn cmd_module_list(cli: &Cli, modules_dir: &std::path::Path) -> Result<()> {
    use module_manifest::{is_module_enabled, scan_modules_dir};

    let modules = scan_modules_dir(modules_dir);

    if modules.is_empty() {
        println!("No modules found in {}", modules_dir.display());
        println!("Use 'innerwarden module enable <path>' to enable a module from its directory.");
        return Ok(());
    }

    println!(
        "{:<24} {:<10} {:<8} Description",
        "Module", "Status", "Tier"
    );
    println!("{}", "─".repeat(80));

    for m in &modules {
        let status = if is_module_enabled(&cli.sensor_config, &cli.agent_config, m) {
            "enabled"
        } else {
            "disabled"
        };
        // Truncate description to keep table readable
        let desc: String = m.name.chars().take(23).collect();
        println!("{:<24} {:<10} {:<8} {}", m.id, status, "open", desc);
    }
    Ok(())
}

pub(crate) fn cmd_module_status(cli: &Cli, id: &str, modules_dir: &std::path::Path) -> Result<()> {
    use module_manifest::{
        collector_section, detector_section, is_module_enabled, notifier_section, scan_modules_dir,
    };

    let modules = scan_modules_dir(modules_dir);
    let manifest = modules.iter().find(|m| m.id == id).ok_or_else(|| {
        anyhow::anyhow!(
            "module '{}' not found in {} - check the path or run 'innerwarden module list'",
            id,
            modules_dir.display()
        )
    })?;

    let enabled = is_module_enabled(&cli.sensor_config, &cli.agent_config, manifest);
    let status = if enabled { "enabled" } else { "disabled" };
    let builtin = if manifest.builtin { "yes" } else { "no" };

    println!("Module:      {}", manifest.name);
    println!("ID:          {}", manifest.id);
    println!("Status:      {status}");
    println!("Builtin:     {builtin}");

    if !manifest.collectors.is_empty() {
        let parts: Vec<String> = manifest
            .collectors
            .iter()
            .map(|id| {
                let on = collector_section(id)
                    .map(|s| config_editor::read_bool(&cli.sensor_config, s, "enabled"))
                    .unwrap_or(false);
                format!("{id} ({})", if on { "enabled" } else { "disabled" })
            })
            .collect();
        println!("Collectors:  {}", parts.join(", "));
    }

    if !manifest.detectors.is_empty() {
        let parts: Vec<String> = manifest
            .detectors
            .iter()
            .map(|id| {
                let on = detector_section(id)
                    .map(|s| config_editor::read_bool(&cli.sensor_config, s, "enabled"))
                    .unwrap_or(false);
                format!("{id} ({})", if on { "enabled" } else { "disabled" })
            })
            .collect();
        println!("Detectors:   {}", parts.join(", "));
    }

    if !manifest.skills.is_empty() {
        let active =
            config_editor::read_str_array(&cli.agent_config, "responder", "allowed_skills");
        let parts: Vec<String> = manifest
            .skills
            .iter()
            .map(|s| {
                let on = active.iter().any(|a| a == s);
                format!("{s} ({})", if on { "enabled" } else { "disabled" })
            })
            .collect();
        println!("Skills:      {}", parts.join(", "));
    }

    if !manifest.notifiers.is_empty() {
        let parts: Vec<String> = manifest
            .notifiers
            .iter()
            .map(|id| {
                let on = notifier_section(id)
                    .map(|s| config_editor::read_bool(&cli.agent_config, s, "enabled"))
                    .unwrap_or(false);
                format!("{id} ({})", if on { "enabled" } else { "disabled" })
            })
            .collect();
        println!("Notifiers:   {}", parts.join(", "));
    }

    Ok(())
}

fn apply_module_disable(cli: &Cli, manifest: &module_manifest::ModuleManifest) -> Result<()> {
    use module_manifest::{collector_section, detector_section, notifier_section};

    // Disable collectors
    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", false)?;
            println!("  [done] [{section}] enabled = false");
        }
    }

    // Disable detectors
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", false)?;
            println!("  [done] [{section}] enabled = false");
        }
    }

    // Remove skills from allowed_skills
    for skill in &manifest.skills {
        let removed = config_editor::write_array_remove(
            &cli.agent_config,
            "responder",
            "allowed_skills",
            skill,
        )?;
        if removed {
            println!("  [done] Removed \"{skill}\" from [responder] allowed_skills");
        }
    }

    // Disable notifiers in agent config
    for id in &manifest.notifiers {
        if let Some(section) = notifier_section(id) {
            config_editor::write_bool(&cli.agent_config, section, "enabled", false)?;
            println!("  [done] [{section}] enabled = false");
        } else {
            println!("  [warn] unknown notifier '{id}' - skipped");
        }
    }

    // Remove sudoers drop-in
    if !manifest.allowed_commands.is_empty() {
        let drop_in_name = format!("innerwarden-module-{}", manifest.id);
        let drop_in = sudoers::SudoersDropIn::new(drop_in_name, String::new());
        drop_in.remove(cli.dry_run)?;
        println!(
            "  [done] Removed /etc/sudoers.d/innerwarden-module-{}",
            manifest.id
        );
    }

    // Restart services
    let needs_sensor = !manifest.collectors.is_empty() || !manifest.detectors.is_empty();
    let needs_agent = !manifest.skills.is_empty() || !manifest.notifiers.is_empty();

    if needs_sensor {
        systemd::restart_service("innerwarden-sensor", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-sensor");
    }
    if needs_agent {
        systemd::restart_service("innerwarden-agent", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-agent");
    }

    Ok(())
}

fn run_module_preflight(pf: &module_manifest::ModulePreflightSpec) -> (bool, String) {
    match pf.kind.as_str() {
        "binary_exists" => {
            let exists = std::path::Path::new(&pf.value).exists();
            (exists, format!("{} not found", pf.value))
        }
        "directory_exists" => {
            let exists = std::path::Path::new(&pf.value).is_dir();
            (exists, format!("directory {} not found", pf.value))
        }
        "user_exists" => {
            // Check via /etc/passwd presence (no external tools needed)
            let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
            let exists = passwd
                .lines()
                .any(|l| l.split(':').next().is_some_and(|u| u == pf.value));
            (exists, format!("user '{}' does not exist", pf.value))
        }
        _ => (true, String::new()), // unknown kind = pass (fail-open)
    }
}

fn apply_module_enable(
    cli: &Cli,
    manifest: &module_manifest::ModuleManifest,
    sudoers_rule_fn: &dyn Fn(&str, &[String]) -> String,
) -> Result<()> {
    use module_manifest::{collector_section, detector_section, notifier_section};

    // Enable collectors in sensor config
    for id in &manifest.collectors {
        if let Some(section) = collector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", true)?;
            println!("  [done] [{section}] enabled = true");
        } else {
            println!("  [warn] unknown collector '{id}' - no sensor config section found; skipped");
        }
    }

    // Enable detectors in sensor config
    for id in &manifest.detectors {
        if let Some(section) = detector_section(id) {
            config_editor::write_bool(&cli.sensor_config, section, "enabled", true)?;
            println!("  [done] [{section}] enabled = true");
        } else {
            println!("  [warn] unknown detector '{id}' - no sensor config section found; skipped");
        }
    }

    // Add skills to agent allowed_skills and enable responder
    if !manifest.skills.is_empty() {
        config_editor::write_bool(&cli.agent_config, "responder", "enabled", true)?;
        println!("  [done] [responder] enabled = true");
    }
    for skill in &manifest.skills {
        let added = config_editor::write_array_push(
            &cli.agent_config,
            "responder",
            "allowed_skills",
            skill,
        )?;
        if added {
            println!("  [done] Added \"{skill}\" to [responder] allowed_skills");
        }
    }

    // Enable notifiers in agent config
    for id in &manifest.notifiers {
        if let Some(section) = notifier_section(id) {
            config_editor::write_bool(&cli.agent_config, section, "enabled", true)?;
            println!("  [done] [{section}] enabled = true");
        } else {
            println!("  [warn] unknown notifier '{id}' - no agent config section found; skipped");
        }
    }

    // Install sudoers drop-in if commands are declared
    if !manifest.allowed_commands.is_empty() {
        let rule = sudoers_rule_fn(&manifest.id, &manifest.allowed_commands);
        let drop_in_name = format!("innerwarden-module-{}", manifest.id);
        let drop_in = sudoers::SudoersDropIn::new(drop_in_name, rule);
        drop_in.install(cli.dry_run)?;
        println!(
            "  [done] Wrote /etc/sudoers.d/innerwarden-module-{}",
            manifest.id
        );
    }

    // Restart services
    let needs_sensor = !manifest.collectors.is_empty() || !manifest.detectors.is_empty();
    let needs_agent = !manifest.skills.is_empty() || !manifest.notifiers.is_empty();

    if needs_sensor {
        systemd::restart_service("innerwarden-sensor", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-sensor");
    }
    if needs_agent {
        systemd::restart_service("innerwarden-agent", cli.dry_run)?;
        println!("  [done] Restarted innerwarden-agent");
    }

    Ok(())
}

const REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/InnerWarden/innerwarden/main/registry.toml";

/// A single entry from registry.toml.
#[derive(Debug)]
struct RegistryModule {
    id: String,
    name: String,
    version: String,
    description: String,
    tags: Vec<String>,
    tier: String,
    builtin: bool,
    /// Capabilities to activate for builtin modules (maps to `innerwarden enable <cap>`)
    enables: Vec<String>,
    /// Tarball URL for non-builtin modules
    install_url: Option<String>,
}

/// Fetch and parse the registry. Falls back to an empty list on network errors
/// so `module install <url>` still works offline.
fn fetch_registry() -> Vec<RegistryModule> {
    let raw = match ureq_get(REGISTRY_URL) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("  [warn] could not fetch registry: {e}");
            return vec![];
        }
    };

    parse_registry_toml(&raw)
}

fn parse_registry_toml(raw: &str) -> Vec<RegistryModule> {
    // Minimal TOML array-of-tables parser - no external dep needed.
    // We parse [[modules]] blocks by splitting on that header.
    let mut modules = vec![];
    for block in raw.split("\n[[modules]]") {
        let get = |key: &str| -> String {
            for line in block.lines() {
                let line = line.trim();
                if line.starts_with(&format!("{key} ")) || line.starts_with(&format!("{key}=")) {
                    if let Some(rest) = line.split_once('=').map(|x| x.1) {
                        return rest.trim().trim_matches('"').to_string();
                    }
                }
            }
            String::new()
        };
        let get_bool = |key: &str| get(key) == "true";
        let get_vec = |key: &str| -> Vec<String> {
            for line in block.lines() {
                let line = line.trim();
                if line.starts_with(&format!("{key} ")) || line.starts_with(&format!("{key}=")) {
                    if let Some(rest) = line.split_once('=').map(|x| x.1) {
                        return rest
                            .trim()
                            .trim_start_matches('[')
                            .trim_end_matches(']')
                            .split(',')
                            .map(|s| s.trim().trim_matches('"').to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                }
            }
            vec![]
        };

        let id = get("id");
        if id.is_empty() {
            continue;
        }
        modules.push(RegistryModule {
            id,
            name: get("name"),
            version: get("version"),
            description: get("description"),
            tags: get_vec("tags"),
            tier: get("tier"),
            builtin: get_bool("builtin"),
            enables: get_vec("enables"),
            install_url: {
                let u = get("install_url");
                if u.is_empty() {
                    None
                } else {
                    Some(u)
                }
            },
        });
    }
    modules
}

/// Simple blocking HTTP GET - downloads URL to a temp file and reads it.
fn ureq_get(url: &str) -> anyhow::Result<String> {
    use std::io::Read;
    let tmp = tempfile::tempdir()?;
    let dest = module_package::download(url, tmp.path())?;
    let mut s = String::new();
    std::fs::File::open(dest)?.read_to_string(&mut s)?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// innerwarden module search
// ---------------------------------------------------------------------------

pub(crate) fn cmd_module_search(query: Option<&str>) -> Result<()> {
    println!("Fetching registry from {}...", REGISTRY_URL);
    let modules = fetch_registry();

    if modules.is_empty() {
        println!("No modules found (registry unavailable or empty).");
        return Ok(());
    }

    let q = query.unwrap_or("").to_lowercase();
    let filtered: Vec<_> = modules
        .iter()
        .filter(|m| {
            q.is_empty()
                || m.id.contains(&q)
                || m.name.to_lowercase().contains(&q)
                || m.description.to_lowercase().contains(&q)
                || m.tags.iter().any(|t| t.to_lowercase().contains(&q))
        })
        .collect();

    if filtered.is_empty() {
        println!("No modules match '{q}'.");
        return Ok(());
    }

    println!();
    for m in &filtered {
        let tier_badge = if m.tier == "premium" {
            " [premium]"
        } else {
            ""
        };
        let builtin_note = if m.builtin { " (built-in)" } else { "" };
        println!("  {}  v{}{}{}", m.id, m.version, tier_badge, builtin_note);
        println!("    {}", m.description);
        if !m.tags.is_empty() {
            println!("    tags: {}", m.tags.join(", "));
        }
        println!();
    }

    println!("{} module(s) found.", filtered.len());
    if query.is_none() {
        println!("Install: innerwarden module install <id>");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Module install / uninstall / publish
// ---------------------------------------------------------------------------

pub(crate) fn cmd_module_install(
    cli: &Cli,
    source: &str,
    modules_dir: &Path,
    enable_after: bool,
    force: bool,
    yes: bool,
) -> Result<()> {
    use module_manifest::ModuleManifest;
    use module_package::*;

    let is_url = source.starts_with("https://") || source.starts_with("http://");
    let is_path =
        source.starts_with('/') || source.starts_with('.') || std::path::Path::new(source).exists();

    // ── Registry lookup: short module name (e.g. "ssh-protection") ────────
    if !is_url && !is_path {
        let name = source;
        println!("Looking up '{}' in the InnerWarden registry...", name);
        let registry = fetch_registry();
        let entry = registry.into_iter().find(|m| m.id == name).ok_or_else(|| {
            anyhow::anyhow!(
                "Module '{}' not found in registry.\n\
                     Run 'innerwarden module search' to see available modules.\n\
                     You can also pass a URL or local path directly.",
                name
            )
        })?;

        println!(
            "Found: {} v{} - {}",
            entry.name, entry.version, entry.description
        );
        println!();

        // Built-in modules ship with the binary; enable the underlying capabilities.
        if entry.builtin {
            if entry.enables.is_empty() {
                println!(
                    "'{}' is a built-in module configured via sensor config.",
                    entry.id
                );
                println!(
                    "See modules/{}/docs/README.md for setup instructions.",
                    entry.id
                );
                return Ok(());
            }
            println!(
                "'{}' is a built-in module. Enabling its capabilities:",
                entry.id
            );
            for cap in &entry.enables {
                println!("  innerwarden enable {cap}");
            }
            println!();
            if !yes {
                print!("Proceed? [Y/n] ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let trimmed = input.trim().to_lowercase();
                if !trimmed.is_empty() && trimmed != "y" {
                    println!("Aborted.");
                    return Ok(());
                }
            }
            let cap_registry = CapabilityRegistry::default_all();
            for cap_id in &entry.enables {
                if cap_registry.get(cap_id).is_none() {
                    anyhow::bail!("capability '{}' not found - update InnerWarden", cap_id);
                }
                cmd_enable(cli, &cap_registry, cap_id, HashMap::new(), yes)?;
            }
            return Ok(());
        }

        // External module - install from registry URL.
        let url = entry
            .install_url
            .ok_or_else(|| anyhow::anyhow!("Registry entry for '{}' has no install_url", name))?;
        println!("Downloading from registry...");
        return cmd_module_install(cli, &url, modules_dir, enable_after, force, yes);
    }

    let tmp = tempfile::tempdir().context("failed to create temp directory")?;

    // ── Download or resolve local path ────────────────────────────────────
    let tarball_path: PathBuf = if is_url {
        println!("Downloading module package...");
        let path = download(source, tmp.path())?;

        // Verify SHA-256 sidecar if available
        if let Some(expected) = fetch_sha256_sidecar(source) {
            print!("  Validating SHA-256... ");
            std::io::stdout().flush()?;
            verify_sha256(&path, &expected)?;
            println!("ok");
        } else {
            println!("  (no SHA-256 sidecar found - skipping integrity check)");
        }
        path
    } else {
        let p = PathBuf::from(source);
        if !p.exists() {
            anyhow::bail!("local path not found: {}", p.display());
        }
        // Check for local sidecar
        let sidecar = PathBuf::from(format!("{}.sha256", source));
        if sidecar.exists() {
            let expected = std::fs::read_to_string(&sidecar)?;
            verify_sha256(&p, expected.split_whitespace().next().unwrap_or(""))?;
            println!("  SHA-256 ok");
        }
        p
    };

    // ── Extract ───────────────────────────────────────────────────────────
    let extract_dir = tmp.path().join("extracted");
    std::fs::create_dir_all(&extract_dir)?;
    extract_tarball(&tarball_path, &extract_dir)?;
    let module_dir = find_module_dir(&extract_dir)?;

    // ── Validate manifest ─────────────────────────────────────────────────
    let report = module_validator::validate(&module_dir, false)?;
    if !report.passed() {
        report.print();
        anyhow::bail!("module validation failed - package is not installable");
    }

    let manifest = ModuleManifest::from_path(&module_dir)?;
    println!("Module: {} ({})", manifest.name, manifest.id);

    // ── Check existing installation ───────────────────────────────────────
    let install_dest = modules_dir.join(&manifest.id);
    if install_dest.exists() {
        if !force {
            anyhow::bail!(
                "module '{}' is already installed in {}\n\
                 Use --force to overwrite.",
                manifest.id,
                modules_dir.display()
            );
        }
        println!("  (overwriting existing installation)");
    }

    // ── Plan ──────────────────────────────────────────────────────────────
    println!("\nWill install to: {}", install_dest.display());
    if enable_after {
        println!("Will enable after install.");
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nInstall? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    // ── Copy to modules_dir/<id>/ ─────────────────────────────────────────
    std::fs::create_dir_all(modules_dir)
        .with_context(|| format!("cannot create {}", modules_dir.display()))?;
    if install_dest.exists() {
        std::fs::remove_dir_all(&install_dest)?;
    }
    copy_dir(&module_dir, &install_dest)?;
    println!("  [done] Installed → {}", install_dest.display());

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "module_install".to_string(),
        target: manifest.id.clone(),
        parameters: serde_json::json!({ "source": source }),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    // ── Enable immediately if requested ───────────────────────────────────
    if enable_after {
        println!();
        cmd_module_enable(cli, &install_dest, yes)?;
    } else {
        println!(
            "\nModule '{}' installed. Run 'innerwarden module enable {}' to activate.",
            manifest.id,
            install_dest.display()
        );
    }
    Ok(())
}

pub(crate) fn cmd_module_uninstall(
    cli: &Cli,
    id: &str,
    modules_dir: &Path,
    yes: bool,
) -> Result<()> {
    use module_manifest::{is_module_enabled, ModuleManifest};

    let install_dir = modules_dir.join(id);
    if !install_dir.exists() {
        anyhow::bail!(
            "module '{}' is not installed in {}",
            id,
            modules_dir.display()
        );
    }

    let manifest = ModuleManifest::from_path(&install_dir)?;
    println!("Uninstalling module: {} ({})", manifest.name, manifest.id);

    // Disable first if enabled
    let enabled = is_module_enabled(&cli.sensor_config, &cli.agent_config, &manifest);
    if enabled {
        println!("  Module is currently enabled - will disable before removing.");
    }

    println!("  Will remove: {}", install_dir.display());

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nUninstall? [Y/n] ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();

    if enabled {
        apply_module_disable(cli, &manifest)?;
    }

    std::fs::remove_dir_all(&install_dir)
        .with_context(|| format!("failed to remove {}", install_dir.display()))?;
    println!("  [done] Removed {}", install_dir.display());

    // Audit log
    let mut audit = AdminActionEntry {
        ts: chrono::Utc::now(),
        operator: current_operator(),
        source: "cli".to_string(),
        action: "module_uninstall".to_string(),
        target: manifest.id.clone(),
        parameters: serde_json::json!({}),
        result: "success".to_string(),
        prev_hash: None,
    };
    if let Err(e) = append_admin_action(&cli.data_dir, &mut audit) {
        eprintln!("  [warn] failed to write admin audit: {e:#}");
    }

    println!("\nModule '{}' uninstalled.", manifest.id);
    Ok(())
}

pub(crate) fn cmd_module_publish(module_path: &Path, output: Option<&Path>) -> Result<()> {
    use module_manifest::ModuleManifest;
    use module_package::*;

    // Validate before packaging
    let report = module_validator::validate(module_path, false)?;
    if !report.passed() {
        report.print();
        anyhow::bail!("module validation failed - fix errors before publishing");
    }

    let manifest = ModuleManifest::from_path(module_path)?;

    // Determine output path: <id>-v<version>.tar.gz or caller-supplied
    let tarball_path = if let Some(p) = output {
        p.to_path_buf()
    } else {
        let version = manifest.version.as_deref().unwrap_or("0.1.0");
        PathBuf::from(format!("{}-v{version}.tar.gz", manifest.id))
    };

    println!("Publishing module: {} ({})", manifest.name, manifest.id);
    println!("  Output: {}", tarball_path.display());

    create_tarball(module_path, &tarball_path)?;
    println!("  [done] Created {}", tarball_path.display());

    let sidecar = write_sha256_sidecar(&tarball_path)?;
    let hex = sha256_hex(&tarball_path)?;
    println!("  [done] SHA-256:  {hex}");
    println!("  [done] Sidecar:  {}", sidecar.display());

    println!(
        "\nInstall with:\n  innerwarden module install {}",
        tarball_path.display()
    );
    Ok(())
}

pub(crate) fn cmd_module_update_all(
    cli: &Cli,
    modules_dir: &Path,
    check_only: bool,
    yes: bool,
) -> Result<()> {
    use crate::upgrade::is_newer;
    use module_manifest::{scan_modules_dir, ModuleManifest};
    use module_package::*;

    let modules = scan_modules_dir(modules_dir);
    if modules.is_empty() {
        println!("No modules installed in {}.", modules_dir.display());
        return Ok(());
    }

    println!("Checking modules for updates...\n");

    struct UpdateCandidate {
        manifest: ModuleManifest,
        current_version: String,
        new_version: String,
        url: String,
    }

    let mut candidates: Vec<UpdateCandidate> = Vec::new();
    let mut skipped = 0usize;

    for manifest in &modules {
        let current = manifest.version.as_deref().unwrap_or("0.0.0");

        let Some(ref url) = manifest.update_url else {
            println!("  {:<24} (no update_url - skipped)", manifest.id);
            skipped += 1;
            continue;
        };

        // Download to temp, extract, read new version
        let tmp = tempfile::tempdir().context("failed to create temp dir")?;
        print!("  {:<24} checking... ", manifest.id);
        std::io::stdout().flush()?;

        let tarball = match download(url, tmp.path()) {
            Ok(p) => p,
            Err(e) => {
                println!("error ({})", e);
                continue;
            }
        };

        // Validate SHA-256 sidecar if available
        if let Some(expected) = fetch_sha256_sidecar(url) {
            if let Err(e) = verify_sha256(&tarball, &expected) {
                println!("SHA-256 mismatch - skipping ({})", e);
                continue;
            }
        }

        let extract_dir = tmp.path().join("extracted");
        std::fs::create_dir_all(&extract_dir)?;
        if let Err(e) = extract_tarball(&tarball, &extract_dir) {
            println!("extract error - skipping ({})", e);
            continue;
        }
        let module_dir = match find_module_dir(&extract_dir) {
            Ok(d) => d,
            Err(e) => {
                println!("no module.toml - skipping ({})", e);
                continue;
            }
        };
        let new_manifest = match ModuleManifest::from_path(&module_dir) {
            Ok(m) => m,
            Err(e) => {
                println!("manifest parse error - skipping ({})", e);
                continue;
            }
        };
        let new_version = new_manifest
            .version
            .as_deref()
            .unwrap_or("0.0.0")
            .to_string();

        if is_newer(current, &new_version) {
            println!("{current} → {new_version}  [update available]");
            candidates.push(UpdateCandidate {
                manifest: manifest.clone(),
                current_version: current.to_string(),
                new_version,
                url: url.clone(),
            });
        } else {
            println!("{current}  [up to date]");
        }
    }

    println!();

    if candidates.is_empty() {
        println!("All modules are up to date.");
        return Ok(());
    }

    println!("{} update(s) available:", candidates.len());
    for c in &candidates {
        println!(
            "  {} {} → {}",
            c.manifest.id, c.current_version, c.new_version
        );
    }

    if check_only {
        println!("\nRun 'innerwarden module update-all' to install.");
        return Ok(());
    }

    if cli.dry_run {
        println!("\n[DRY RUN] No changes applied.");
        return Ok(());
    }

    if !yes {
        print!("\nApply {} update(s)? [Y/n] ", candidates.len());
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Aborted.");
            return Ok(());
        }
    }

    println!();
    let mut updated = 0usize;
    for c in &candidates {
        println!(
            "Updating {} ({} → {})...",
            c.manifest.id, c.current_version, c.new_version
        );
        let install_dir = modules_dir.join(&c.manifest.id);
        match cmd_module_install(cli, &c.url, modules_dir, false, true, true) {
            Ok(()) => {
                println!("  [done] {} updated to {}", c.manifest.id, c.new_version);
                // Re-enable if it was enabled before
                if module_manifest::is_module_enabled(
                    &cli.sensor_config,
                    &cli.agent_config,
                    &c.manifest,
                ) {
                    let _ = cmd_module_enable(cli, &install_dir, true);
                }
                updated += 1;
            }
            Err(e) => println!("  [fail] {}: {}", c.manifest.id, e),
        }
    }

    println!(
        "\n{updated}/{} module(s) updated successfully.",
        candidates.len()
    );
    if skipped > 0 {
        println!("({skipped} skipped - no update_url declared)");
    }
    Ok(())
}
