//! NISHESH command-line interface.
//!
//! Subcommands map one-to-one onto the architecture:
//!
//!   testgen      build a ground-truth corpus                     (harness)
//!   identify     M1 — device access, capacity truth, media class
//!   recover      M2 — filesystem recovery, carving, slack
//!   sanitize     M3 — policy, execution, and the verification loop
//!   verify-cert  M4 — independent offline certificate validation
//!   selftest     end-to-end pipeline check with pass/fail grading
//!
//! Argument parsing is hand-rolled. That is a deliberate consequence of the
//! zero-dependency policy: a tool destined for air-gapped accreditation should
//! not carry a parser generator's transitive dependency tree for twenty flags.

#![allow(dead_code)]

mod artifact;
mod carve;
mod device;
mod fat;
mod hash;
mod json;
mod proof;
mod report;
mod sanitize;
mod testgen;

use artifact::Artifact;
use device::{Device, ImageDevice, MediaClass, Region};
use hash::{hex, sha256};
use json::Json;
use proof::{build_certificate, verify_certificate, AppendLog, DevSigner, Signer};
use report as ui;
use sanitize::Technique;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

const USAGE: &str = "\
USAGE
  nishesh <command> [options]

COMMANDS
  testgen      --out <img> [--manifest <json>] [--size-mb N] [--seed N]
               Build a FAT16 evidence image with known ground truth.

  identify     <img> [--as hdd|sata-ssd|nvme|usb|sed] [--hpa N] [--dco N] [--frozen]
               Device access layer: geometry, media class, hidden capacity.

  recover      <img> [--out <dir>] [--manifest <json>] [--no-carve]
               Filesystem recovery, signature carving and slack extraction.
               With --manifest, grades every recovery by SHA-256.

  sanitize     <img> --as <class> [--execute --confirm] [--samples N]
                     [--cert <json>] [--log <jsonl>] [--hpa N] [--dco N]
               Plan, execute, then ATTACK the result with the recovery engine.
               Without --execute this is a dry run: the plan is shown only.

  verify-cert  <cert.json> [--log <jsonl>] [--passphrase <s>]
               Offline verification: payload hash, signature, chain integrity.

  selftest     Run the full pipeline against a generated corpus and grade it.

GLOBAL
  --no-banner  Suppress the banner.
  --help       This text.
";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv[0] == "--help" || argv[0] == "-h" {
        ui::banner();
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let args = Args::parse(&argv[1..]);
    if !args.flag("no-banner") {
        ui::banner();
    }
    let result = match argv[0].as_str() {
        "testgen" => cmd_testgen(&args),
        "identify" => cmd_identify(&args),
        "recover" => cmd_recover(&args),
        "sanitize" => cmd_sanitize(&args),
        "verify-cert" => cmd_verify_cert(&args),
        "selftest" => cmd_selftest(&args),
        other => {
            eprintln!("unknown command: {other}\n");
            print!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            ui::fail(&e.to_string());
            ExitCode::from(2)
        }
    }
}

// ------------------------------------------------------------ arg handling

#[derive(Debug, Default)]
struct Args {
    positional: Vec<String>,
    opts: HashMap<String, String>,
    flags: Vec<String>,
}

impl Args {
    fn parse(argv: &[String]) -> Args {
        let mut a = Args::default();
        let mut i = 0;
        while i < argv.len() {
            let t = &argv[i];
            if let Some(name) = t.strip_prefix("--") {
                if i + 1 < argv.len() && !argv[i + 1].starts_with("--") {
                    a.opts.insert(name.to_string(), argv[i + 1].clone());
                    i += 2;
                } else {
                    a.flags.push(name.to_string());
                    i += 1;
                }
            } else {
                a.positional.push(t.clone());
                i += 1;
            }
        }
        a
    }
    fn flag(&self, n: &str) -> bool {
        self.flags.iter().any(|f| f == n)
    }
    fn opt(&self, n: &str) -> Option<&str> {
        self.opts.get(n).map(|s| s.as_str())
    }
    fn num(&self, n: &str, default: u64) -> u64 {
        self.opt(n).and_then(|v| v.parse().ok()).unwrap_or(default)
    }
    fn path(&self, n: &str) -> Option<PathBuf> {
        self.opt(n).map(PathBuf::from)
    }
    fn first(&self) -> Result<&str, String> {
        self.positional
            .first()
            .map(|s| s.as_str())
            .ok_or_else(|| "missing required argument".to_string())
    }
}

fn media_from(name: Option<&str>) -> MediaClass {
    match name.unwrap_or("image") {
        "hdd" | "magnetic" => MediaClass::MagneticDisk,
        "sata-ssd" | "ssd" => MediaClass::SataSsd,
        "nvme" => MediaClass::NvmeSsd,
        "usb" => MediaClass::UsbFlash,
        "sed" | "opal" => MediaClass::SelfEncrypting,
        "unknown" => MediaClass::Unknown,
        _ => MediaClass::Image,
    }
}

fn open_simulated(args: &Args, path: &Path, writable: bool) -> std::io::Result<ImageDevice> {
    let mut dev = if writable {
        ImageDevice::open_writable(path)?
    } else {
        ImageDevice::open_readonly(path)?
    };
    if let Some(m) = args.opt("as") {
        dev.simulate_media(media_from(Some(m)));
    }
    let hpa = args.num("hpa", 0);
    let dco = args.num("dco", 0);
    if hpa > 0 || dco > 0 {
        dev.simulate_hidden(hpa, dco);
    }
    if args.flag("frozen") {
        dev.set_frozen(true);
    }
    Ok(dev)
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

// ----------------------------------------------------------------- testgen

fn cmd_testgen(args: &Args) -> Result<bool, String> {
    let out = args
        .path("out")
        .or_else(|| args.positional.first().map(PathBuf::from))
        .ok_or("testgen requires --out <img>")?;
    let size_mb = args.num("size-mb", 20);
    let seed = args.num("seed", 0x4E49_5348_4553);

    ui::section("1", "ground-truth corpus generation");
    ui::note(
        "Every recovery number NISHESH reports is graded against a manifest produced here, \
         not eyeballed. The image is built in userspace: no root, no loop device, no mkfs.",
    );
    println!();

    let t0 = Instant::now();
    let corpus = testgen::build_corpus(size_mb, seed);
    std::fs::write(&out, &corpus.image).map_err(|e| format!("writing image: {e}"))?;

    let manifest_path = args
        .path("manifest")
        .unwrap_or_else(|| out.with_extension("manifest.json"));
    std::fs::write(&manifest_path, corpus.manifest().pretty())
        .map_err(|e| format!("writing manifest: {e}"))?;

    ui::kv("image", &out.display().to_string());
    ui::kv("filesystem", "FAT16, 512 B sectors, 4 KiB clusters");
    ui::kv("size", &ui::human(corpus.image.len() as u64));
    ui::kv("manifest", &manifest_path.display().to_string());
    ui::kv("seed", &format!("{seed:#x} (deterministic)"));
    println!();

    let rows: Vec<Vec<String>> = corpus
        .entries
        .iter()
        .map(|e| {
            vec![
                e.name.clone(),
                e.kind.to_string(),
                ui::human(e.size as u64),
                if e.deleted {
                    ui::c(ui::RED, "DELETED")
                } else {
                    ui::c(ui::GREY, "allocated")
                },
                e.sha256[..16].to_string(),
            ]
        })
        .collect();
    ui::table(&["FILE", "TYPE", "SIZE", "STATE", "SHA-256 (head)"], &rows);
    println!();
    if let Some(host) = &corpus.slack_planted {
        ui::step(&format!(
            "payload planted in the file slack of {host} — the unused tail of an allocated \
             cluster, which no wiping tool touches"
        ));
    }
    ui::step(&format!(
        "{} files deleted the way the filesystem driver does it: directory entry stamped 0xE5, \
         cluster chain released, file content left untouched",
        corpus.expected_recoverable().len()
    ));
    ui::pass(&format!("corpus built in {:?}", t0.elapsed()));
    Ok(true)
}

// ---------------------------------------------------------------- identify

fn cmd_identify(args: &Args) -> Result<bool, String> {
    let path = PathBuf::from(args.first()?);
    let mut dev = open_simulated(args, &path, false).map_err(|e| format!("open: {e}"))?;
    let info = dev.info().clone();

    ui::section("1", "M1 · device access");
    ui::kv("path", &info.path.display().to_string());
    ui::kv("model", &info.model);
    ui::kv("serial", &info.serial);
    ui::kv("media class", info.media.label());
    ui::kv("sector size", &format!("{} B", info.sector_size));
    ui::kv(
        "write blocked",
        if dev.is_write_blocked() {
            "yes (analysis mode)"
        } else {
            "NO"
        },
    );
    println!();

    ui::step("capacity is a three-valued question, and on real drives the answers disagree");
    let rows = vec![
        vec![
            "user max LBA".into(),
            info.user_max_lba.to_string(),
            "what the operating system is allowed to address".into(),
        ],
        vec![
            "native max LBA".into(),
            info.native_max_lba.to_string(),
            "READ NATIVE MAX ADDRESS — exceeds user max when an HPA exists".into(),
        ],
        vec![
            "DCO max LBA".into(),
            info.dco_max_lba.to_string(),
            "DEVICE CONFIGURATION IDENTIFY — the factory maximum".into(),
        ],
    ];
    ui::table(&["FIELD", "VALUE", "SOURCE"], &rows);
    println!();

    if info.hidden_sectors() > 0 {
        ui::warn(&format!(
            "{} sectors ({}) are hidden from the operating system",
            info.hidden_sectors(),
            ui::human(info.hidden_sectors() * info.sector_size as u64)
        ));
        for r in info.regions() {
            let colour = match r.kind {
                Region::Addressable => ui::GREY,
                _ => ui::AMBER,
            };
            println!(
                "    {:<22} LBA {:>10} .. {:<10} {}",
                ui::c(colour, r.kind.label()),
                r.start_lba,
                r.start_lba + r.sectors,
                ui::c(ui::GREY, &ui::human(r.sectors * info.sector_size as u64))
            );
        }
        ui::note(
            "A tool that trusts the reported capacity sanitizes a subset of the medium and then \
             certifies the whole of it. NISHESH unlocks these regions, includes them in the \
             wipe, and sweeps them again during verification.",
        );
    } else {
        ui::pass("no hidden capacity: user, native and DCO maxima agree");
    }

    println!();
    ui::step("sanitize primitives reported by the device");
    ui::kv("ATA SANITIZE", yn(info.supports_ata_sanitize));
    ui::kv("ATA SECURITY ERASE", yn(info.supports_ata_security_erase));
    ui::kv("NVMe Sanitize", yn(info.supports_nvme_sanitize));
    ui::kv("NVMe Format NVM", yn(info.supports_nvme_format));
    ui::kv("TCG Opal", yn(info.supports_opal));
    if info.security_frozen {
        ui::warn("ATA security state is SEC2 (frozen) — erase commands will be rejected");
    }
    if info.passthrough_blocked {
        ui::warn("transport does not pass ATA/NVMe commands through to the device");
    }

    println!();
    ui::section("2", "volume identification");
    match fat::FatVolume::probe(&mut dev, 0) {
        Some(v) => {
            ui::pass(&format!(
                "{} volume detected",
                ui::c(ui::TEAL, v.bpb.kind.label())
            ));
            ui::kv("volume label", &v.bpb.volume_label);
            ui::kv("bytes per sector", &v.bpb.bytes_per_sector.to_string());
            ui::kv(
                "sectors per cluster",
                &v.bpb.sectors_per_cluster.to_string(),
            );
            ui::kv("cluster size", &ui::human(v.bpb.cluster_bytes()));
            ui::kv("cluster count", &v.bpb.cluster_count().to_string());
            ui::kv("FAT copies", &v.bpb.num_fats.to_string());
            ui::kv("first data sector", &v.bpb.first_data_sector().to_string());
            ui::note(
                "FAT width is derived from the cluster count per the Microsoft specification. \
                 The filesystem-type string in the boot sector is advisory and is routinely \
                 wrong on real media, so it is not used for the decision.",
            );
        }
        None => ui::warn("no recognised filesystem at LBA 0 — the carver can still sweep it"),
    }
    Ok(true)
}

// ----------------------------------------------------------------- recover

struct RecoveryRun {
    artifacts: Vec<Artifact>,
    elapsed_ms: u128,
    bytes_scanned: u64,
    automaton_states: usize,
    pattern_count: usize,
}

fn run_recovery(
    dev: &mut ImageDevice,
    do_carve: bool,
    show_progress: bool,
) -> Result<RecoveryRun, String> {
    let t0 = Instant::now();
    let mut artifacts = Vec::new();
    let mut bytes_scanned = 0;

    if let Some(vol) = fat::FatVolume::probe(dev, 0) {
        artifacts.extend(
            vol.recover_deleted(dev)
                .map_err(|e| format!("filesystem recovery: {e}"))?,
        );
        artifacts.extend(
            vol.extract_slack(dev)
                .map_err(|e| format!("slack extraction: {e}"))?,
        );
    }

    let carver = carve::Carver::new(carve::default_signatures());
    if do_carve {
        let total = dev.physical_sectors();
        let (carved, stats) = carver
            .scan(dev, 0, total, Region::Addressable, |d, t| {
                if show_progress {
                    ui::progress("carving", d, t);
                }
            })
            .map_err(|e| format!("carve: {e}"))?;
        bytes_scanned = stats.bytes_scanned;
        artifacts.extend(carved);
    }

    Ok(RecoveryRun {
        artifacts,
        elapsed_ms: t0.elapsed().as_millis(),
        bytes_scanned,
        automaton_states: carver.automaton_states(),
        pattern_count: carver.pattern_count(),
    })
}

fn cmd_recover(args: &Args) -> Result<bool, String> {
    let path = PathBuf::from(args.first()?);
    let mut dev = open_simulated(args, &path, false).map_err(|e| format!("open: {e}"))?;

    ui::section("1", "M2 · recovery engine");
    ui::note(
        "Deleting a file changes almost nothing. On FAT the directory entry's first byte is \
         stamped 0xE5 and the cluster chain is released; the entry keeps its starting cluster, \
         its size and its timestamps, and the file content is never touched. That asymmetry is \
         the entire reason recovery works.",
    );
    println!();

    let do_carve = !args.flag("no-carve");
    let run = run_recovery(&mut dev, do_carve, true)?;

    if do_carve {
        ui::kv("signatures loaded", &run.pattern_count.to_string());
        ui::kv("automaton states", &run.automaton_states.to_string());
        ui::kv("bytes swept", &ui::human(run.bytes_scanned));
        let secs = (run.elapsed_ms as f64 / 1000.0).max(0.001);
        ui::kv(
            "throughput",
            &format!("{}/s", ui::human((run.bytes_scanned as f64 / secs) as u64)),
        );
        ui::note(
            "One Aho-Corasick automaton over every signature, so the medium is read once no \
             matter how many file types are being hunted — O(n + m + z).",
        );
    }
    println!();

    let mut rows = Vec::new();
    for a in &run.artifacts {
        rows.push(vec![
            a.name.clone().unwrap_or_else(|| "<unnamed>".into()),
            a.method.label().to_string(),
            ui::human(a.size),
            a.file_type.unwrap_or("-").to_string(),
            if a.validated {
                ui::c(ui::GREEN, "validated")
            } else {
                ui::c(ui::AMBER, "unconfirmed")
            },
            format!("{:.0}%", a.confidence * 100.0),
            a.short_hash(),
        ]);
    }
    ui::table(
        &[
            "ARTIFACT", "METHOD", "SIZE", "TYPE", "ORACLE", "CONF", "SHA-256",
        ],
        &rows,
    );
    println!();
    ui::kv("artifacts recovered", &run.artifacts.len().to_string());
    ui::kv(
        "with original metadata",
        &run.artifacts
            .iter()
            .filter(|a| a.method.carries_metadata())
            .count()
            .to_string(),
    );
    ui::kv(
        "validator-confirmed",
        &run.artifacts
            .iter()
            .filter(|a| a.validated)
            .count()
            .to_string(),
    );

    if let Some(dir) = args.path("out") {
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
        for a in &run.artifacts {
            let data = dev
                .read_at(a.offset, a.size as usize)
                .map_err(|e| format!("read: {e}"))?;
            let name = a
                .name
                .clone()
                .unwrap_or_else(|| format!("artifact-{:012x}", a.offset));
            let safe = name.replace(['/', '\\', ':'], "_");
            std::fs::write(dir.join(&safe), &data).map_err(|e| format!("write: {e}"))?;
        }
        println!();
        ui::pass(&format!(
            "{} artifacts written to {}",
            run.artifacts.len(),
            dir.display()
        ));
    }

    if let Some(mp) = args.path("manifest") {
        grade(&run.artifacts, &mp)?;
    }
    Ok(true)
}

/// Grade a recovery run against the corpus manifest by SHA-256. The only
/// honest way to state a recovery rate.
fn grade(artifacts: &[Artifact], manifest_path: &Path) -> Result<f64, String> {
    let text = std::fs::read_to_string(manifest_path).map_err(|e| format!("manifest: {e}"))?;
    let m = json::parse(&text).map_err(|e| format!("manifest parse: {e}"))?;
    let files = m
        .get("files")
        .and_then(|f| f.as_arr())
        .ok_or("bad manifest")?;
    let recovered: Vec<String> = artifacts.iter().map(|a| hex(&a.sha256)).collect();

    ui::section("2", "grading against ground truth");
    let mut rows = Vec::new();
    let mut hit = 0usize;
    let mut expected = 0usize;
    for f in files {
        if !matches!(f.get("deleted"), Some(Json::Bool(true))) {
            continue;
        }
        expected += 1;
        let name = f.get("name").and_then(|j| j.as_str()).unwrap_or("?");
        let want = f.get("sha256").and_then(|j| j.as_str()).unwrap_or("");
        let found = recovered.iter().any(|r| r == want);
        if found {
            hit += 1;
        }
        rows.push(vec![
            name.to_string(),
            f.get("kind")
                .and_then(|j| j.as_str())
                .unwrap_or("-")
                .to_string(),
            ui::human(f.get("size").and_then(|j| j.as_i64()).unwrap_or(0) as u64),
            if found {
                ui::c(ui::GREEN, "RECOVERED — hash identical")
            } else {
                ui::c(ui::RED, "not recovered")
            },
        ]);
    }
    ui::table(&["DELETED FILE", "TYPE", "SIZE", "RESULT"], &rows);
    println!();

    let rate = if expected == 0 {
        0.0
    } else {
        hit as f64 / expected as f64 * 100.0
    };
    let extra = artifacts.len().saturating_sub(hit);
    ui::kv_hi(
        "recovery rate (byte-exact)",
        &format!("{rate:.1}%  ({hit}/{expected})"),
        if rate >= 99.0 { ui::GREEN } else { ui::AMBER },
    );
    ui::kv(
        "additional artifacts",
        &format!("{extra} (slack, carved fragments of live files)"),
    );
    ui::note(
        "Graded by SHA-256 against the manifest written before deletion. No partial credit: a \
         recovery counts only when every byte matches.",
    );
    Ok(rate)
}

// ---------------------------------------------------------------- sanitize

fn cmd_sanitize(args: &Args) -> Result<bool, String> {
    let path = PathBuf::from(args.first()?);
    let execute = args.flag("execute");
    let confirmed = args.flag("confirm");
    let samples = args.num("samples", 3000);
    let passphrase = args.opt("passphrase").unwrap_or("nishesh-demo").to_string();

    let dev = open_simulated(args, &path, false).map_err(|e| format!("open: {e}"))?;
    let info = dev.info().clone();
    let plan = sanitize::plan(&info);
    drop(dev);

    ui::section("1", "M3 · sanitization policy engine");
    ui::kv("media class", info.media.label());
    ui::kv(
        "translation layer",
        if info.media.has_translation_layer() {
            "yes — host overwrite cannot reach stale pages or over-provisioning"
        } else {
            "no"
        },
    );
    println!();
    ui::kv_hi("technique", plan.technique.label(), ui::TEAL);
    ui::kv_hi(
        "NIST SP 800-88 Rev.2 level",
        plan.level.label(),
        match plan.level {
            sanitize::NistLevel::Purge => ui::GREEN,
            sanitize::NistLevel::Clear => ui::AMBER,
            sanitize::NistLevel::Destroy => ui::RED,
        },
    );
    ui::kv("standard", plan.standard);
    println!();
    ui::step("rationale");
    ui::note(&plan.rationale);

    if !plan.blockers.is_empty() {
        println!();
        for b in &plan.blockers {
            ui::warn("execution blocked");
            ui::note(b);
        }
    }

    if plan.technique == Technique::RefuseAndDestroy {
        ui::verdict(
            false,
            "NO CERTIFICATE ISSUED",
            &[
                ui::c(
                    ui::GREY,
                    "  The medium cannot reach Purge through this transport.",
                ),
                ui::c(
                    ui::GREY,
                    "  Escalation: direct SATA/NVMe port, then physical destruction.",
                ),
                ui::c(
                    ui::GREY,
                    "  The refusal is recorded and signed too, so an operator",
                ),
                ui::c(ui::GREY, "  cannot quietly skip reporting a failure."),
            ],
        );
        return Ok(false);
    }

    if !execute {
        println!();
        ui::step("dry run — nothing was written. Re-run with --execute --confirm to proceed.");
        return Ok(true);
    }
    if !confirmed {
        return Err("--execute requires --confirm (this destroys data)".into());
    }

    ui::section("2", "baseline — what is recoverable before sanitization");
    let mut bdev = open_simulated(args, &path, false).map_err(|e| format!("open: {e}"))?;
    let before = run_recovery(&mut bdev, true, true)?;
    ui::kv_hi(
        "artifacts recoverable now",
        &before.artifacts.len().to_string(),
        ui::RED,
    );
    drop(bdev);

    ui::section("3", "execution");
    let mut wdev = open_simulated(args, &path, true).map_err(|e| format!("open rw: {e}"))?;
    let t0 = Instant::now();
    let event =
        sanitize::execute_on_image(&mut wdev, &plan, |d, t| ui::progress("sanitizing", d, t))
            .map_err(|e| format!("execute: {e}"))?;
    ui::kv("outcome", &format!("{:?}", event.outcome));
    ui::kv("sectors written", &event.sectors_written.to_string());
    ui::kv("elapsed", &format!("{:?}", t0.elapsed()));
    for r in &event.regions_covered {
        ui::step(r);
    }
    for n in &event.notes {
        ui::warn(n);
    }
    drop(wdev);

    ui::section("4", "verification — statistical");
    let mut vdev = open_simulated(args, &path, false).map_err(|e| format!("reopen: {e}"))?;
    let total = vdev.physical_sectors();
    let seed = derive_seed(&path, samples);
    let (nonzero, max_h) = sanitize::statistical_check(&mut vdev, total, samples, seed)
        .map_err(|e| format!("sampling: {e}"))?;
    ui::kv("blocks sampled", &samples.to_string());
    ui::kv("sample seed", &format!("{seed:#018x} (reproducible)"));
    ui::kv_hi(
        "non-zero blocks",
        &nonzero.to_string(),
        if nonzero == 0 { ui::GREEN } else { ui::RED },
    );
    ui::kv("max entropy observed", &format!("{max_h:.3} bits/byte"));
    ui::kv_hi(
        "residual upper bound",
        &format!(
            "< {:.4}% at 95% confidence",
            sanitize::residual_bound_pct(samples)
        ),
        ui::TEAL,
    );
    ui::note(
        "Rule of three: zero observed failures in n independent trials bounds the true failure \
         rate at approximately 3/n. The seed is recorded so an auditor can re-run the identical \
         sample set and reach the identical answer.",
    );

    ui::section("5", "verification — adversarial");
    ui::note(
        "The step no shipping product performs. Instead of asking the drive whether the erase \
         worked, the wiped medium is handed back to our own forensic recovery engine and \
         attacked with everything it has: filesystem metadata, signature carving, file slack, \
         and every unlocked hidden region.",
    );
    println!();
    let after = run_recovery(&mut vdev, true, true)?;
    ui::kv_hi(
        "artifacts recovered after wipe",
        &after.artifacts.len().to_string(),
        if after.artifacts.is_empty() {
            ui::GREEN
        } else {
            ui::RED
        },
    );
    ui::kv(
        "before → after",
        &format!("{} → {}", before.artifacts.len(), after.artifacts.len()),
    );

    let verification = sanitize::verify(&mut vdev, total, samples, seed, after.artifacts.clone())
        .map_err(|e| format!("verify: {e}"))?;

    ui::section("6", "M4 · certificate and tamper-evident log");
    let signer = DevSigner::from_passphrase(&passphrase);
    let payload = json! {
        "tool" => "NISHESH 0.1.0",
        "device" => json!{
            "path" => info.path.display().to_string(),
            "model" => info.model.clone(),
            "serial" => info.serial.clone(),
            "media_class" => info.media.label(),
            "sector_size" => info.sector_size as i64,
            "user_max_lba" => info.user_max_lba,
            "native_max_lba" => info.native_max_lba,
            "dco_max_lba" => info.dco_max_lba,
            "hidden_sectors_included" => info.hidden_sectors(),
        },
        "sanitization" => plan.to_json(),
        "execution" => json!{
            "outcome" => format!("{:?}", event.outcome),
            "attempts" => event.attempts as i64,
            "sectors_written" => event.sectors_written,
            "regions_covered" => Json::Arr(event.regions_covered.iter().map(|r| Json::Str(r.clone())).collect()),
        },
        "verification" => verification.to_json(),
        "adversarial_baseline" => json!{
            "artifacts_before_wipe" => before.artifacts.len(),
            "artifacts_after_wipe" => after.artifacts.len(),
        },
    };
    let cert = build_certificate(payload, &signer);

    let log_path = args
        .path("log")
        .unwrap_or_else(|| PathBuf::from("nishesh-chain.jsonl"));
    let mut log = AppendLog::load(&log_path).map_err(|e| format!("log: {e}"))?;
    let entry = log.append(json! {
        "event" => "sanitize",
        "device_serial" => info.serial.clone(),
        "technique" => plan.technique.label(),
        "level" => plan.level.label(),
        "verified" => verification.passed,
        "certificate_sha256" => hex(&sha256(cert.canonical().as_bytes())),
    });
    log.persist(&log_path)
        .map_err(|e| format!("log write: {e}"))?;
    let tree = log.merkle();
    let proof = tree.prove(log.entries.len() - 1).ok_or("proof")?;

    let mut full = cert.clone();
    full.set("log_entry", entry);
    full.set("merkle_inclusion_proof", proof.to_json());

    let cert_path = args
        .path("cert")
        .unwrap_or_else(|| PathBuf::from("nishesh-certificate.json"));
    std::fs::write(&cert_path, full.pretty()).map_err(|e| format!("cert write: {e}"))?;

    ui::kv("signature scheme", signer.scheme().label());
    ui::kv("key id", &signer.key_id());
    ui::kv("canonicalisation", "RFC 8785 (JCS)");
    ui::kv("log entries", &log.entries.len().to_string());
    ui::kv("merkle root", &hex(&tree.root()));
    ui::kv(
        "inclusion proof",
        &format!("{} sibling hashes (log2 n)", proof.path.len()),
    );
    ui::kv("certificate", &cert_path.display().to_string());
    ui::kv("chain log", &log_path.display().to_string());
    if !signer.scheme().provides_non_repudiation() {
        ui::warn(
            "development signer: HMAC-SHA256 is a message authentication code, not a digital \
             signature. Non-repudiation arrives with the Ed25519 signer in Phase 2.",
        );
    }

    let lines = vec![
        format!("  {:<34} {}", "Technique executed", plan.technique.label()),
        format!("  {:<34} {}", "NIST 800-88 Rev.2 level", plan.level.label()),
        format!(
            "  {:<34} {} → {}",
            "Artifacts recoverable",
            before.artifacts.len(),
            after.artifacts.len()
        ),
        format!(
            "  {:<34} {} blocks, {} non-zero",
            "Statistical sweep", samples, nonzero
        ),
        format!(
            "  {:<34} < {:.4}% at 95% confidence",
            "Residual upper bound",
            sanitize::residual_bound_pct(samples)
        ),
        String::new(),
        ui::c(ui::GREY, "  Limitation, stated on the certificate itself:"),
        ui::c(
            ui::GREY,
            "  no software reads unmapped physical NAND pages held by a flash",
        ),
        ui::c(
            ui::GREY,
            "  translation layer. What is established is that every reachable",
        ),
        ui::c(
            ui::GREY,
            "  byte is clean, and that the right firmware technique executed.",
        ),
    ];
    ui::verdict(
        verification.passed,
        if verification.passed {
            "SANITIZATION VERIFIED — CERTIFICATE SIGNED"
        } else {
            "VERIFICATION FAILED — CERTIFICATE REFUSED"
        },
        &lines,
    );

    if !verification.passed {
        ui::step("IEEE 2883 escalation: retry, then an alternative Purge technique, then Destroy");
        if let Some(next) = sanitize::escalate(plan.technique) {
            ui::step(&format!("next technique would be: {}", next.label()));
        }
    }
    Ok(verification.passed)
}

fn derive_seed(path: &Path, samples: u64) -> u64 {
    let mut h = hash::Sha256::new();
    h.update(path.to_string_lossy().as_bytes());
    h.update(&samples.to_le_bytes());
    let d = h.finalize();
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

// ------------------------------------------------------------- verify-cert

fn cmd_verify_cert(args: &Args) -> Result<bool, String> {
    let path = PathBuf::from(args.first()?);
    let passphrase = args.opt("passphrase").unwrap_or("nishesh-demo");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
    let cert = json::parse(&text).map_err(|e| format!("parse: {e}"))?;

    ui::section("1", "offline certificate verification");
    ui::note(
        "An independent verifier needs the certificate file and nothing else — not the log, \
         not the other entries, not a network connection.",
    );
    println!();

    let signer = DevSigner::from_passphrase(passphrase);
    let check = verify_certificate(&cert, &signer).ok_or("malformed certificate")?;
    ui::kv("scheme", &check.scheme);
    if check.payload_hash_ok {
        ui::pass("payload hash matches the canonical serialisation");
    } else {
        ui::fail("payload hash MISMATCH — the certificate body was altered");
    }
    if check.signature_ok {
        ui::pass("signature verifies against the operator key");
    } else {
        ui::fail("signature INVALID");
    }
    if !check.non_repudiation {
        ui::warn("this scheme provides authentication, not non-repudiation");
    }

    let mut proof_ok = true;
    if let Some(p) = cert.get("merkle_inclusion_proof") {
        let leaf = p.get("leaf").and_then(|j| j.as_str()).unwrap_or("");
        let root = p.get("root").and_then(|j| j.as_str()).unwrap_or("");
        let idx = p.get("index").and_then(|j| j.as_i64()).unwrap_or(-1);
        let steps = p
            .get("path")
            .and_then(|j| j.as_arr())
            .map(|a| a.len())
            .unwrap_or(0);
        println!();
        ui::kv("merkle index", &idx.to_string());
        ui::kv("merkle root", root);
        ui::kv("proof length", &format!("{steps} sibling hashes"));
        proof_ok = rebuild_root(leaf, p).as_deref() == Some(root);
        if proof_ok {
            ui::pass("inclusion proof recomputes the stated root");
        } else {
            ui::fail("inclusion proof does NOT reach the stated root");
        }
    }

    let mut chain_ok = true;
    if let Some(lp) = args.path("log") {
        println!();
        ui::section("2", "append-only chain audit");
        let log = AppendLog::load(&lp).map_err(|e| format!("log: {e}"))?;
        match log.audit() {
            Ok(()) => ui::pass(&format!(
                "{} entries, every prev_hash link intact",
                log.entries.len()
            )),
            Err(i) => {
                chain_ok = false;
                ui::fail(&format!(
                    "chain breaks at entry {i} — an earlier entry was altered"
                ));
            }
        }
        ui::kv("merkle root of log", &hex(&log.merkle().root()));
    }

    let ok = check.ok() && proof_ok && chain_ok;
    ui::verdict(
        ok,
        if ok {
            "CERTIFICATE VALID"
        } else {
            "CERTIFICATE REJECTED"
        },
        &[],
    );
    Ok(ok)
}

fn rebuild_root(leaf_hex: &str, proof: &Json) -> Option<String> {
    let mut acc: [u8; 32] = hash::unhex(leaf_hex)?.try_into().ok()?;
    for step in proof.get("path")?.as_arr()? {
        let sib: [u8; 32] = hash::unhex(step.get("hash")?.as_str()?)?.try_into().ok()?;
        let right = matches!(step.get("sibling_on_right"), Some(Json::Bool(true)));
        acc = if right {
            proof::node_hash(&acc, &sib)
        } else {
            proof::node_hash(&sib, &acc)
        };
    }
    Some(hex(&acc))
}

// ---------------------------------------------------------------- selftest

fn cmd_selftest(args: &Args) -> Result<bool, String> {
    let dir = std::env::temp_dir().join("nishesh-selftest");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    let img = dir.join("evidence.img");
    let man = dir.join("evidence.manifest.json");

    ui::section("0", "end-to-end self test");
    let corpus = testgen::build_corpus(args.num("size-mb", 20), 0x5348);
    std::fs::write(&img, &corpus.image).map_err(|e| e.to_string())?;
    std::fs::write(&man, corpus.manifest().pretty()).map_err(|e| e.to_string())?;
    ui::pass(&format!(
        "corpus: {} files, {} deleted, {}",
        corpus.entries.len(),
        corpus.expected_recoverable().len(),
        ui::human(corpus.image.len() as u64)
    ));

    let mut dev = ImageDevice::open_readonly(&img).map_err(|e| e.to_string())?;
    let run = run_recovery(&mut dev, true, false)?;
    let rate = grade(&run.artifacts, &man)?;
    drop(dev);

    let ok = rate >= 99.0;
    ui::verdict(
        ok,
        if ok {
            "PIPELINE HEALTHY"
        } else {
            "PIPELINE DEGRADED"
        },
        &[format!("  byte-exact recovery rate: {rate:.1}%")],
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(ok)
}
