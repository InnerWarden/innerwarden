//! Steganography detection via statistical analysis (T1001.002).
//!
//! Detects LSB steganography in images by running 4 statistical tests
//! (inspired by StegExpose) and fusing the results.
//!
//! Detectors:
//!   1. Chi-Square Attack — detects equalized PoV pairs (Westfeld & Pfitzmann 1999)
//!   2. RS Analysis — Regular/Singular groups (Fridrich, Goljan & Du 2001)
//!   3. Sample Pairs Analysis — adjacent pixel pair statistics (Dumitrescu et al. 2003)
//!   4. Primary Sets — histogram-level PoV analysis
//!
//! Fusion: simple average of normalized scores. Threshold: 0.20 (configurable).
//!
//! Triggered by fanotify/eBPF file.write_access events for image files.
//! No external dependencies — pure Rust arithmetic on raw pixel bytes.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use innerwarden_core::{entities::EntityRef, event::Event, event::Severity, incident::Incident};

const STEGO_THRESHOLD: f64 = 0.20;
const IMAGE_EXTENSIONS: &[&str] = &[".png", ".bmp", ".ppm", ".tga"];
const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB
const MIN_FILE_SIZE: u64 = 1024; // 1 KB

pub struct StegoDetector {
    host: String,
    cooldown: Duration,
    alerted: HashMap<String, DateTime<Utc>>,
    threshold: f64,
}

/// Result from the 4 statistical detectors.
#[derive(Debug)]
pub struct StegoResult {
    pub chi_square: f64,
    pub rs_analysis: f64,
    pub sample_pairs: f64,
    pub primary_sets: f64,
    pub fusion: f64,
    pub is_stego: bool,
}

impl StegoDetector {
    pub fn new(host: impl Into<String>, cooldown_seconds: u64) -> Self {
        Self {
            host: host.into(),
            cooldown: Duration::seconds(cooldown_seconds as i64),
            alerted: HashMap::new(),
            threshold: STEGO_THRESHOLD,
        }
    }

    pub fn process(&mut self, event: &Event) -> Option<Incident> {
        // Only process file write events for image files
        if event.kind != "file.write_access" && event.kind != "file.realtime_modified" {
            return None;
        }

        let filename = event.details.get("filename").and_then(|v| v.as_str())?;
        let lower = filename.to_lowercase();

        // Check if it's an image file
        if !IMAGE_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
            return None;
        }

        // Cooldown per file
        let now = event.ts;
        if let Some(&last) = self.alerted.get(filename) {
            if now - last < self.cooldown {
                return None;
            }
        }

        // Check file size
        let meta = std::fs::metadata(filename).ok()?;
        let size = meta.len();
        if !(MIN_FILE_SIZE..=MAX_FILE_SIZE).contains(&size) {
            return None;
        }

        // Read file and analyze
        let data = std::fs::read(filename).ok()?;
        let pixels = extract_pixels(&data, &lower)?;

        if pixels.len() < 100 {
            return None;
        }

        let result = analyze_pixels(&pixels, self.threshold);

        if !result.is_stego {
            return None;
        }

        self.alerted.insert(filename.to_string(), now);

        let comm = event
            .details
            .get("comm")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let pid = event
            .details
            .get("pid")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Prune stale entries
        if self.alerted.len() > 500 {
            let cutoff = now - self.cooldown;
            self.alerted.retain(|_, t| *t > cutoff);
        }

        Some(Incident {
            ts: now,
            host: self.host.clone(),
            incident_id: format!("stego_detect:{}:{}", comm, now.format("%Y-%m-%dT%H:%MZ")),
            severity: Severity::High,
            title: format!(
                "Steganography detected in image: {} (fusion score {:.2})",
                truncate_path(filename, 50),
                result.fusion
            ),
            summary: format!(
                "Statistical analysis detected likely LSB steganography in '{}'. \
                 Scores: chi={:.3} rs={:.3} spa={:.3} ps={:.3} fusion={:.3} (threshold={:.2}). \
                 Written by process '{comm}' (pid={pid}).",
                filename,
                result.chi_square,
                result.rs_analysis,
                result.sample_pairs,
                result.primary_sets,
                result.fusion,
                self.threshold,
            ),
            evidence: serde_json::json!([{
                "kind": "steganography",
                "filename": filename,
                "comm": comm,
                "pid": pid,
                "chi_square": result.chi_square,
                "rs_analysis": result.rs_analysis,
                "sample_pairs": result.sample_pairs,
                "primary_sets": result.primary_sets,
                "fusion_score": result.fusion,
                "threshold": self.threshold,
            }]),
            recommended_checks: vec![
                format!("Inspect image: file {filename}"),
                "Check if hidden data can be extracted: zsteg/stegdetect".to_string(),
                format!("Review who wrote this file and from where"),
            ],
            tags: vec![
                "steganography".to_string(),
                "command_and_control".to_string(),
                "data_hiding".to_string(),
            ],
            entities: vec![EntityRef::path(filename)],
        })
    }
}

// ---------------------------------------------------------------------------
// Pixel extraction from raw image bytes (no image crate dependency)
// ---------------------------------------------------------------------------

/// Extract RGB pixel values from raw image data.
/// Supports BMP and raw PPM. For PNG, requires decoder.
fn extract_pixels(data: &[u8], filename: &str) -> Option<Vec<u8>> {
    if filename.ends_with(".bmp") {
        extract_bmp_pixels(data)
    } else if filename.ends_with(".ppm") {
        extract_ppm_pixels(data)
    } else if filename.ends_with(".png") {
        extract_png_pixels(data)
    } else {
        None
    }
}

/// Extract pixels from BMP (uncompressed, 24-bit or 32-bit).
fn extract_bmp_pixels(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 54 || data[0] != b'B' || data[1] != b'M' {
        return None;
    }
    let offset = u32::from_le_bytes([data[10], data[11], data[12], data[13]]) as usize;
    let bpp = u16::from_le_bytes([data[28], data[29]]) as usize;
    let compression = u32::from_le_bytes([data[30], data[31], data[32], data[33]]);

    if compression != 0 || (bpp != 24 && bpp != 32) {
        return None; // Only uncompressed RGB
    }

    let bytes_per_pixel = bpp / 8;
    if offset >= data.len() {
        return None;
    }

    let pixel_data = &data[offset..];
    let mut rgb = Vec::with_capacity(pixel_data.len());

    // BMP stores BGR(A), convert to RGB
    let mut i = 0;
    while i + bytes_per_pixel <= pixel_data.len() {
        rgb.push(pixel_data[i + 2]); // R
        rgb.push(pixel_data[i + 1]); // G
        rgb.push(pixel_data[i]); // B
        i += bytes_per_pixel;
    }

    Some(rgb)
}

/// Extract pixels from PPM (P6 binary format).
fn extract_ppm_pixels(data: &[u8]) -> Option<Vec<u8>> {
    let header = std::str::from_utf8(&data[..data.len().min(100)]).ok()?;
    if !header.starts_with("P6") {
        return None;
    }
    // Find end of header (after width height maxval)
    let mut pos = 2;
    let mut numbers_found = 0;
    while pos < data.len() && numbers_found < 3 {
        // Skip whitespace and comments
        while pos < data.len() && (data[pos] == b' ' || data[pos] == b'\n' || data[pos] == b'\r') {
            pos += 1;
        }
        if pos < data.len() && data[pos] == b'#' {
            while pos < data.len() && data[pos] != b'\n' {
                pos += 1;
            }
            continue;
        }
        // Read number
        while pos < data.len() && data[pos].is_ascii_digit() {
            pos += 1;
        }
        numbers_found += 1;
    }
    // Skip the single whitespace after maxval
    if pos < data.len() {
        pos += 1;
    }
    if pos >= data.len() {
        return None;
    }
    Some(data[pos..].to_vec())
}

/// Extract pixels from PNG using minimal decoder (IDAT decompression).
/// This is a simplified decoder — handles standard 8-bit RGB/RGBA PNGs.
fn extract_png_pixels(data: &[u8]) -> Option<Vec<u8>> {
    // Check PNG signature
    if data.len() < 8 || &data[0..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }

    // Parse IHDR
    let mut pos = 8;
    if pos + 25 > data.len() {
        return None;
    }
    let ihdr_len =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if &data[pos..pos + 4] != b"IHDR" || ihdr_len < 13 {
        return None;
    }
    pos += 4;
    let width =
        u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    let height =
        u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]) as usize;
    let bit_depth = data[pos + 8];
    let color_type = data[pos + 9];
    pos += ihdr_len + 4; // skip CRC

    if bit_depth != 8 || (color_type != 2 && color_type != 6) {
        return None; // Only 8-bit RGB (2) or RGBA (6)
    }

    let channels: usize = if color_type == 2 { 3 } else { 4 };

    // Collect all IDAT chunks
    let mut compressed = Vec::new();
    while pos + 12 <= data.len() {
        let chunk_len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + 4 > data.len() {
            break;
        }
        let chunk_type = &data[pos..pos + 4];
        pos += 4;
        if chunk_type == b"IDAT" {
            if pos + chunk_len <= data.len() {
                compressed.extend_from_slice(&data[pos..pos + chunk_len]);
            }
        } else if chunk_type == b"IEND" {
            break;
        }
        pos += chunk_len + 4; // data + CRC
    }

    if compressed.is_empty() {
        return None;
    }

    // Decompress zlib
    let decompressed = miniz_decompress(&compressed)?;

    // Unfilter rows (filter byte + pixel data per row)
    let row_bytes = 1 + width * channels;
    if decompressed.len() < height * row_bytes {
        return None;
    }

    let mut pixels = Vec::with_capacity(width * height * 3);
    let mut prev_row: Vec<u8> = vec![0; width * channels];

    for y in 0..height {
        let row_start = y * row_bytes;
        let filter = decompressed[row_start];
        let row_data = &decompressed[row_start + 1..row_start + row_bytes];

        let mut current_row = vec![0u8; width * channels];

        for x in 0..width * channels {
            let raw = row_data[x];
            let a = if x >= channels {
                current_row[x - channels]
            } else {
                0
            };
            let b = prev_row[x];
            let c = if x >= channels {
                prev_row[x - channels]
            } else {
                0
            };

            current_row[x] = match filter {
                0 => raw,                                                 // None
                1 => raw.wrapping_add(a),                                 // Sub
                2 => raw.wrapping_add(b),                                 // Up
                3 => raw.wrapping_add(((a as u16 + b as u16) / 2) as u8), // Average
                4 => raw.wrapping_add(paeth(a, b, c)),                    // Paeth
                _ => raw,
            };
        }

        // Extract RGB (skip alpha if RGBA)
        for x in 0..width {
            pixels.push(current_row[x * channels]); // R
            pixels.push(current_row[x * channels + 1]); // G
            pixels.push(current_row[x * channels + 2]); // B
        }

        prev_row = current_row;
    }

    Some(pixels)
}

/// Paeth predictor for PNG filtering.
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = a as i16 + b as i16 - c as i16;
    let pa = (p - a as i16).unsigned_abs();
    let pb = (p - b as i16).unsigned_abs();
    let pc = (p - c as i16).unsigned_abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// Minimal zlib/deflate decompressor using flate2 (already a dep via other crates).
fn miniz_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

// ---------------------------------------------------------------------------
// Statistical detectors
// ---------------------------------------------------------------------------

/// Run all 4 detectors and fuse results.
fn analyze_pixels(rgb: &[u8], threshold: f64) -> StegoResult {
    // Separate channels
    let red: Vec<u8> = rgb.iter().step_by(3).copied().collect();
    let green: Vec<u8> = rgb.iter().skip(1).step_by(3).copied().collect();
    let blue: Vec<u8> = rgb.iter().skip(2).step_by(3).copied().collect();

    let channels = [&red, &green, &blue];

    // Run each detector on each channel, average
    let chi = channels.iter().map(|c| chi_square_attack(c)).sum::<f64>() / 3.0;
    let rs = channels.iter().map(|c| rs_analysis(c)).sum::<f64>() / 3.0;
    let spa = channels
        .iter()
        .map(|c| sample_pairs_analysis(c))
        .sum::<f64>()
        / 3.0;
    let ps = channels.iter().map(|c| primary_sets(c)).sum::<f64>() / 3.0;

    // Normalize to [0, 1] and fuse
    let chi_norm = chi; // already 0-1 (p-value)
    let rs_norm = (rs * 2.0).min(1.0);
    let spa_norm = (spa * 2.0).min(1.0);
    let ps_norm = (ps * 2.0).min(1.0);

    let fusion = (chi_norm + rs_norm + spa_norm + ps_norm) / 4.0;

    StegoResult {
        chi_square: chi,
        rs_analysis: rs,
        sample_pairs: spa,
        primary_sets: ps,
        fusion,
        is_stego: fusion > threshold,
    }
}

/// Chi-Square Attack: detect equalized Pairs of Values (PoVs).
fn chi_square_attack(channel: &[u8]) -> f64 {
    let mut hist = [0u32; 256];
    for &v in channel {
        hist[v as usize] += 1;
    }

    let mut chi2 = 0.0;
    let mut df = 0u32;

    for k in (0..256).step_by(2) {
        let n_even = hist[k] as f64;
        let n_odd = hist[k + 1] as f64;
        let total = n_even + n_odd;
        if total > 0.0 {
            chi2 += (n_even - n_odd).powi(2) / total;
            df += 1;
        }
    }

    if df == 0 {
        return 0.0;
    }

    // p-value from chi-square distribution
    // Using approximation: 1 - regularized_gamma(df/2, chi2/2)
    1.0 - chi_square_cdf(chi2, df as f64)
}

/// RS Analysis: Regular/Singular group detection.
fn rs_analysis(channel: &[u8]) -> f64 {
    if channel.len() < 4 {
        return 0.0;
    }

    let mask = [false, true, true, false]; // M = [0, 1, 1, 0]
    let n_groups = channel.len() / 4;

    let mut r_m = 0u32; // Regular groups (positive flip)
    let mut s_m = 0u32; // Singular groups (positive flip)
    let mut r_nm = 0u32; // Regular groups (negative flip)
    let mut s_nm = 0u32; // Singular groups (negative flip)

    for g in 0..n_groups {
        let base = g * 4;
        let group: [u8; 4] = [
            channel[base],
            channel[base + 1],
            channel[base + 2],
            channel[base + 3],
        ];

        let f_orig = smoothness(&group);

        // Positive flip (F1: XOR 1 on masked positions)
        let mut g_pos = group;
        for i in 0..4 {
            if mask[i] {
                g_pos[i] ^= 1;
            }
        }
        let f_pos = smoothness(&g_pos);

        // Negative flip (F-1: shift pairs)
        let mut g_neg = group;
        for i in 0..4 {
            if mask[i] {
                g_neg[i] = flip_negative(g_neg[i]);
            }
        }
        let f_neg = smoothness(&g_neg);

        // Classify
        if f_pos > f_orig {
            r_m += 1;
        } else if f_pos < f_orig {
            s_m += 1;
        }
        if f_neg > f_orig {
            r_nm += 1;
        } else if f_neg < f_orig {
            s_nm += 1;
        }
    }

    let r_m = r_m as f64 / n_groups as f64;
    let s_m = s_m as f64 / n_groups as f64;
    let r_nm = r_nm as f64 / n_groups as f64;
    let s_nm = s_nm as f64 / n_groups as f64;

    let denom = r_nm - s_nm;
    if denom.abs() < 1e-10 {
        return 0.0;
    }

    let ratio = (r_m - s_m) / denom;
    let embedding = (1.0 - ratio) * 0.5;
    embedding.clamp(0.0, 0.5)
}

/// Sample Pairs Analysis.
fn sample_pairs_analysis(channel: &[u8]) -> f64 {
    if channel.len() < 2 {
        return 0.0;
    }

    let mut cm_e = 0u64; // Close-match pairs, first even
    let mut cm_o = 0u64; // Close-match pairs, first odd

    for i in 0..channel.len() - 1 {
        let u = channel[i];
        let v = channel[i + 1];
        let hu = u >> 1;
        let hv = v >> 1;

        if hu == hv {
            if u.is_multiple_of(2) {
                cm_e += 1;
            } else {
                cm_o += 1;
            }
        }
    }

    let d = (channel.len() - 1) as f64;
    let cm_e = cm_e as f64;
    let cm_o = cm_o as f64;

    // Quadratic: a*x^2 + b*x + c = 0
    let a = 2.0 * (2.0 * cm_e - d);
    let b = d - 2.0 * cm_o;
    let c = -(cm_e - cm_o);

    if a.abs() < 1e-10 {
        return 0.0;
    }

    let discriminant = b * b - 4.0 * a * c;
    if discriminant < 0.0 {
        return 0.0;
    }

    let sqrt_disc = discriminant.sqrt();
    let x1 = (-b + sqrt_disc) / (2.0 * a);
    let x2 = (-b - sqrt_disc) / (2.0 * a);

    // Choose root in [0, 0.5]
    let x = if (0.0..=0.5).contains(&x1) {
        x1
    } else if (0.0..=0.5).contains(&x2) {
        x2
    } else {
        x1.abs().min(x2.abs()).min(0.5)
    };

    x.clamp(0.0, 0.5)
}

/// Primary Sets analysis (histogram-based PoV analysis).
fn primary_sets(channel: &[u8]) -> f64 {
    let mut hist = [0u32; 256];
    for &v in channel {
        hist[v as usize] += 1;
    }

    let total = channel.len() as f64;
    if total == 0.0 {
        return 0.0;
    }

    let mut excess = 0.0;
    for k in (0..256).step_by(2) {
        let p = hist[k] as f64;
        let q = hist[k + 1] as f64;
        excess += (p - q).abs();
    }

    // Normalize: clean images have high excess, stego has low
    // Expected excess for random image ~ sqrt(total) * some_constant
    let expected = total.sqrt() * 4.0; // empirical constant
    let score = 1.0 - (excess / expected).min(1.0);

    score.clamp(0.0, 0.5)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Smoothness function for RS Analysis.
fn smoothness(group: &[u8]) -> f64 {
    let mut sum = 0.0;
    for i in 1..group.len() {
        sum += (group[i] as f64 - group[i - 1] as f64).abs();
    }
    sum
}

/// Negative flip for RS Analysis: F-1.
fn flip_negative(x: u8) -> u8 {
    if x == 0 {
        1
    } else if x == 255 {
        254
    } else if x.is_multiple_of(2) {
        x - 1
    } else {
        x + 1
    }
}

/// Chi-square CDF approximation using the regularized incomplete gamma function.
/// P(X <= x) for chi-square distribution with k degrees of freedom.
fn chi_square_cdf(x: f64, k: f64) -> f64 {
    if x <= 0.0 || k <= 0.0 {
        return 0.0;
    }
    regularized_gamma_p(k / 2.0, x / 2.0)
}

/// Regularized lower incomplete gamma function P(a, x) = gamma(a, x) / Gamma(a).
/// Uses series expansion for small x, continued fraction for large x.
fn regularized_gamma_p(a: f64, x: f64) -> f64 {
    if x < 0.0 {
        return 0.0;
    }
    if x == 0.0 {
        return 0.0;
    }
    if x < a + 1.0 {
        // Series expansion
        gamma_series(a, x)
    } else {
        // Continued fraction
        1.0 - gamma_cf(a, x)
    }
}

fn gamma_series(a: f64, x: f64) -> f64 {
    let mut sum = 1.0 / a;
    let mut term = 1.0 / a;
    for n in 1..200 {
        term *= x / (a + n as f64);
        sum += term;
        if term.abs() < 1e-12 * sum.abs() {
            break;
        }
    }
    sum * (-x + a * x.ln() - ln_gamma(a)).exp()
}

fn gamma_cf(a: f64, x: f64) -> f64 {
    let mut c = 1e-30_f64;
    let mut d = 1.0 / (x + 1.0 - a);
    let mut f = d;

    for n in 1..200 {
        let an = -(n as f64) * (n as f64 - a);
        let bn = x + 2.0 * n as f64 + 1.0 - a;
        d = bn + an * d;
        if d.abs() < 1e-30 {
            d = 1e-30;
        }
        c = bn + an / c;
        if c.abs() < 1e-30 {
            c = 1e-30;
        }
        d = 1.0 / d;
        let delta = c * d;
        f *= delta;
        if (delta - 1.0).abs() < 1e-12 {
            break;
        }
    }

    f * (-x + a * x.ln() - ln_gamma(a)).exp()
}

/// Natural log of the Gamma function (Lanczos approximation).
fn ln_gamma(x: f64) -> f64 {
    let coeffs = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let y = x;
    let mut tmp = x + 5.5;
    tmp -= (x + 0.5) * tmp.ln();
    let mut ser = 1.000000000190015;
    for (j, &coeff) in coeffs.iter().enumerate() {
        ser += coeff / (y + 1.0 + j as f64);
    }
    -tmp + (2.5066282746310005 * ser / x).ln()
}

fn truncate_path(path: &str, max: usize) -> &str {
    if path.len() <= max {
        path
    } else {
        &path[path.len() - max..]
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chi_square_natural_data() {
        // Simulate natural image: values clustered with odd/even asymmetry
        let mut channel = vec![0u8; 10000];
        for (i, v) in channel.iter_mut().enumerate() {
            // Natural images have unequal PoV distributions
            let base = ((i * 37 + i / 3) % 200 + 20) as u8;
            // Add bias: even values slightly more frequent
            *v = if i % 3 == 0 { base & 0xFE } else { base };
        }
        let score = chi_square_attack(&channel);
        // Natural data with PoV asymmetry → low p-value (not stego)
        assert!(
            score < 0.8,
            "natural data chi score {score} should be below 0.8"
        );
    }

    #[test]
    fn chi_square_equalized_pairs() {
        // Equalized PoV pairs = stego signature
        let mut channel = Vec::new();
        for k in 0..128 {
            // Equal counts of even and odd in each pair
            for _ in 0..50 {
                channel.push(k * 2);
                channel.push(k * 2 + 1);
            }
        }
        let score = chi_square_attack(&channel);
        // Should be high p-value (stego detected)
        assert!(
            score > 0.5,
            "equalized PoVs chi score {score} should be high"
        );
    }

    #[test]
    fn rs_analysis_clean() {
        // Natural image-like data
        let channel: Vec<u8> = (0..1000).map(|i| ((i * 3 + i / 7) % 256) as u8).collect();
        let score = rs_analysis(&channel);
        assert!(score < 0.2, "clean data RS score {score} should be low");
    }

    #[test]
    fn sample_pairs_clean() {
        let channel: Vec<u8> = (0..1000).map(|i| ((i * 3 + i / 7) % 256) as u8).collect();
        let score = sample_pairs_analysis(&channel);
        assert!(score < 0.3, "clean data SPA score {score} should be low");
    }

    #[test]
    fn primary_sets_clean() {
        let channel: Vec<u8> = (0..1000).map(|i| ((i * 3 + i / 7) % 256) as u8).collect();
        let score = primary_sets(&channel);
        assert!(score < 0.3, "clean data PS score {score} should be low");
    }

    #[test]
    fn fusion_natural_data() {
        // Simulate natural image with PoV asymmetry
        let rgb: Vec<u8> = (0..3000)
            .map(|i| {
                let base = ((i * 37 + i / 5 + (i % 7) * 13) % 200 + 20) as u8;
                if i % 3 == 0 {
                    base & 0xFE
                } else {
                    base
                }
            })
            .collect();
        let result = analyze_pixels(&rgb, STEGO_THRESHOLD);
        // Natural data should have fusion well below 1.0
        assert!(
            result.fusion < 0.5,
            "natural data fusion {:.3} should be below 0.5",
            result.fusion
        );
    }

    #[test]
    fn bmp_extraction() {
        // Minimal valid BMP: 2x1 pixels, 24bpp
        let mut bmp = vec![0u8; 54 + 8]; // header + 2 pixels (padded to 4-byte row)
        bmp[0] = b'B';
        bmp[1] = b'M';
        // File size
        let size = bmp.len() as u32;
        bmp[2..6].copy_from_slice(&size.to_le_bytes());
        // Data offset
        bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
        // DIB header size
        bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
        // Width
        bmp[18..22].copy_from_slice(&2u32.to_le_bytes());
        // Height
        bmp[22..26].copy_from_slice(&1u32.to_le_bytes());
        // Planes
        bmp[26..28].copy_from_slice(&1u16.to_le_bytes());
        // BPP
        bmp[28..30].copy_from_slice(&24u16.to_le_bytes());
        // Compression = 0
        // Pixel data: BGR BGR padding
        bmp[54] = 255; // B
        bmp[55] = 0; // G
        bmp[56] = 0; // R  → pixel 1 = (0, 0, 255) = blue
        bmp[57] = 0; // B
        bmp[58] = 255; // G
        bmp[59] = 0; // R  → pixel 2 = (0, 255, 0) = green

        let pixels = extract_bmp_pixels(&bmp).unwrap();
        assert_eq!(pixels.len(), 6); // 2 pixels * 3 channels
        assert_eq!(pixels[0], 0); // R of pixel 1 (was BGR blue)
        assert_eq!(pixels[1], 0); // G
        assert_eq!(pixels[2], 255); // B
    }

    #[test]
    fn ln_gamma_known_values() {
        // Gamma(1) = 1, ln(1) = 0
        assert!((ln_gamma(1.0)).abs() < 0.001);
        // Gamma(5) = 24, ln(24) ≈ 3.178
        assert!((ln_gamma(5.0) - 3.178).abs() < 0.01);
    }
}
