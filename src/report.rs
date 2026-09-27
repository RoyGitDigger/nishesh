//! Terminal presentation.
//!
//! Kept in one module so the CLI, the demo and any future GUI render the same
//! facts the same way. Colour is disabled automatically when stdout is not a
//! terminal or when NO_COLOR is set, so piped output and log capture stay
//! clean — a tool whose output cannot be diffed is not an auditable tool.

use std::io::{IsTerminal, Write};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[38;5;167m";
pub const GREEN: &str = "\x1b[38;5;71m";
pub const TEAL: &str = "\x1b[38;5;37m";
pub const AMBER: &str = "\x1b[38;5;178m";
pub const BLUE: &str = "\x1b[38;5;68m";
pub const GREY: &str = "\x1b[38;5;245m";

pub fn colour_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

pub fn c(code: &str, text: &str) -> String {
    if colour_enabled() {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

pub fn banner() {
    let art = r#"
   ███╗   ██╗██╗███████╗██╗  ██╗███████╗███████╗██╗  ██╗
   ████╗  ██║██║██╔════╝██║  ██║██╔════╝██╔════╝██║  ██║
   ██╔██╗ ██║██║███████╗███████║█████╗  ███████╗███████║
   ██║╚██╗██║██║╚════██║██╔══██║██╔══╝  ╚════██║██╔══██║
   ██║ ╚████║██║███████║██║  ██║███████╗███████║██║  ██║
   ╚═╝  ╚═══╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝"#;
    println!("{}", c(TEAL, art));
    println!(
        "   {}  {}",
        c(BOLD, "निःशेष"),
        c(GREY, "leaving nothing behind")
    );
    println!(
        "   {}",
        c(
            GREY,
            "Integrated secure data erasure and advanced file recovery"
        )
    );
    println!(
        "   {}  {}\n",
        c(DIM, "v0.1.0 · SIH26149 · NTRO ·"),
        c(DIM, "NIST SP 800-88 Rev.2 · IEEE 2883-2022")
    );
}

pub fn rule() {
    println!("{}", c(GREY, &"─".repeat(78)));
}

pub fn section(n: &str, title: &str) {
    println!();
    println!(
        "{} {}",
        c(TEAL, &format!("[{n}]")),
        c(BOLD, &title.to_uppercase())
    );
    println!("{}", c(GREY, &"─".repeat(78)));
}

pub fn kv(key: &str, value: &str) {
    println!("  {:<30} {}", c(GREY, key), value);
}

pub fn kv_hi(key: &str, value: &str, colour: &str) {
    println!("  {:<30} {}", c(GREY, key), c(colour, value));
}

pub fn note(text: &str) {
    for line in wrap(text, 74) {
        println!("  {}", c(GREY, &line));
    }
}

pub fn warn(text: &str) {
    println!("  {} {}", c(AMBER, "!"), c(AMBER, text));
}

pub fn fail(text: &str) {
    println!("  {} {}", c(RED, "✗"), c(RED, text));
}

pub fn pass(text: &str) {
    println!("  {} {}", c(GREEN, "✓"), text);
}

pub fn step(text: &str) {
    println!("  {} {}", c(BLUE, "→"), text);
}

/// Wrap on word boundaries so long rationale text stays readable on camera.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

pub fn table(headers: &[&str], rows: &[Vec<String>]) {
    if rows.is_empty() {
        println!("  {}", c(GREY, "(no rows)"));
        return;
    }
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in rows {
        for (i, cell) in r.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(display_len(cell));
            }
        }
    }
    let header: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:<w$}", h, w = widths[i]))
        .collect();
    println!("  {}", c(BOLD, &header.join("  ")));
    println!(
        "  {}",
        c(GREY, &widths.iter().map(|w| "─".repeat(*w)).collect::<Vec<_>>().join("  "))
    );
    for r in rows {
        let cells: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let pad = widths.get(i).copied().unwrap_or(0).saturating_sub(display_len(cell));
                format!("{}{}", cell, " ".repeat(pad))
            })
            .collect();
        println!("  {}", cells.join("  "));
    }
}

/// Length ignoring ANSI escapes, so coloured cells still align.
fn display_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for ch in s.chars() {
        if in_esc {
            if ch == 'm' {
                in_esc = false;
            }
        } else if ch == '\x1b' {
            in_esc = true;
        } else {
            n += 1;
        }
    }
    n
}

/// Single-line progress bar. Redraws in place, so the recording shows real
/// throughput rather than a wall of scrolling text.
pub fn progress(label: &str, done: u64, total: u64) {
    if total == 0 || !colour_enabled() {
        return;
    }
    let width = 34usize;
    let frac = (done as f64 / total as f64).clamp(0.0, 1.0);
    let filled = (frac * width as f64).round() as usize;
    let bar = format!(
        "{}{}",
        "█".repeat(filled),
        c(GREY, &"░".repeat(width - filled))
    );
    print!(
        "\r  {:<18} {} {:>6.1}%  {}",
        c(GREY, label),
        c(TEAL, &bar),
        frac * 100.0,
        c(DIM, &human(done))
    );
    let _ = std::io::stdout().flush();
    if done >= total {
        println!();
    }
}

pub fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", bytes, U[0])
    } else {
        format!("{:.2} {}", v, U[i])
    }
}

/// The verdict panel. This is the frame the demo pauses on.
pub fn verdict(passed: bool, headline: &str, lines: &[String]) {
    let (colour, mark, word) = if passed {
        (GREEN, "✓", "PASS")
    } else {
        (RED, "✗", "FAIL")
    };
    println!();
    println!("  {}", c(colour, &"═".repeat(74)));
    println!(
        "  {} {}   {}",
        c(colour, mark),
        c(BOLD, &c(colour, word)),
        c(BOLD, headline)
    );
    println!("  {}", c(colour, &"═".repeat(74)));
    for l in lines {
        println!("  {}", l);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_never_exceeds_width() {
        let text = "the quick brown fox jumps over the lazy dog and keeps on running \
                    far past the margin";
        for line in wrap(text, 20) {
            assert!(line.len() <= 20, "line too long: {line:?}");
        }
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2.00 KiB");
        assert_eq!(human(20 * 1024 * 1024), "20.00 MiB");
    }

    #[test]
    fn display_length_ignores_escapes() {
        assert_eq!(display_len("\x1b[31mabc\x1b[0m"), 3);
        assert_eq!(display_len("abc"), 3);
    }
}
