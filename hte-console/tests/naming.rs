//! HTE Remote's name (phase 9, 2.0.0). Fails on anything that brings the old name back: "CortenDesk" on a page, in a template or in a
//! string a person reads; a `CORTENDESK_*` setting read directly; `std::env::var` in the library (it must go through `envvar::var`, which
//! reads `HTE_REMOTE_<X>` first and the old name as a fallback). Run after every merge of a branch written before the rename.

use std::fs;
use std::path::{Path, PathBuf};

fn files(dir: &Path, ext: &[&str], out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, ext, out);
        } else if p.extension().and_then(|x| x.to_str()).map_or(false, |x| ext.contains(&x)) {
            out.push(p);
        }
    }
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Lines that may say CortenDesk: the one credit, licence-required notices, and the web client's own replacements of the name.
const ALLOWED: [&str; 10] = [
    "github.com/marcpope/cortendesk", // Settings > About: the credit
    "Corten<span>Desk</span>",        // webclient.rs: what the bundled web client says, replaced at serve time
    "alt=\"CortenDesk\"",
    "\\u2014 CortenDesk`",
    "\\xB7 CortenDesk`",
    "(\"CortenDesk Web Client\"", // webclient.rs: the manifest's name, replaced at serve time
    "slug(\"CortenDesk\")",           // cache.rs: Laravel's slug of the old default APP_NAME, a test
    "(from CortenDesk)",              // asset header comments: where the file came from
    "Modified for CortenDesk",        // remixicon.css: the licence's modification notice
    "CortenDesk's",                   // hte-brand.css / webclient.rs: comments on what the brand replaces
];

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with("{#") || t.starts_with("<!--")
}

#[test]
fn no_old_name_where_a_person_reads_it() {
    let mut list = vec![];
    files(&root().join("templates"), &["html", "txt", "js"], &mut list);
    files(&root().join("src"), &["rs"], &mut list);
    files(&root().join("assets/css"), &["css"], &mut list);
    files(&root().join("assets/js"), &["js"], &mut list);
    let mut bad = vec![];
    for f in &list {
        let text = fs::read_to_string(f).unwrap();
        let rs = f.extension().map_or(false, |x| x == "rs");
        let block_comments = f.extension().map_or(false, |x| x == "css" || x == "js" || x == "rs");
        let mut in_tests = false;
        let mut in_block = false;
        for (n, line) in text.lines().enumerate() {
            // inside a /* ... */ block (CSS, JS, Rust): the line is a comment
            let was_in_block = in_block;
            if block_comments {
                if let (Some(o), c) = (line.rfind("/*"), line.rfind("*/")) {
                    in_block = c.map_or(true, |c| c < o);
                } else if line.contains("*/") {
                    in_block = false;
                }
            }
            if rs && line.starts_with("#[cfg(test)]") {
                in_tests = true; // unit tests may name the old strings they check against
            }
            if in_tests || !line.contains("CortenDesk") {
                continue;
            }
            // an allowed phrase counts in a comment, or in the files whose job it is (the credit, the web client's replacements, a slug test)
            let fname = f.file_name().unwrap().to_str().unwrap();
            let owner = ["webclient.rs", "cache.rs", "index.html"].contains(&fname);
            let comment = was_in_block || is_comment(line);
            if (comment || owner) && ALLOWED.iter().any(|a| line.contains(a)) {
                continue;
            }
            if (rs || block_comments) && comment && !f.to_string_lossy().contains("/templates/") {
                continue; // history in source comments is fine; strings are not
            }
            bad.push(format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim()));
        }
    }
    assert!(bad.is_empty(), "\"CortenDesk\" where a person reads it (say HTE Remote):\n{}", bad.join("\n"));
}

#[test]
fn settings_go_through_envvar() {
    let mut list = vec![];
    files(&root().join("src"), &["rs"], &mut list);
    files(&root().join("templates"), &["html"], &mut list);
    let mut bad = vec![];
    for f in &list {
        let name = f.file_name().unwrap().to_str().unwrap();
        if name == "envvar.rs" {
            continue;
        }
        let text = fs::read_to_string(f).unwrap();
        for (n, line) in text.lines().enumerate() {
            let at = format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim());
            let bare = line.replace("envvar::var(", "");
            if name != "main.rs" && ["env::var(", "env::var_os(", "env::vars("].iter().any(|x| bare.contains(x)) {
                bad.push(format!("{at}   <- use crate::envvar::var"));
            }
            if line.contains("CORTENDESK_") && !is_comment(line) {
                bad.push(format!("{at}   <- the setting is HTE_REMOTE_<X> (envvar::var falls back to the old name)"));
            }
        }
    }
    assert!(bad.is_empty(), "settings read around the HTE_REMOTE_* names:\n{}", bad.join("\n"));
}

/// Lower case in what the browser gets (file names, placeholders): only the credit's links may name the old project.
#[test]
fn no_old_name_in_templates_lower_case() {
    let mut list = vec![];
    files(&root().join("templates"), &["html", "txt"], &mut list);
    let mut bad = vec![];
    for f in &list {
        for (n, line) in fs::read_to_string(f).unwrap().lines().enumerate() {
            if line.contains("github.com/marcpope/cortendesk") {
                continue; // the credit line (Settings > About)
            }
            let rest = line.to_string();
            if rest.to_ascii_lowercase().contains("cortendesk") && !is_comment(line) {
                bad.push(format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim()));
            }
        }
    }
    assert!(bad.is_empty(), "the old name in a template (say hte-remote):\n{}", bad.join("\n"));
}

/// The pages show HTE Remote's version (`crate::REMOTE_VERSION`); `api_version` (the PHP release the client API matches) is for the
/// client API, the web client's config, Diagnostics' export and the About card's "Client API level" only.
#[test]
fn pages_show_hte_remote_s_version() {
    let mut list = vec![];
    files(&root().join("src"), &["rs"], &mut list);
    let mut bad = vec![];
    for f in &list {
        let name = f.file_name().unwrap().to_str().unwrap();
        if ["webclient.rs", "diagnostics.rs"].contains(&name) {
            continue;
        }
        for (n, line) in fs::read_to_string(f).unwrap().lines().enumerate() {
            let l: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let from_api = ["\"version\":p.n.api_version", "\"version\":ctx.p.n.api_version", "\"version\":self.p.n.api_version", "\"version\".into(),json!(p.n.api_version", "\"version\".into(),json!(ctx.p.n.api_version"];
            if from_api.iter().any(|x| l.contains(x)) || (l.contains("render_page(") && l.contains("api_version")) {
                bad.push(format!("{}:{}: {}", f.strip_prefix(root()).unwrap().display(), n + 1, line.trim()));
            }
        }
    }
    assert!(bad.is_empty(), "a page's \"version\" from api_version (use crate::REMOTE_VERSION):\n{}", bad.join("\n"));
}

/// Every text file of the repository: the root walked once, without the upstream submodule, build output, git, the vendored
/// third-party assets and the bundled web client (minified upstream code).
fn repository_text_files() -> Vec<PathBuf> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name == ".git" || name == ".DS_Store" {
                continue; // a worktree's .git file names the local checkout, not a repository file
            }
            if p.is_dir() {
                if !["libs", "target", ".git", "vendor", "rdclient", "node_modules"].contains(&name.as_str()) {
                    walk(&p, out);
                }
            } else if !matches!(p.extension().and_then(|x| x.to_str()), Some("png" | "jpg" | "jpeg" | "ico" | "woff" | "woff2" | "ttf" | "sqlite3" | "lock" | "gz" | "tar")) {
                out.push(p);
            }
        }
    }
    let mut out = vec![];
    walk(&root().join(".."), &mut out);
    out
}

/// SHA-256 of private words and word pairs/triples (lower case, tokens of letters and digits): the company, people, the deployment's
/// domain, hosts and paths. Only the digests are here, so this file publishes none of them.
const PRIVATE_DIGESTS: [&str; 10] = [
    "41d41e4a03aa8226c9819a94f0d5ca5caf01afaf51c22e33309f9d6ff13783a3",
    "f4b06aa29ab865363a48cdebbb72f9cc73d768a5e63f6a870abb087a20c4ca77",
    "e2c893f95bbf1908d0807a369a0ae8a3d8624c14335af2655ee0a503418968fa",
    "9ae1a6124dcc1271920422f910bf867163649d42f7e09abbd19eecc5801e679d",
    "7c4527cc6e4b3c2f0cb6ca12191e9603deaeff8a604696f34d5b75e9ae3c480a",
    "ba4db3a7cc3d135fee36ead13dcbb5a4261b1c770357cac9eda40a43ef79daf8",
    "600eb8471f4ab24379fc3bb7efdb6e541bf6cbea53b9914d873da633fe5a2e2f",
    "fcc2dc2639c9f08b1f6f3e53b649dd5ba0765aac399aabbd8ba4a81f92c39534",
    "7e8aeb06cde35c71163458a849506904c20c0d2711d355e1fe8e55934bd3116e",
    "c1ad4fc52173a9dbcfee4731a379cd4f7972d9dca272f7b58374f91da3477bb0",
];

/// The public repository names no company, person, private host, internal path or deployment: the product is "HTE Remote" and
/// deployments are described with placeholders (example.com, <your-server>).
#[test]
fn no_company_or_private_details_in_the_repository() {
    use sha2::{Digest, Sha256};
    let digest = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    let token = regex::Regex::new(r"[a-z0-9]+").unwrap();
    let email = regex::Regex::new(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}").unwrap();
    let guid = regex::Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b").unwrap();
    let generic = regex::Regex::new(r"(?i)\bvps\b|sharepoint|onmicrosoft").unwrap();
    let mut bad = vec![];
    for f in repository_text_files() {
        let Ok(text) = fs::read_to_string(&f) else { continue };
        let rel = f.strip_prefix(root().join("..")).unwrap_or(&f).display().to_string();
        if rel.ends_with("tests/naming.rs") {
            continue; // its patterns name what they look for
        }
        for (n, line) in text.lines().enumerate() {
            let low = line.to_ascii_lowercase();
            let toks: Vec<&str> = token.find_iter(&low).map(|m| m.as_str()).collect();
            let mut hit = None;
            for k in 0..toks.len() {
                for w in 1..=3 {
                    if k + w <= toks.len() && PRIVATE_DIGESTS.contains(&digest(&toks[k..k + w].join(" ")).as_str()) {
                        hit = Some("a private name");
                    }
                }
            }
            if generic.is_match(line) {
                hit = Some("a deployment detail");
            }
            for m in email.find_iter(line) {
                let a = m.as_str().to_ascii_lowercase();
                // test addresses: example domains, reserved TLDs, one- or two-letter domains (a@b.co), and a few obvious stand-ins
                let domain = a.rsplit('@').next().unwrap_or("");
                let second = domain.rsplit('.').nth(1).unwrap_or("");
                let ok = [".example", "@example.", ".invalid", ".test", "noreply", "opentradesolutions.com", "elsewhere.org", "other.org"].iter().any(|x| a.contains(x))
                    || second.len() <= 2;
                if !ok {
                    hit = Some("an e-mail address");
                }
            }
            for m in guid.find_iter(line) {
                let g = m.as_str().to_ascii_lowercase();
                let ok = g.starts_with("00000000-0000-") || g == "9188040d-6c67-4c5b-b112-36a304b66dad"
                    || ["e4c181d0-41c7-4ae6-8ef0-36581b6b2b12", "01890a5d-ac96-774b-bcce-b302099a8057"].contains(&g.as_str()) // example uuids of hbbs's relay-uuid tests (UUID v4 and v7 shapes)
                    || g.contains("1111-4222");
                if !ok {
                    hit = Some("a GUID (tenant or client id?)");
                }
            }
            if let Some(what) = hit {
                bad.push(format!("{rel}:{}: {what}", n + 1)); // the line itself is not printed: CI logs are public too
            }
        }
    }
    assert!(bad.is_empty(), "company, personal or deployment details in the public repository:\n{}", bad.join("\n"));
}

/// The previous console (CortenDesk, written in PHP with Livewire, served by nginx) is not part of this project. Its name may appear
/// where this project reads its formats or credits it, nowhere else: docs, image files, templates and assets never; Rust only in
/// identifiers (the compatibility modules `php`, `laravel`), and in the strings listed here, each with its reason.
#[test]
fn no_previous_console_runtime_in_the_repository() {
    let word = regex::Regex::new(r"(?i)\bphp\b(?:\.rs)?|livewire|\bnginx\b|\bartisan\b|\bblade\b").unwrap();
    let string = regex::Regex::new(r#""(?:[^"\\]|\\.)*""#).unwrap();
    // (file, text on the line) -> why it stays
    let allowed: [(&str, &str, &str); 8] = [
        ("cache.rs", "php artisan", "the scheduler's lock name is sha1 of the previous console's command line: the lock format"),
        ("housekeeping.rs", "php artisan", "the same lock name, asserted"),
        ("server_link.rs", "php artisan", "the same lock name, asserted"),
        ("sanitise.rs", "\"php\"", "a file extension the sanitiser treats as a path, not a word"),
        ("standalone.rs", "/livewire", "proves the previous console's live-update endpoints answer 404 here"),
        ("README.md", "php.rs", "the compatibility module, named"),
        ("mod.rs", "`php` (the field)", "the Pages field holding the optional upstream router (kept: a rename touches every test harness)"),
        ("naming.rs", "", "this test"),
    ];
    // whole files whose subject is the comparison with the previous console (used by tests with two hte-console instances)
    let comparison = ["webreplay.rs"];
    let mut bad = vec![];
    for f in repository_text_files() {
        let rel = f.strip_prefix(root().join("..")).unwrap_or(&f).display().to_string();
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if comparison.contains(&name.as_str()) || rel.starts_with("hte-console/fixtures/") || rel.ends_with("CHANGES.md") || rel == "Cargo.lock" {
            continue; // golden answers recorded from the previous console, and change logs (history)
        }
        let Ok(text) = fs::read_to_string(&f) else { continue };
        let rs = name.ends_with(".rs");
        for (n, line) in text.lines().enumerate() {
            // Rust: comments and string literals only (identifiers such as `crate::php::Val`, `to_php_string` are the compat modules)
            let scope: String = if rs {
                let t = line.trim_start();
                if t.starts_with("//") || t.starts_with("* ") || t.trim_end() == "*" || t.starts_with("*/") || t.starts_with("/*") {
                    line.to_string()
                } else {
                    let code = line.split("//").next().unwrap_or("");
                    let mut s: Vec<String> = string.find_iter(code).map(|m| m.as_str().to_string()).collect();
                    if code.len() < line.len() {
                        s.push(line[code.len()..].to_string());
                    }
                    s.join(" ")
                }
            } else {
                line.to_string()
            };
            if !word.is_match(&scope) {
                continue;
            }
            if allowed.iter().any(|(file, text, _)| name == *file && line.contains(text)) {
                continue;
            }
            bad.push(format!("{rel}:{}: {}", n + 1, line.trim()));
        }
    }
    assert!(bad.is_empty(), "the previous console named outside its compatibility code (say \"the previous console\"):\n{}", bad.join("\n"));
}

#[test]
fn new_archives_have_the_new_name() {
    assert_eq!(hte_console::backup::PREFIX, "hte-remote-backup-");
    assert!(hte_console::backup::is_backup_name("cortendesk-backup-20261024-033000.tar"), "old archives stay restorable");
}

/// The web terminal is xterm.js (MIT): the licence travels with the bundle and the credit is in NOTICE.
#[test]
fn the_terminal_s_licence_is_kept() {
    let licence = fs::read_to_string(root().join("rdclient/LICENSE-xterm.txt")).unwrap();
    assert!(licence.contains("The MIT License") && licence.contains("The xterm.js authors") && licence.contains("Permission is hereby granted"));
    let notice = fs::read_to_string(root().join("NOTICE")).unwrap();
    assert!(notice.contains("xterm.js") && notice.contains("LICENSE-xterm.txt"));
    let chunks: Vec<String> = fs::read_dir(root().join("rdclient/chunks")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
    assert!(chunks.iter().any(|c| c.starts_with("xterm-") && c.ends_with(".js.LEGAL.txt")), "the bundled notice stays beside the chunk: {chunks:?}");
}
