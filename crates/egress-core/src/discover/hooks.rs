//! Build and install hook detection by presence (KTD17, R8). Contents are
//! never analyzed; a hook file in a supported language is also scanned as
//! ordinary source with the `build-hook` label.

use std::collections::BTreeMap;

use super::FileKind;
use super::manifests::{BuildScript, Manifests};
use crate::model::Language;
use crate::paths::file_name;

/// One detected hook: the file the blind spot sits on, its language, and a
/// fixed name for the hook (used as construct text, never scanned input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hook {
    pub path: Vec<u8>,
    pub language: Language,
    pub name: &'static str,
}

/// A hook implied by a file's name alone.
pub fn file_hook(name: &[u8]) -> Option<(Language, &'static str)> {
    match name {
        b"setup.py" => Some((Language::Python, "setup.py")),
        b"sitecustomize.py" => Some((Language::Python, "sitecustomize")),
        b"usercustomize.py" => Some((Language::Python, "usercustomize")),
        b"binding.gyp" => Some((Language::Javascript, "binding.gyp")),
        _ if name.ends_with(b".pth") && name.len() > 4 => Some((Language::Python, "pth")),
        _ => None,
    }
}

fn sibling(manifest: &[u8], name: &str) -> Vec<u8> {
    // The manifest's directory with its trailing `/`, or empty at the root.
    let dir = &manifest[..manifest.len() - file_name(manifest).len()];
    [dir, name.as_bytes()].concat()
}

/// Every hook in the tree. `failed_cargo` lists Cargo manifests that did not
/// parse; their default `build.rs` is still flagged.
pub fn detect(
    index: &BTreeMap<Vec<u8>, FileKind>,
    manifests: &Manifests,
    failed_cargo: &[Vec<u8>],
) -> Vec<Hook> {
    let mut out = Vec::new();
    for path in index.keys() {
        if let Some((language, name)) = file_hook(file_name(path)) {
            out.push(Hook {
                path: path.clone(),
                language,
                name,
            });
        }
    }
    let default_build = |manifest: &[u8], out: &mut Vec<Hook>| {
        let b = sibling(manifest, "build.rs");
        if index.contains_key(&b) {
            out.push(Hook {
                path: b,
                language: Language::Rust,
                name: "build-script",
            });
        }
    };
    for c in &manifests.cargo {
        if c.has_package {
            match &c.build {
                BuildScript::Default => default_build(&c.path, &mut out),
                BuildScript::Path(p) => out.push(Hook {
                    path: if index.contains_key(p) {
                        p.clone()
                    } else {
                        c.path.clone()
                    },
                    language: Language::Rust,
                    name: "build-script",
                }),
                BuildScript::Disabled | BuildScript::Outside => {}
            }
        }
        if c.proc_macro {
            out.push(Hook {
                path: c.path.clone(),
                language: Language::Rust,
                name: "proc-macro",
            });
        }
    }
    for m in failed_cargo {
        default_build(m, &mut out);
    }
    for p in &manifests.package_json {
        for s in &p.lifecycle {
            out.push(Hook {
                path: p.path.clone(),
                language: Language::Javascript,
                name: s,
            });
        }
    }
    for p in &manifests.pyproject {
        if p.build_backend.is_some() && !p.backend_path.is_empty() {
            out.push(Hook {
                path: p.path.clone(),
                language: Language::Python,
                name: "backend-path",
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::sibling;

    #[test]
    fn sibling_replaces_the_file_name() {
        assert_eq!(sibling(b"Cargo.toml", "build.rs"), b"build.rs");
        assert_eq!(sibling(b"a/b/Cargo.toml", "build.rs"), b"a/b/build.rs");
        assert_eq!(sibling(b"/Cargo.toml", "build.rs"), b"/build.rs");
        assert_eq!(sibling(b"a/", "build.rs"), b"a/build.rs");
        assert_eq!(sibling(b"", "build.rs"), b"build.rs");
    }
}
