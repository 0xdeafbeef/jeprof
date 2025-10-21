use anyhow::{bail, Context, Result};
use object::{Object, ObjectSymbol, SymbolKind};
use rustc_demangle::try_demangle;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SymEntry {
    pub mangled: String,
    pub demangled: String,
    pub addr: u64,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MatchMode {
    Contains,
    Exact,
    Regex,
}

pub fn list_text_symbols(path: &Path) -> Result<Vec<SymEntry>> {
    let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let obj = object::File::parse(&*data).context("parsing object file")?;

    let mut out = Vec::new();
    for sym in obj.symbols().chain(obj.dynamic_symbols()) {
        if sym.kind() != SymbolKind::Text || sym.is_undefined() {
            continue;
        }
        let Ok(name) = sym.name() else {
            continue;
        };
        let addr = sym.address();
        if addr == 0 {
            continue;
        }
        if name.is_empty() {
            continue;
        }

        let demangled = match try_demangle(name) {
            Ok(value) => format!("{value}"),
            Err(_) => name.to_string(),
        };

        out.push(SymEntry {
            mangled: name.to_string(),
            demangled,
            addr,
        });
    }

    if out.is_empty() {
        bail!("no text symbols found in {}", path.display());
    }
    Ok(out)
}

pub fn filter_symbols<'a>(
    all: &'a [SymEntry],
    patterns: &[String],
    mode: MatchMode,
) -> Result<Vec<&'a SymEntry>> {
    use MatchMode::*;
    if patterns.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    match mode {
        Contains => {
            for sym in all {
                if patterns
                    .iter()
                    .any(|pattern| !pattern.is_empty() && sym.demangled.contains(pattern))
                    && seen.insert(&sym.mangled)
                {
                    out.push(sym);
                }
            }
        }
        Exact => {
            for sym in all {
                if patterns
                    .iter()
                    .any(|pattern| !pattern.is_empty() && sym.demangled == *pattern)
                    && seen.insert(&sym.mangled)
                {
                    out.push(sym);
                }
            }
        }
        Regex => {
            let compiled: Result<Vec<regex::Regex>, _> = patterns
                .iter()
                .filter(|pattern| !pattern.is_empty())
                .map(|pattern| regex::Regex::new(pattern))
                .collect();
            let compiled = compiled.context("invalid regex in --function")?;
            for sym in all {
                if compiled.iter().any(|re| re.is_match(&sym.demangled))
                    && seen.insert(&sym.mangled)
                {
                    out.push(sym);
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[no_mangle]
    pub extern "C" fn jeprofl_symbols_test_marker() {}

    #[test]
    fn list_symbols_in_proc_self_includes_marker() {
        jeprofl_symbols_test_marker();
        let symbols = list_text_symbols(Path::new("/proc/self/exe")).expect("load /proc/self");
        let marker = symbols
            .iter()
            .find(|sym| sym.mangled == "jeprofl_symbols_test_marker")
            .expect("marker present");
        assert_eq!(marker.demangled, "jeprofl_symbols_test_marker");
    }

    #[test]
    fn filter_exact_matches_marker() {
        jeprofl_symbols_test_marker();
        let symbols = list_text_symbols(Path::new("/proc/self/exe")).expect("load /proc/self");
        let matches = filter_symbols(
            &symbols,
            &[String::from("jeprofl_symbols_test_marker")],
            MatchMode::Exact,
        )
        .expect("filter exact");
        assert!(
            matches
                .iter()
                .any(|sym| sym.mangled == "jeprofl_symbols_test_marker"),
            "exact match returns marker"
        );
    }

    #[test]
    fn filter_contains_matches_marker() {
        jeprofl_symbols_test_marker();
        let symbols = list_text_symbols(Path::new("/proc/self/exe")).expect("load /proc/self");
        let matches = filter_symbols(
            &symbols,
            &[String::from("symbols_test_marker")],
            MatchMode::Contains,
        )
        .expect("filter contains");
        assert!(
            matches
                .iter()
                .any(|sym| sym.mangled == "jeprofl_symbols_test_marker"),
            "contains match returns marker"
        );
    }

    #[test]
    fn filter_regex_matches_marker() {
        jeprofl_symbols_test_marker();
        let symbols = list_text_symbols(Path::new("/proc/self/exe")).expect("load /proc/self");
        let matches = filter_symbols(
            &symbols,
            &[String::from(r"jeprofl_symbols_test_.*")],
            MatchMode::Regex,
        )
        .expect("filter regex");
        assert!(
            matches
                .iter()
                .any(|sym| sym.mangled == "jeprofl_symbols_test_marker"),
            "regex match returns marker"
        );
    }
}
