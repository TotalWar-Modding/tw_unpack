extern crate getopts;
extern crate glob;
extern crate tw_pack_lib;

use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

use getopts::Options;
use glob::glob;

static VERSION: &str = env!("CARGO_PKG_VERSION");

struct Config {
    verbose: bool
}

/// Safely join an archive-supplied entry `name` onto `base`, confining the
/// result to `base`. Returns `None` for any entry that would escape it.
///
/// Entry paths inside a `.pack` are attacker controlled and stored verbatim
/// (see `tw_pack_lib`), so joining them directly with `Path::join` is a
/// path-traversal / arbitrary-file-write vulnerability (zip-slip, CWE-22): a
/// `..` component climbs out of the output directory and an absolute path (or
/// Windows drive prefix) discards `base` entirely.
///
/// `..` is resolved lexically against the accumulated segments, so an entry
/// that dips into `..` but still lands inside `base` (e.g. `a/../b.txt`) is
/// accepted and normalised; only a path that pops *above* `base` is rejected.
/// Absolute paths and Windows drive prefixes are always rejected because they
/// would drop `base`.
///
/// `.pack` paths use `\` as the separator, so both `\` and `/` are treated as
/// separators here; otherwise a `..\..\evil` payload would slip through the
/// component check on platforms where `\` is not a separator.
///
/// Note: this is a *lexical* confinement (it does not resolve symlinks). That
/// is sufficient here because extraction only ever writes regular files into
/// directories it creates itself — the archive cannot introduce a symlink for
/// a later entry to follow.
fn safe_join(base: &Path, name: &str) -> Option<PathBuf> {
    let normalized = name.replace('\\', "/");
    let mut segments: Vec<&OsStr> = Vec::new();
    for component in Path::new(&normalized).components() {
        match component {
            Component::Normal(part) => segments.push(part),
            Component::CurDir => {}
            // Resolve `..` lexically; reject only when it climbs above `base`.
            Component::ParentDir => {
                if segments.pop().is_none() {
                    return None;
                }
            }
            // Absolute paths / drive prefixes would discard `base` entirely.
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    // Reject entries that resolve to no real path segment (e.g. "", ".").
    if segments.is_empty() {
        return None;
    }
    let mut out = base.to_path_buf();
    for segment in segments {
        out.push(segment);
    }
    Some(out)
}

fn unpack_pack(path: &PathBuf, output_directory: &PathBuf, config: &Config) {
    match File::open(&path) {
        Ok(pack_filename) => {
            let pack = tw_pack_lib::parse_pack(pack_filename).unwrap();
            println!("unpacking {}: {}", &path.display(), &pack);

            for item in pack.into_iter() {
                if config.verbose {
                    println!("{}", &item);
                }
                let target_path = match safe_join(output_directory, &item.path) {
                    Some(p) => p,
                    None => {
                        println!("skipping unsafe entry path: {:?}", &item.path);
                        continue;
                    }
                };
                if let Some(target_directory) = target_path.parent() {
                    std::fs::create_dir_all(target_directory).unwrap();
                }
                let mut file = OpenOptions::new().write(true).create(true).open(&target_path).unwrap();
                file.write(&item.get_data().unwrap()).unwrap();
            }
        },
        Err(e) => panic!("Could not open file {} ({})", &path.display(), e)
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("tw_unpack version {}\nUsage: {} FILE", VERSION, program);
    println!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("o", "", "the output directory for the extracted files. If no output directory is specified, tw_unpack will save the files in the current directory", "OUTPUT");
    opts.optflag("v", "", "enable verbose logging");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            println!("failed to parse arguments ({})", f);
            return;
        }
    };

    let output_directory_param = matches.opt_str("o");
    let pack_filename_param = if !matches.free.is_empty() {
        matches.free[0].clone()
    } else {
        print_usage(&program, opts);
        return;
    };

    let verbose = if matches.opt_present("v") {
        true
    } else {
        false
    };

    let output_directory = match output_directory_param {
        Some(p) => {
            let path = PathBuf::from(&p);
            if path.exists() {
                path
            } else {
                println!("output directory does not exist");
                return;
            }
        },
        None => {
            match env::current_dir() {
                Ok(curr_dir) => curr_dir,
                Err(e) => {
                    println!("invalid current directory ({})", e);
                    return;
                }
            }
        }
    };

    let config = Config {
        verbose: verbose
    };

    match glob(&pack_filename_param) {
        Ok(glob) => {
            for entry in glob {
                match entry {
                    Ok(path) => {
                        unpack_pack(&path, &output_directory, &config)
                    }
                    Err(e) => println!("failed to handle glob entry ({})", e),
                }
            }
        },
        Err(e) => {
            println!("invalid glob pattern ({})", e);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::safe_join;
    use std::path::{Path, PathBuf};

    fn base() -> PathBuf {
        PathBuf::from("/out")
    }

    // entries that must be rejected (would escape the output directory) 

    #[test]
    fn rejects_net_parent_traversal() {
        // only entries that climb *above* base are rejected.
        assert_eq!(safe_join(&base(), "../ESCAPED.txt"), None);
        assert_eq!(safe_join(&base(), "../../ESCAPED.txt"), None);
        assert_eq!(safe_join(&base(), "data/../../ESCAPED.txt"), None);
        assert_eq!(safe_join(&base(), "a/b/../../../c"), None);
    }

    #[test]
    fn normalizes_inside_dotdot() {
        // `..` that stays within base is resolved, not rejected.
        assert_eq!(
            safe_join(&base(), "a/../b.txt"),
            Some(Path::new("/out/b.txt").to_path_buf())
        );
        assert_eq!(
            safe_join(&base(), "data/../secret.txt"),
            Some(Path::new("/out/secret.txt").to_path_buf())
        );
        assert_eq!(
            safe_join(&base(), "data/sub/../bar.txt"),
            Some(Path::new("/out/data/bar.txt").to_path_buf())
        );
        assert_eq!(
            safe_join(&base(), "./a/../b.txt"),
            Some(Path::new("/out/b.txt").to_path_buf())
        );
    }

    #[test]
    fn rejects_windows_separator_traversal() {
        // `\` is the `.pack` separator; it must be treated as a separator so
        // `..\..\` cannot slip past the component check on unix.
        assert_eq!(safe_join(&base(), "..\\..\\ESCAPED.txt"), None);
        assert_eq!(safe_join(&base(), "data\\..\\..\\ESCAPED.txt"), None);
        // ...but an inside `..` with `\` separators normalises like `/`.
        assert_eq!(
            safe_join(&base(), "a\\..\\b.txt"),
            Some(Path::new("/out/b.txt").to_path_buf())
        );
    }

    #[test]
    fn rejects_absolute_path() {
        // absoltue paths are also rejected because they discard `base` entirely.
        assert_eq!(safe_join(&base(), "/etc/passwd"), None);
        assert_eq!(safe_join(&base(), "/tmp/pwned.txt"), None);
    }

    #[test]
    fn rejects_empty_or_dot_only() {
        assert_eq!(safe_join(&base(), ""), None);
        assert_eq!(safe_join(&base(), "."), None);
        assert_eq!(safe_join(&base(), "./"), None);
    }

    // safe entries, that must be allowed.

    #[test]
    fn allows_plain_file() {
        assert_eq!(safe_join(&base(), "file.txt"), Some(Path::new("/out/file.txt").to_path_buf()));
    }

    #[test]
    fn allows_nested_unix_separator() {
        assert_eq!(
            safe_join(&base(), "data/foo/bar.txt"),
            Some(Path::new("/out/data/foo/bar.txt").to_path_buf())
        );
    }

    #[test]
    fn allows_nested_windows_separator() {
        // `\` is normalised to a real directory separator.
        assert_eq!(
            safe_join(&base(), "data\\foo\\baz.txt"),
            Some(Path::new("/out/data/foo/baz.txt").to_path_buf())
        );
    }

    #[test]
    fn allows_leading_dot_slash() {
        // a leading `./` is a no-op, not a rejection.
        assert_eq!(
            safe_join(&base(), "./data/bar.txt"),
            Some(Path::new("/out/data/bar.txt").to_path_buf())
        );
    }

    #[test]
    fn result_always_stays_under_base() {
        // property check: whatever it accepts must start with `base`.
        let b = base();
        for entry in [
            "file.txt",
            "data/foo/bar.txt",
            "data\\foo\\baz.txt",
            "./a/b/c.dat",
            "../escape",
            "..\\escape",
            "/abs/path",
            "a/../../escape",
            "",
        ] {
            if let Some(joined) = safe_join(&b, entry) {
                assert!(
                    joined.starts_with(&b),
                    "accepted entry {:?} escaped base: {:?}",
                    entry,
                    joined
                );
            }
        }
    }
}
