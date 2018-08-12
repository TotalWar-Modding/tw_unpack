extern crate getopts;
extern crate glob;
extern crate twa_pack_lib;

use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use getopts::Options;
use glob::glob;

static VERSION: &str = "0.1.3";

struct Config {
    verbose: bool
}

fn unpack_pack(pack_filename: &mut File, output_directory: &PathBuf, config: &Config) {
    let mut buf = vec!();
    pack_filename.read_to_end(&mut buf).unwrap();
    let pack = twa_pack_lib::parse_pack(buf);

    for item in pack.into_iter() {
        let target_directory = output_directory.join(&Path::new(&item.name).parent().unwrap());
        let target_path = output_directory.join(&item.name);
        std::fs::create_dir_all(target_directory).unwrap();
        let mut file = OpenOptions::new().write(true).create(true).open(&target_path).unwrap();
        if config.verbose {
            println!("{}", &item);
        }
        file.write(item.content).unwrap();
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("twa_unpack version {}\nUsage: {} FILE", VERSION, program);
    println!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("o", "", "the output directory for the extracted files. If no output directory is specified, twa_unpack will save the files in the current directory", "OUTPUT");
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
                        match File::open(&path) {
                            Ok(mut f) => {
                                println!("unpacking {}", &path.display());
                                unpack_pack(&mut f, &output_directory, &config)
                            },
                            Err(e) => panic!("fould not open file {} ({})", &path.display(), e)
                        }
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
