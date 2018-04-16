extern crate twa_pack_lib;
extern crate getopts;

use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use getopts::Options;

fn unpack_pack(pack_filename: &mut File, output_directory: &PathBuf) {
    let mut buf = vec!();
    pack_filename.read_to_end(&mut buf).unwrap();
    let pack = twa_pack_lib::parse_pack(buf);
    let header = pack.get_header();
    let index = pack.get_index();

    let begin = header.get_header_size() + header.get_payload_offset();
    let mut i = 0;

    for item in index.into_iter() {
        let target_path = output_directory.join(&Path::new(&item.name).parent().unwrap());
        println!("Extracting {:?} to {:?}", item, &target_path);
        std::fs::create_dir_all(target_path).unwrap();
        let mut file = OpenOptions::new().write(true).create(true).open(output_directory.join(&item.name)).unwrap();
        file.write(&pack.raw_data[(begin + i) as usize..(begin + i + item.item_length) as usize]).unwrap();
        i += item.item_length;
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE", program);
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


    let mut pack_filename = match File::open(pack_filename_param) {
        Ok(f) => f,
        Err(e) => {
            println!("could not open input file ({})", e);
            return;
        }
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
    unpack_pack(&mut pack_filename, &output_directory);
}
