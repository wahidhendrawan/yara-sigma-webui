//! Command-line interface: `convert`, `pipelines`, `query`, `reverse`, `serve`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use clap::builder::PossibleValuesParser;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};

use crate::progress::ProgressReporter;
use crate::sig2yar::{self, ReverseOptions};
use crate::{available_pipelines, backends, emitter, load_mapping, parser, py_str, web};

#[derive(Parser)]
#[command(
    name = "yar2sig",
    version,
    about = "YARA <-> Sigma converter (Sigma-to-YARA is best-effort)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Convert YARA file/dir to Sigma
    Convert(ConvertArgs),
    /// List available mapping pipelines
    Pipelines,
    /// Generate a native SIEM query
    Query(QueryArgs),
    /// Convert Sigma YAML file/dir to YARA (best-effort)
    Reverse(ReverseArgs),
    /// Serve the web UI and JSON API
    Serve(ServeArgs),
}

#[derive(Args)]
struct ConvertArgs {
    /// YARA file (.yar) or directory for bulk import
    input: PathBuf,
    #[arg(short, long, default_value = "sysmon")]
    pipeline: String,
    /// Output directory (required for bulk import)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Output format; detection-rules writes YAML in the layout of the Detection-Rules repository
    #[arg(long, value_enum, default_value_t = ConvertFormat::Yaml)]
    format: ConvertFormat,
    /// MITRE ATT&CK technique tag to add for --format detection-rules (repeatable, e.g. T1059.001)
    #[arg(long, value_name = "TECHNIQUE")]
    attack: Vec<String>,
    /// Force directory/bulk mode
    #[arg(long)]
    dir: bool,
    #[arg(short, long)]
    verbose: bool,
    /// Disable progress bar for batch runs
    #[arg(long)]
    no_progress: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ConvertFormat {
    Yaml,
    Json,
    DetectionRules,
}

#[derive(Args)]
struct QueryArgs {
    input: PathBuf,
    #[arg(short, long, default_value = "sysmon")]
    pipeline: String,
    #[arg(short, long, default_value = "splunk", value_parser = PossibleValuesParser::new(backends::backend_ids()))]
    backend: String,
}

#[derive(Args)]
struct ReverseArgs {
    /// Sigma YAML file or directory
    input: PathBuf,
    /// Output directory (writes to stdout if omitted)
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Output format
    #[arg(long, value_enum, default_value_t = ReverseFormat::Yar)]
    format: ReverseFormat,
    /// Print conversion report to stderr
    #[arg(short, long)]
    verbose: bool,
    /// Disable progress bar for batch runs
    #[arg(long)]
    no_progress: bool,
    /// Omit conversion warnings from YARA output
    #[arg(long)]
    no_comments: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ReverseFormat {
    Yar,
    Json,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8000)]
    port: u16,
}

/// Run the CLI; returns the process exit code.
pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::try_parse_from(args).unwrap_or_else(|e| e.exit());
    match cli.command {
        Command::Convert(args) => convert(&args),
        Command::Pipelines => pipelines(),
        Command::Query(args) => query(&args),
        Command::Reverse(args) => reverse(&args),
        Command::Serve(args) => match web::serve(&args.host, args.port) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
    }
}

fn collect_files(root: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| extensions.contains(&e))
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default()
}

/// The stable machine-readable CLI conversion envelope.
fn json_envelope(pipeline: &str, results: Vec<Value>) -> Value {
    json!({"schema_version": "1.0", "pipeline": pipeline, "results": results})
}

fn convert(args: &ConvertArgs) -> i32 {
    let files = if args.input.is_dir() {
        collect_files(&args.input, &["yar", "yara"])
    } else {
        vec![args.input.clone()]
    };
    if files.is_empty() {
        eprintln!("No YARA files found at {}", args.input.display());
        return 1;
    }
    if let Some(outdir) = &args.output {
        if let Err(e) = fs::create_dir_all(outdir) {
            eprintln!("[!] {}: {e}", outdir.display());
            return 1;
        }
    }

    // Progress goes to stderr and only for directory output, so stdout stays clean for
    // YAML/JSON pipelines.
    let show_progress = !args.no_progress && args.output.is_some() && files.len() > 1;
    let mut json_results: Vec<Value> = Vec::new();
    let mut had_error = false;
    let mut progress = ProgressReporter::stderr(files.len(), show_progress);

    for f in &files {
        let results = fs::read_to_string(f)
            .map_err(|e| e.to_string())
            .and_then(|text| crate::convert_all(&text, &args.pipeline).map_err(|e| e.0));
        let results = match results {
            Ok(results) => results,
            Err(e) => {
                had_error = true;
                eprintln!("[!] {}: {e}", f.display());
                progress.update(&file_name(f));
                continue;
            }
        };
        for (i, (rule, report)) in results.iter().enumerate() {
            let rule = if args.format == ConvertFormat::DetectionRules {
                match emitter::to_detection_rules(rule, &args.attack) {
                    Ok(rule) => rule,
                    Err(e) => {
                        had_error = true;
                        let name = rule
                            .get("x_yar2sig")
                            .and_then(|x| x.get("source_rule"))
                            .or(rule.get("title"));
                        eprintln!(
                            "[!] {}: {}: {e}",
                            f.display(),
                            name.map(py_str).unwrap_or_default()
                        );
                        continue;
                    }
                }
            } else {
                rule.clone()
            };
            let result = json!({"source": f.display().to_string(), "rule": rule, "report": report});
            let (text, extension) = if args.format == ConvertFormat::Json {
                (
                    pretty(&json_envelope(&args.pipeline, vec![result.clone()])) + "\n",
                    "json",
                )
            } else {
                (serde_yaml_ng::to_string(&rule).unwrap_or_default(), "yml")
            };

            if let Some(outdir) = &args.output {
                let suffix = if results.len() > 1 {
                    format!("_{}", i + 1)
                } else {
                    String::new()
                };
                let dest = outdir.join(format!("{}{suffix}.{extension}", file_stem(f)));
                if let Err(e) = fs::write(&dest, &text) {
                    had_error = true;
                    eprintln!("[!] {}: {e}", dest.display());
                    continue;
                }
                if !show_progress {
                    println!(
                        "[+] {} [{}] -> {}",
                        file_name(f),
                        py_str(&rule["title"]),
                        dest.display()
                    );
                }
            } else if args.format == ConvertFormat::Json {
                json_results.push(result);
            } else {
                if i > 0 {
                    println!("---");
                }
                println!("{text}");
            }

            if args.verbose {
                for line in report {
                    eprintln!("    # {line}");
                }
            }
        }
        progress.update(&file_name(f));
    }
    progress.close();

    if args.format == ConvertFormat::Json && args.output.is_none() {
        println!("{}", pretty(&json_envelope(&args.pipeline, json_results)));
    }
    i32::from(had_error)
}

fn pipelines() -> i32 {
    for name in available_pipelines() {
        let mapping = load_mapping(name).unwrap_or_default();
        let logsource = |key: &str| {
            mapping
                .get("logsource")
                .and_then(|l| l.get(key))
                .map(py_str)
        };
        let product = logsource("product").unwrap_or_else(|| "?".into());
        let service = logsource("service")
            .or_else(|| logsource("category"))
            .unwrap_or_else(|| "?".into());
        println!("{name:<12} {product}/{service}");
    }
    0
}

fn query(args: &QueryArgs) -> i32 {
    let run = || -> Result<String, String> {
        let text = fs::read_to_string(&args.input)
            .map_err(|e| format!("{}: {e}", args.input.display()))?;
        let parsed = parser::parse_yara_rule(
            &text,
            parser::DEFAULT_MAX_PATTERNS,
            parser::DEFAULT_MAX_PATTERN_LENGTH,
        )
        .map_err(|e| e.0)?;
        let (rule, _) =
            emitter::emit_sigma(&parsed, &load_mapping(&args.pipeline).map_err(|e| e.0)?);
        backends::generate_query(&args.backend, &rule, &parsed.values()).map_err(|e| e.to_string())
    };
    match run() {
        Ok(query) => {
            println!("{query}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// The stable machine-readable Sigma-to-YARA envelope.
fn reverse_envelope(results: Vec<Value>) -> Value {
    json!({"schema_version": "1.0", "direction": "sigma-to-yara", "results": results})
}

fn reverse(args: &ReverseArgs) -> i32 {
    let files = if args.input.is_dir() {
        collect_files(&args.input, &["yml", "yaml"])
    } else {
        vec![args.input.clone()]
    };
    if files.is_empty() {
        eprintln!("No Sigma YAML files found at {}", args.input.display());
        return 1;
    }
    if let Some(outdir) = &args.output {
        if let Err(e) = fs::create_dir_all(outdir) {
            eprintln!("[!] {}: {e}", outdir.display());
            return 1;
        }
    }

    let show_progress = !args.no_progress && args.output.is_some() && files.len() > 1;
    let options = ReverseOptions {
        include_comments: !args.no_comments,
        ..Default::default()
    };
    let mut json_results: Vec<Value> = Vec::new();
    let mut had_error = false;
    let mut progress = ProgressReporter::stderr(files.len(), show_progress);

    for source in &files {
        let results = match sig2yar::convert_sigma_file(source, &options) {
            Ok(results) => results,
            Err(e) => {
                had_error = true;
                eprintln!("[!] {}: {e}", source.display());
                progress.update(&file_name(source));
                continue;
            }
        };
        for (index, (yara_text, report)) in results.iter().enumerate() {
            let record = json!({"source": source.display().to_string(), "yara": yara_text, "report": report});
            let (text, extension) = if args.format == ReverseFormat::Json {
                (
                    pretty(&reverse_envelope(vec![record.clone()])) + "\n",
                    "json",
                )
            } else {
                (yara_text.clone(), "yar")
            };

            if let Some(outdir) = &args.output {
                let suffix = if results.len() > 1 {
                    format!("_{}", index + 1)
                } else {
                    String::new()
                };
                let dest = outdir.join(format!("{}{suffix}.{extension}", file_stem(source)));
                if let Err(e) = fs::write(&dest, &text) {
                    had_error = true;
                    eprintln!("[!] {}: {e}", dest.display());
                    continue;
                }
                if !show_progress {
                    println!("[+] {} -> {}", file_name(source), dest.display());
                }
            } else if args.format == ReverseFormat::Json {
                json_results.push(record);
            } else {
                if index > 0 {
                    println!("---");
                }
                println!("{text}");
            }

            if args.verbose {
                for line in report {
                    eprintln!("    # {line}");
                }
            }
        }
        progress.update(&file_name(source));
    }
    progress.close();

    if args.format == ReverseFormat::Json && args.output.is_none() {
        println!("{}", pretty(&reverse_envelope(json_results)));
    }
    i32::from(had_error)
}
