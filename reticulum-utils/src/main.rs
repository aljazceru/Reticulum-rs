//! `rn` — multi-call binary for the Reticulum `rn*` utilities
//! (see `reticulum-utils/src/lib.rs`).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use reticulum_utils::common::parse_hash;
use reticulum_utils::rncp::{FetchOptions, SendOptions, ServeOptions};
use reticulum_utils::rnid::IdOptions;

/// Reticulum utility programs (rnid, rnpath, rnstatus, rncp).
#[derive(Parser)]
#[command(name = "rn", version, about = "Reticulum utility programs", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate and inspect Reticulum identities (rnid)
    Id(IdArgs),
    /// Look up paths to destinations (rnpath)
    Path(PathArgs),
    /// Show local instance status (rnstatus)
    Status(StatusArgs),
    /// Transfer files over Reticulum resources (rncp)
    Cp(CpArgs),
    /// Probe transport instances (rnprobe)
    Probe(ProbeArgs),
    /// Remote command execution (rnx)
    X(XArgs),
    /// Remote shell sessions (rnsh)
    Sh(ShArgs),
    /// RNode diagnostics and validation (rnodeconf)
    Nodeconf(NodeconfArgs),
    /// RNode device emulator for interface testing
    #[cfg(feature = "iface-rnode")]
    NodeSim(reticulum_utils::rnode_sim::Args),
    /// Identity resolver stub (rnir)
    Ir(CommonArgs),
    /// Package manager stub (rnpkg)
    Pkg(CommonArgs),
}

#[derive(Args)]
struct IdArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Generate a new identity and save it to this path
    #[arg(short, long)]
    generate: Option<PathBuf>,
    /// Inspect an existing identity: path to an identity file or a hex string
    /// (with `--public`: a public identity hex string)
    #[arg(short, long)]
    identity: Option<String>,
    /// Only show public key material
    #[arg(long)]
    public: bool,
}

#[derive(Args)]
struct PathArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Destination hash (32 hexadecimal characters)
    destination: Option<String>,
    /// Show all known paths instead of looking one up
    #[arg(short, long)]
    table: bool,
    /// Maximum hops to filter the path table by
    #[arg(short, long)]
    max: Option<u8>,
    /// Timeout in seconds before giving up
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Output in JSON format
    #[arg(short = 'j', long)]
    json: bool,
    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args)]
struct StatusArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Output in JSON format
    #[arg(short = 'j', long)]
    json: bool,
    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args)]
struct CommonArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Args)]
struct XArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Run a command listener
    #[arg(short, long)]
    serve: bool,
    /// Accept commands from anyone
    #[arg(short = 'A', long)]
    allow_all: bool,
    /// Allow this identity hash (repeatable)
    #[arg(short = 'a', long = "allowed")]
    allowed: Vec<String>,
    /// Command to execute remotely
    command: Option<String>,
    /// Hexadecimal hash of the listener (execute mode)
    #[arg(short, long)]
    destination: Option<String>,
    /// Timeout in seconds
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Debug helper: bind a UDP loopback interface LISTEN:FORWARD
    #[arg(long)]
    udp_loopback: Option<String>,
}

#[derive(Args)]
struct ShArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Run a session listener
    #[arg(short, long)]
    serve: bool,
    /// Run one command in a session
    #[arg(short, long)]
    command: Option<String>,
    /// Hexadecimal hash of the listener
    #[arg(short, long)]
    destination: Option<String>,
    /// Debug helper: bind a UDP loopback interface LISTEN:FORWARD
    #[arg(long)]
    udp_loopback: Option<String>,
}

#[derive(Args)]
struct NodeconfArgs {
    /// Serial port of the device
    #[arg(short, long)]
    port: Option<String>,
    /// TCP address of the device
    #[arg(short, long)]
    tcp: Option<String>,
    /// Serial baudrate
    #[arg(short = 'B', long, default_value_t = 115200)]
    baudrate: u32,
    /// Validate the device's radio configuration
    #[arg(long)]
    validate: bool,
    /// Radio frequency in Hz
    #[arg(short, long)]
    frequency: Option<u64>,
    /// Radio bandwidth in Hz
    #[arg(short, long)]
    bandwidth: Option<u32>,
    /// TX power in dBm
    #[arg(short = 'T', long)]
    txpower: Option<u8>,
    /// LoRa spreading factor
    #[arg(short, long)]
    spreadingfactor: Option<u8>,
    /// LoRa coding rate
    #[arg(short, long)]
    codingrate: Option<u8>,
}

#[derive(Args)]
struct ProbeArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Hexadecimal hash of the probe destination
    destination: Option<String>,
    /// Payload size in bytes
    #[arg(short, long)]
    size: Option<usize>,
    /// Number of probes to send
    #[arg(short, long, default_value_t = 1)]
    probes: usize,
    /// Timeout in seconds before giving up
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// UDP loopback ports LISTEN:FORWARD instead of configured interfaces
    #[arg(long)]
    udp_loopback: Option<String>,
    /// Run a local probe server and probe it once
    #[arg(short, long)]
    loopback: bool,
    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Args)]
struct CpArgs {
    /// Path to alternative Reticulum config directory
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// File to transfer (send/fetch mode)
    file: Option<String>,
    /// Hexadecimal hash of the receiver (send/fetch mode)
    destination: Option<String>,
    /// Run a listener accepting files into this directory
    #[arg(short = 'l', long = "serve")]
    serve: Option<PathBuf>,
    /// Fetch the file from the remote instead of sending it
    #[arg(short = 'f', long)]
    fetch: bool,
    /// Print identity and destination info and exit
    #[arg(short = 'p', long)]
    print_identity: bool,
    /// Accept transfers from anyone (no authentication)
    #[arg(short = 'n', long)]
    no_auth: bool,
    /// Allow authenticated clients to fetch files
    #[arg(short = 'F', long)]
    allow_fetch: bool,
    /// Allow this identity hash (repeatable)
    #[arg(short = 'a', long = "allowed")]
    allowed: Vec<String>,
    /// Restrict fetch requests to this path
    #[arg(short = 'j', long)]
    jail: Option<PathBuf>,
    /// Save received files in this path
    #[arg(short = 's', long)]
    save: Option<PathBuf>,
    /// Path to identity to use
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,
    /// Disable automatic compression
    #[arg(short = 'C', long)]
    no_compress: bool,
    /// Disable transfer progress output
    #[arg(short = 'S', long)]
    silent: bool,
    /// Announce interval in seconds (0 = only at startup)
    #[arg(short = 'b', long, default_value_t = 0)]
    announce: u64,
    /// Timeout in seconds before giving up
    #[arg(short = 'w', long)]
    timeout: Option<f64>,
    /// Debug helper: bind a UDP loopback interface BIND:FORWARD instead of
    /// using configured interfaces
    #[arg(long)]
    udp_loopback: Option<String>,
    /// Increase verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(level),
    )
    .init();
}

fn duration_arg(seconds: Option<f64>, default: Duration) -> Duration {
    seconds
        .map(|s| Duration::from_secs_f64(s.max(0.1)))
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Id(args) => {
            let options = IdOptions {
                generate: args.generate,
                identity: args.identity,
                public: args.public,
                no_save: false,
            };
            match reticulum_utils::rnid::run(options) {
                Ok(code) => ExitCode::from(code as u8),
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(reticulum_utils::rnid::R_INVALID_IDENTITY as u8)
                }
            }
        }
        Command::Path(args) => exit_code(run_path(args).await),
        Command::Status(args) => exit_code(run_status(args).await),
        Command::Cp(args) => exit_code(run_cp(args).await),
        Command::Probe(args) => exit_code(run_probe(args).await),
        Command::X(args) => exit_code(run_x(args).await),
        Command::Sh(args) => exit_code(run_sh(args).await),
        #[cfg(feature = "iface-rnode")]
        Command::NodeSim(args) => {
            init_logging(1);
            if let Err(err) = reticulum_utils::rnode_sim::run(args).await {
                eprintln!("{err}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }

        Command::Nodeconf(args) => {
            #[cfg(feature = "iface-rnode")]
            {
                exit_code(run_nodeconf(args).await)
            }
            #[cfg(not(feature = "iface-rnode"))]
            {
                let _ = args;
                eprintln!("rnodeconf requires building with --features iface-rnode");
                ExitCode::FAILURE
            }
        }
        Command::Ir(args) => {
            init_logging(0);
            let options = reticulum_utils::rnir::Options {
                config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            };
            exit_code(reticulum_utils::rnir::run(&options).await)
        }
        Command::Pkg(args) => {
            init_logging(0);
            let options = reticulum_utils::rnpkg::Options {
                config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            };
            exit_code(reticulum_utils::rnpkg::run(&options).await)
        }
    }
}

fn exit_code(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

async fn run_path(args: PathArgs) -> Result<(), String> {
    init_logging(args.verbose);
    if !args.table && args.destination.is_none() {
        return Err("No destination specified. Use -t/--table to list paths or pass a destination hash.".to_string());
    }
    let config_dir = reticulum_utils::common::resolve_config_dir(args.config.as_deref());
    let timeout = duration_arg(args.timeout, reticulum_utils::rnpath::DEFAULT_TIMEOUT);

    let transport = reticulum_utils::common::build_tool_transport(
        reticulum_utils::common::ToolTransportOptions {
            config_dir: &config_dir,
            instance_name: "rnpath",
            enable_transport: false,
            udp_loopback: None,
        },
    )
    .await;

    if args.table {
        let filter = match &args.destination {
            Some(destination) => Some(parse_hash(destination)?),
            None => None,
        };
        let entries = reticulum_utils::rnpath::path_table(&transport, filter.as_ref(), args.max).await;
        if args.json {
            #[derive(serde::Serialize)]
            struct Entry {
                hash: String,
                hops: u8,
                via: String,
                interface: String,
            }
            let json: Vec<Entry> = entries
                .iter()
                .map(|entry| Entry {
                    hash: reticulum_utils::common::prettyhexrep(entry.destination.as_slice()),
                    hops: entry.hops,
                    via: reticulum_utils::common::prettyhexrep(entry.via.as_slice()),
                    interface: entry.iface.to_hex_string(),
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        } else {
            print!("{}", reticulum_utils::rnpath::render_table(&entries));
            if entries.is_empty() {
                println!("No information available");
            }
        }
        return Ok(());
    }

    let destination = parse_hash(args.destination.as_deref().expect("checked"))?;
    let result = reticulum_utils::rnpath::wait_for_path(&transport, &destination, timeout).await;
    match result {
        Some(result) => {
            println!("{}", result.render());
            Ok(())
        }
        None => Err("Path not found".to_string()),
    }
}

async fn run_status(args: StatusArgs) -> Result<(), String> {
    init_logging(args.verbose);
    let config_dir = reticulum_utils::common::resolve_config_dir(args.config.as_deref());
    let transport = reticulum_utils::common::build_tool_transport(
        reticulum_utils::common::ToolTransportOptions {
            config_dir: &config_dir,
            instance_name: "rnstatus",
            enable_transport: false,
            udp_loopback: None,
        },
    )
    .await;

    // Give interfaces a moment to come up so their status is meaningful.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let report = reticulum_utils::rnstatus::collect(&transport, false).await;
    if args.json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.render());
    }
    Ok(())
}

async fn run_cp(args: CpArgs) -> Result<(), String> {
    init_logging(args.verbose);
    let timeout = duration_arg(args.timeout, reticulum_utils::rncp::DEFAULT_TIMEOUT);
    let udp_loopback = args.udp_loopback.as_deref().and_then(parse_udp_loopback);

    let config_dir = reticulum_utils::common::resolve_config_dir(args.config.as_deref());
    if args.print_identity {
        let (identity, destination) =
            reticulum_utils::rncp::print_identity(&config_dir, args.identity.as_deref()).await?;
        println!("Identity     : {identity}");
        println!("Listening on : {destination}");
        return Ok(());
    }

    if let Some(dir) = &args.serve {
        let allowed = args
            .allowed
            .iter()
            .map(|hash| parse_hash(hash))
            .collect::<Result<Vec<_>, _>>()?;
        let options = ServeOptions {
            config_dir: args.config.clone(),
            save_dir: dir.clone(),
            allowed,
            no_auth: args.no_auth,
            allow_fetch: args.allow_fetch,
            jail: args.jail.clone(),
            announce_interval: args.announce,
            no_compress: args.no_compress,
            identity_path: args.identity.clone(),
            udp_loopback,
        };
        return reticulum_utils::rncp::serve(options).await;
    }

    let (file, destination) = match (&args.file, &args.destination) {
        (Some(file), Some(destination)) => (file.clone(), parse_hash(destination)?),
        _ => {
            return Err(
                "Nothing to do: pass <file> <destination> to send, --fetch <file> <destination> \
                 to fetch, or --serve <dir> to listen."
                    .to_string(),
            )
        }
    };

    if args.fetch {
        let options = FetchOptions {
            config_dir: args.config.clone(),
            file,
            destination,
            timeout,
            silent: args.silent,
            save_dir: args.save.clone(),
            identity_path: args.identity.clone(),
            udp_loopback,
        };
        let message = reticulum_utils::rncp::fetch(options).await?;
        println!("{message}");
    } else {
        let options = SendOptions {
            config_dir: args.config.clone(),
            file: PathBuf::from(file),
            destination,
            timeout,
            no_compress: args.no_compress,
            silent: args.silent,
            identity_path: args.identity.clone(),
            udp_loopback,
        };
        let message = reticulum_utils::rncp::send(options).await?;
        println!("{message}");
    }
    Ok(())
}

fn parse_udp_loopback(spec: &str) -> Option<(u16, u16)> {
    let (bind, forward) = spec.split_once(':')?;
    Some((bind.parse().ok()?, forward.parse().ok()?))
}

async fn run_probe(args: ProbeArgs) -> Result<(), String> {
    init_logging(args.verbose);

    if args.loopback {
        let (destination, results) = reticulum_utils::rnprobe::run_loopback()
            .await
            .map_err(|err| format!("probe failed: {err:?}"))?;
        print!(
            "{}",
            reticulum_utils::rnprobe::render_results(&destination, &results)
        );
        return Ok(());
    }

    let destination = args
        .destination
        .as_deref()
        .map(parse_hash)
        .transpose()
        .map_err(|err| err.to_string())?
        .ok_or("a destination hash is required (or use --loopback)")?;

    let udp_loopback = parse_udp_pair(args.udp_loopback.as_deref());

    let options = reticulum_utils::rnprobe::ProbeOptions {
        config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
        size: args.size.unwrap_or(reticulum_utils::rnprobe::DEFAULT_PROBE_SIZE),
        timeout: duration_arg(args.timeout, reticulum_utils::rnprobe::DEFAULT_TIMEOUT),
        probes: args.probes,
        udp_loopback,
    };

    let results = reticulum_utils::rnprobe::probe(&destination, &options)
        .await
        .map_err(|err| format!("probe failed: {err:?}"))?;

    print!("{}", reticulum_utils::rnprobe::render_results(&destination, &results));
    Ok(())
}


fn parse_udp_pair(spec: Option<&str>) -> Option<(u16, u16)> {
    let spec = spec?;
    let (listen, forward) = spec.split_once(':')?;
    Some((listen.parse().ok()?, forward.parse().ok()?))
}

async fn run_x(args: XArgs) -> Result<(), String> {
    init_logging(1);

    let udp_loopback = parse_udp_pair(args.udp_loopback.as_deref());

    if args.serve {
        let options = reticulum_utils::rnx::ServeOptions {
            config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            allow_all: args.allow_all,
            allowed: args
                .allowed
                .iter()
                .map(|hash| parse_hash(hash))
                .collect::<Result<_, _>>()?,
            udp_loopback,
            idle_timeout: None,
        };

        let address = reticulum_utils::rnx::serve(&options).await?;
        println!("rnx listening on {address}");
        return Ok(());
    }

    let command = args
        .command
        .ok_or("a command is required (or use --serve)")?;
    let destination = args
        .destination
        .as_deref()
        .map(parse_hash)
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or("a destination hash is required")?;

    let options = reticulum_utils::rnx::ExecOptions {
        config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
        timeout: duration_arg(args.timeout, std::time::Duration::from_secs(30)),
        udp_loopback,
    };

    let result = reticulum_utils::rnx::execute(&destination, &command, &options).await?;
    print!("{}", String::from_utf8_lossy(&result.stdout));
    if !result.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }

    if !result.executed {
        return Err("remote did not execute the command".to_string());
    }

    Ok(())
}

async fn run_sh(args: ShArgs) -> Result<(), String> {
    init_logging(1);

    let udp_loopback = parse_udp_pair(args.udp_loopback.as_deref());

    if args.serve {
        let options = reticulum_utils::rnsh::ServeOptions {
            config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
            udp_loopback,
        };

        let address = reticulum_utils::rnsh::serve(&options).await?;
        println!("rnsh listening on {address}");
        return Ok(());
    }

    let command = args
        .command
        .ok_or("a command is required (or use --serve)")?;
    let destination = args
        .destination
        .as_deref()
        .map(parse_hash)
        .transpose()
        .map_err(|e| e.to_string())?
        .ok_or("a destination hash is required")?;

    let options = reticulum_utils::rnsh::ServeOptions {
        config_dir: reticulum_utils::common::resolve_config_dir(args.config.as_deref()),
        udp_loopback,
    };

    let output = reticulum_utils::rnsh::run_command(&destination, &command, &options).await?;
    print!("{}", String::from_utf8_lossy(&output));
    Ok(())
}

#[cfg(feature = "iface-rnode")]
async fn run_nodeconf(args: NodeconfArgs) -> Result<(), String> {
    init_logging(1);

    let target = if let Some(tcp) = args.tcp.as_deref() {
        reticulum_utils::rnodeconf::DeviceTarget::Tcp {
            addr: tcp.to_string(),
        }
    } else if let Some(port) = args.port.as_deref() {
        reticulum_utils::rnodeconf::DeviceTarget::Serial {
            port: port.to_string(),
            baudrate: args.baudrate,
        }
    } else {
        return Err("a --port or --tcp target is required".to_string());
    };

    if args.validate {
        let frequency = args.frequency.ok_or("--frequency is required for validation")?;
        let config = reticulum::iface::rnode::RnodeRadioConfig {
            frequency,
            bandwidth: args.bandwidth.ok_or("--bandwidth is required")?,
            txpower: args.txpower.ok_or("--txpower is required")?,
            spreadingfactor: args.spreadingfactor.ok_or("--spreadingfactor is required")?,
            codingrate: args.codingrate.ok_or("--codingrate is required")?,
            st_alock: None,
            lt_alock: None,
        };

        match reticulum_utils::rnodeconf::validate_config(&target, &config).await {
            Ok(_) => {
                println!("Radio configuration validated");
                Ok(())
            }
            Err(err) => Err(format!("validation failed: {err:?}")),
        }
    } else {
        let info = reticulum_utils::rnodeconf::device_info(&target)
            .await
            .map_err(|e| format!("device probe failed: {e:?}"))?;
        print!("{}", reticulum_utils::rnodeconf::render_info(&info));
        Ok(())
    }
}
