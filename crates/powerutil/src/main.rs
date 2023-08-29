use dbus::blocking::{BlockingSender, Connection};
use dbus::Message;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use structopt::StructOpt;
use utmp_rs::{Utmp32Parser, UtmpEntry};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize, Deserialize, Debug)]
struct AppConfig {
    idle_threshold: i64,
    disable: bool,
    utmp_path: String,
}

#[derive(StructOpt)]
struct Cli {
    Check(Check),
    Set(Set),
    Install(Install),
}

#[derive(StructOpt)]
struct Check {
    #[structopt(short, long, parse(from_os_str))]
    config_file: Option<std::path::PathBuf>,
}

#[derive(StructOpt, Debug, Clone)]
struct Set {
    #[structopt(short, long)]
    init: bool,
    #[structopt(short, long, parse(from_os_str))]
    config_file: Option<std::path::PathBuf>,
    #[structopt(short, long)]
    disable: Option<bool>,
    #[structopt(short, long, default_value = "15")]
    idle_threshold: i64,
    #[structopt(short, long, parse(from_os_str), default_value = "/var/run/utmp")]
    utmp_path: std::path::PathBuf,
}
#[derive(Debug, StructOpt, Clone)]
enum Config {
    Set(Set),
    View(View),
}

#[derive(StructOpt, Debug, Clone)]
struct Install {}

fn main() -> Result<()> {
    let opts = Cli::from_args();

    match opts {
        Cli::Check(opts) => check_idle(opts),
        Cli::Set(opts) => set_config(opts),
        Cli::Config(opts) => install_systemd_service(opts),
    }
}

fn check_idle(opts: Check) -> Result<()> {
    let config = get_config(opts.config_file)?;

    let mut idle_times = Vec::new();

    for entry in Utmp32Parser::from_path(config.utmp_path)? {
        let entry = entry?;
        match entry {
            UtmpEntry::UserProcess { line, .. } => {
                let tty_path = Path::new("/dev").join(line);

                match get_idle_time(tty_path) {
                    Ok(idle_secs) => {
                        let idle_mins = idle_secs / 60;
                        if idle_mins == 0 || idle_mins < config.idle_threshold {
                            println!("Users active within threshold: {idle_mins}m, exiting...");
                            std::process::exit(0);
                        }
                        idle_times.push(idle_mins);
                    }
                    Err(e) => {
                        println!("Failed to get idle time: {e}");
                        continue;
                    }
                }
            }
            _ => continue,
        }
    }
    let smallest_idle = idle_times.iter().min().unwrap_or(&0);
    println!(
        "Smallest idle time: {smallest_idle}m (threshold: {}m)",
        config.idle_threshold
    );
    if *smallest_idle >= config.idle_threshold {
        println!("User idle threshold reached: {smallest_idle}m, suspending...");
        if let Err(error) = suspend_system() {
            println!("Failed to suspend system: {error}");
        }
    }
    Ok(())
}

fn set_config(opts: Set) -> Result<()> {
    let path = if let Some(path) = opts.config_file {
        path.to_string_lossy().to_string()
    } else {
        let home_dir = std::env::var("HOME").unwrap_or("".to_string());
        format!("{home_dir}/.powerutil.yaml")
    };

    let config = Config {
        idle_threshold: opts.idle_threshold,
        disable: opts.disable.unwrap_or(false),
        utmp_path: opts.utmp_path.to_string_lossy().to_string(),
    };

    let contents =
        serde_yaml::to_string(&config).map_err(|e| format!("failed to serialize config: {e}"))?;
    println!("Writing config to: {path}");
    std::fs::write(path, contents).map_err(|e| format!("failed write config file: {e}"))?;

    Ok(())
}

fn install_systemd_service(opts: CliConfig) -> Result<()> {
    let path = if let Some(path) = opts.config_file {
        path
    } else {
        let home_dir = std::env::var("HOME").unwrap_or(String::from("."));
        PathBuf::from(home_dir).join(".powerutil.yaml")
    };

    Ok(())
}

fn get_config(config_file: Option<impl AsRef<Path>>) -> Result<Config> {
    let path = if let Some(path) = config_file {
        path.as_ref().to_path_buf()
    } else {
        let home_dir = std::env::var("HOME").unwrap_or(String::from("."));
        PathBuf::from(home_dir).join(".powerutil.yaml")
    };

    let file = std::fs::read(path).map_err(|e| format!("failed to parse config file: {e}"))?;
    let config: Config = serde_yaml::from_slice(file.as_slice())
        .map_err(|e| format!("failed to parse config: {e}"))?;

    Ok(config)
}

fn suspend_system() -> Result<Connection> {
    let c = Connection::new_system()?;
    let m = Message::new_method_call(
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "Suspend",
    )
    .map_err(|e| format!("failed to create dbus message: {e}"))?
    .append1(true);
    let duration = std::time::Duration::from_secs(2);

    let _ = c
        .send_with_reply_and_block(m, duration)
        .map_err(|e| format!("failed to suspend: {e}"))?;

    Ok(c)
}

fn get_idle_time(tty_path: PathBuf) -> Result<libc::time_t> {
    let tty_str = tty_path
        .into_os_string()
        .into_string()
        .map_err(|os_str| format!("failed to convert tty path to string: {:#?}", os_str))?;
    let cstr = CString::new(tty_str).map_err(|e| format!("failed to convert tty path: {e}"))?;

    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::stat(cstr.as_ptr(), &mut stat) };

    if result == 0 {
        Ok(unsafe { libc::time(std::ptr::null_mut()) - stat.st_atime })
    } else {
        Err(format!("Failed to stat tty: {result}").into())
    }
}
