use serde::{Deserialize, Serialize};
use std::process::Command;
use structopt::StructOpt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    idle_threshold: u32,
    disable: bool,
}

#[derive(StructOpt)]
enum Cli {
    Check(Check),
    Set(Set),
}

#[derive(StructOpt)]
struct Check {
    #[structopt(short, long, parse(from_os_str))]
    config_file: Option<std::path::PathBuf>,
    #[structopt(short, long)]
    view: bool,
}

#[derive(StructOpt)]
struct Set {
    #[structopt(short, long, parse(from_os_str))]
    config_file: Option<std::path::PathBuf>,
    #[structopt(short, long)]
    disable: Option<bool>,
    #[structopt(short, long, default_value = "15")]
    idle_threshold: u32,
}

fn main() -> Result<()> {
    let opts = Cli::from_args();

    match opts {
        Cli::Check(opts) => check_idle(opts),
        Cli::Set(opts) => set_config(opts),
    }
}

fn check_idle(opts: Check) -> Result<()> {
    let path = if let Some(path) = opts.config_file {
        path.to_string_lossy().to_string()
    } else {
        let home_dir = std::env::var("HOME").unwrap_or(String::from(""));
        format!("{home_dir}/.powerutil.yaml")
    };

    let file = std::fs::read(path).map_err(|e| format!("failed to parse config file: {e}"))?;
    let config: Config = serde_yaml::from_slice(file.as_slice())
        .map_err(|e| format!("failed to parse config: {e}"))?;

    if opts.view {
        println!("Current config: {:#?}", &config);
    }

    if config.disable {
        println!("Disabling powerutil...");
        std::process::exit(0);
    }

    let output = Command::new("w")
        .output()
        .expect("Failed to execute command");

    let output = String::from_utf8_lossy(&output.stdout);

    let mut idle_times = Vec::new();

    for line in output.lines().skip(2) {
        println!("Logged in user: {line}");

        if let Some(idle_str) = line.split_whitespace().nth(3) {
            if idle_str.contains("s") {
                println!("Found active user with low idle: {idle_str}, exiting...");
                std::process::exit(0);
            }

            let idle_mins = idle_str
                .split(":")
                .nth(0)
                .unwrap_or("0")
                .parse::<u32>()
                .unwrap_or(0);

            idle_times.push(idle_mins);
        }
    }

    // if idle_times.len() == 0 {
    //     println!("No users found, shutting down...");
    //     shutdown_system();
    // }

    let biggest_idle = idle_times.iter().min().unwrap_or(&0);
    if biggest_idle > &config.idle_threshold {
        println!("User idle threshold reached, suspending...");

        suspend_system();
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
    };

    let contents =
        serde_yaml::to_string(&config).map_err(|e| format!("failed to serialize config: {e}"))?;
    println!("Writing config to: {path}");
    std::fs::write(path, contents).map_err(|e| format!("failed write config file: {e}"))?;

    Ok(())
}

fn suspend_system() {
    Command::new("systemctl")
        .arg("suspend")
        .output()
        .expect("Failed to execute command");
}

// fn shutdown_system() {
//     Command::new("systemctl")
//         .arg("poweroff")
//         .output()
//         .expect("Failed to execute command");
// }
