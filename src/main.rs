#[macro_use]

mod utils;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::Write;

use crate::utils::{disas_instr, get_blocks, restore_data, set_breakpoints, spawn};

fn trace(
    args: &Vec<String>,
    blocks: &Vec<u64>,
    breakpoints: &mut HashMap<u64, u64>,
    bp_set: &mut bool,
) {
    let mut coverage: Vec<u64> = Vec::new();

    let pid = spawn(&args[1], &args[2..args.len()]);

    log::info!(" Spawned process {:?}\n", pid);

    loop {
        match waitpid(pid, None) {
            Ok(WaitStatus::Exited(_, status)) => {
                println!("Process exited with status {}", status);
                break;
            }
            Ok(WaitStatus::Stopped(_, Signal::SIGSEGV)) => {
                let regs = ptrace::getregs(pid).unwrap();
                println!("SegFault at 0x{:x}", regs.rip);
                break;
            }
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => {
                let mut regs = ptrace::getregs(pid).unwrap();

                if !*bp_set {
                    log::info!(" Setting Cov BreakPoints");
                    for i in 0..blocks.len() {
                        breakpoints.insert(blocks[i], set_breakpoints(pid, blocks[i] as i64));
                    }

                    log::info!(" Set {} BreakPoints", blocks.len());
                    *bp_set = true;
                }

                if breakpoints.contains_key(&(regs.rip - 1_u64)) {
                    let reval = breakpoints.get(&(regs.rip - 1_u64)).unwrap();
                    coverage.push(regs.rip - 1_u64);
                    restore_data(pid, (regs.rip - 1) as i64, *reval);
                    breakpoints.remove(&(regs.rip - 1_u64));
                    regs.rip -= 1;
                    ptrace::setregs(pid, regs).unwrap();
                }

                ptrace::cont(pid, None).expect("Should have stepped");
            }
            Ok(WaitStatus::Continued(_)) => println!("Continuing"),
            Ok(WaitStatus::PtraceEvent(pid, signal, v)) => {
                println!(
                    "ptrace event: pid: {:?}, signal: {:?}, v: {:?}",
                    pid, signal, v
                );
            }
            Ok(WaitStatus::Signaled(pid, signal, val)) => {
                println!(
                    "ptrace signaled: pid: {:?}, signal: {:?}, val: {:?}",
                    pid, signal, val
                );
            }
            Ok(WaitStatus::StillAlive) => println!("Still alive"),
            Ok(WaitStatus::Stopped(pid, signal)) => {
                println!("Stopped: pid: {:?}, signal: {:?}", pid, signal);
                break;
            }
            Ok(WaitStatus::PtraceSyscall(pid)) => println!("Syscall: {:?}", pid),
            Err(v) => println!("Error!: {:?}", v),
        }
    }

    let filename = format!("{}.cov", args[1]);
    log::info!("Writing coverage to {}\n", filename);
    let mut f = File::create(filename).unwrap();
    for addr in coverage {
        writeln!(f, "{:x}", addr).unwrap();
    }
}

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_target(false)
        .format_timestamp(None)
        .init();

    log::info!("silverline\n");

    let args: Vec<String> = env::args().collect();
    let blocks = get_blocks(&args[1]);
    let mut breakpoints: HashMap<u64, u64> = HashMap::new();
    let mut bp_set: bool = false;

    for _ in 0..1 {
        trace(&args, &blocks, &mut breakpoints, &mut bp_set);
    }
}
