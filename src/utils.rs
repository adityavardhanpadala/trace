use nix::unistd::Pid;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{mem, ptr};
use libc::c_void;

use nix::Result;
use nix::sys::ptrace;
use nix::errno::Errno;
use nix::sys::ptrace::{Request, RequestType};

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, NasmFormatter};
use r2pipe::R2Pipe;

pub fn spawn(cmd: &String, args: &[String]) -> Pid {
    let child = unsafe {
        Command::new(cmd)
            .args(args)
            .pre_exec(|| {
                ptrace::traceme().expect("Could not trace process");
                Ok(())
            })
            .spawn()
            .expect(&format!("Could not spawn {:?} with args {:?}", cmd, args))
    };

    Pid::from_raw(child.id() as i32)
}

// To set a bp we neet to force "int 3"s at the addresses.
// We read data at address replace lsb with 0xcc
// write it back to the process
pub fn set_breakpoints(pid: Pid, bp: i64) -> u64 {
    let val = ptrace::read(pid, bp as ptrace::AddressType).unwrap() as u64;
    unsafe {
        let data = (&val & 0xffffffffffffff00) | 0xcc;
        let ptr: *const u64 = &data;
        ptrace::write(
            pid,
            bp as ptrace::AddressType,
            *ptr as *mut std::ffi::c_void,
        )
        .expect("Failed to set Breakpoint");
    }
    let papp = ptrace::read(pid, bp as ptrace::AddressType).unwrap() as u64;
    val
}

// To restore the breakpoint set
// We read data at address replace lsb with original data
// write it back to the process
pub fn restore_data(pid: Pid, bp: i64, val: u64) {
    unsafe {
        let ptr: *const u64 = &val;
        ptrace::write(
            pid,
            bp as ptrace::AddressType,
            *ptr as *mut std::ffi::c_void,
        )
        .expect("Failed to set Breakpoint");
    }
}

pub fn get_blocks(binpath : &str) -> Vec<u64>{
    let mut r2p = R2Pipe::spawn(binpath, None).unwrap();
    log::info!("[*] Analyzing binary");
    let _ = r2p.cmd("aaaa");
    let json = r2p.cmdj("ablj").unwrap();
    let mut blockaddr : Vec<u64> = Vec::new();
    let blockcnt = json["blocks"].as_array().unwrap().len();
    for i in 0..blockcnt{
        blockaddr.push(u64::from_str_radix(json["blocks"][i]["addr"].as_str().unwrap().trim_start_matches("0x"),16).unwrap())
    }
    r2p.close();
    blockaddr
}

pub fn ptrace_get_fpregs(pid: Pid) -> Result<libc::user_fpregs_struct> {
    ptrace_get_data::<libc::user_fpregs_struct>(Request::PTRACE_GETFPREGS, pid)
}

pub fn ptrace_set_fpregs(pid: Pid, regs: libc::user_fpregs_struct){
    let _ = unsafe {
        libc::ptrace(
            Request::PTRACE_SETFPREGS as RequestType,
            libc::pid_t::from(pid),
            ptr::null_mut::<c_void>(),
            &regs as *const _ as *const c_void,
        )
    };
}

fn ptrace_get_data<T>(request: Request, pid: Pid) -> Result<T> {
    let mut data = mem::MaybeUninit::uninit();
    let res = unsafe {
        libc::ptrace(
            request as RequestType,
            libc::pid_t::from(pid),
            ptr::null_mut::<T>(),
            data.as_mut_ptr() as *const _ as *const c_void,
        )
    };
    Errno::result(res)?;
    Ok(unsafe { data.assume_init() })
}

pub fn disas_instr(code: &[u8], bitness : u32, rip : u64) 
{
    let bytes = code;
    let mut decoder =
        Decoder::with_ip(bitness, bytes, rip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();

    // Change some options, there are many more
    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    let mut output = String::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        output.clear();
        formatter.format(&instruction, &mut output);
        print!("{:016X} ", instruction.ip());
        let start_index = (instruction.ip() - rip) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        for b in instr_bytes.iter() {
            print!("{:02X}", b);
        }
        if instr_bytes.len() < 10 {
            for _ in 0..10 - instr_bytes.len() {
                print!("  ");
            }
        }
        println!("{:?}",output);
    }

}
