#![feature(is_some_and)]
#![feature(inherent_associated_types)]
#![feature(iter_intersperse)]

use std::fmt::Debug;

use read_process_memory::Pid;

use crate::process::Process;

mod process;

trait DebugErrString<T> {
    fn str_err(self) -> Result<T, String>;
}

impl<T, E: Debug> DebugErrString<T> for Result<T, E> {
    fn str_err(self) -> Result<T, String> {
        self.map_err(|e| format!("{e:?}"))
    }
}

struct Program {
    process: Option<Process>,
}

#[derive(Debug)]
enum ProgramError {
    NoProcess,
    InvalidAddress,
}

impl Program {
    fn run_command(&mut self, command: &str, args: &str) -> Result<(), String> {
        match command {
            "open" => {
                let pid = args.parse::<u32>().str_err()? as Pid;
                let process = Process::try_new(pid).str_err()?;
                self.process = Some(process);
                println!("Opened process with pid {pid}");
            }
            "ptr" => {
                let address = self.fetch_address(args).str_err()?;
                println!("{}", self.format_addr(address));
            }
            "name" => {
                let process = self.process().str_err()?;
                let address = self.fetch_address(args).str_err()?;
                let name = process.read_class_name(address).str_err()?;
                println!("{name}");
            }
            "list" => {
                let (size, address) = args.split_once(' ').ok_or(String::from("Missing args"))?;
                let size = size.parse::<usize>().str_err()?;
                let address = self.fetch_address(address).str_err()?;
                let process = self.process().str_err()?;
                for offset in (0..size).step_by(process.pointer_size()) {
                    let Ok(address) = process.read_ptr(address + offset) else {
                        continue;
                    };
                    if let Ok(name) = process.read_vtable_info(address) {
                        let Ok(name) = process.demangle_class_name(name.as_str()) else {
                            break
                        };
                        println!(
                            "[{offset:>3x}] vtable: {name} ({})",
                            self.format_addr(address)
                        );
                    } else if let Ok(name) = process.read_class_name(address) {
                        let Ok(name) = process.demangle_class_name(name.as_str()) else {
                            break
                        };
                        println!("[{offset:>3x}] {name} ({})", self.format_addr(address));
                    }
                }
            }
            _ => {
                println!("Unknown command \"{command}\"");
            }
        }
        Ok(())
    }

    fn format_addr(&self, addr: usize) -> String {
        if self.process.as_ref().is_some_and(|p| p.pointer_size() == 8) {
            format!("{addr:016x}")
        } else {
            // default to 4 bytes because i cant be bothered to return a result
            format!("{addr:08x}")
        }
    }

    fn process(&self) -> Result<&Process, ProgramError> {
        self.process.as_ref().ok_or(ProgramError::NoProcess)
    }

    fn fetch_address(&self, command: &str) -> Result<usize, ProgramError> {
        let command = command.trim();
        if command.is_empty() {
            return Err(ProgramError::InvalidAddress);
        }
        let process = self.process()?;
        if command.starts_with('[') {
            let mut i = 0;
            let mut count = 1;
            for c in command.chars().skip(1) {
                i += 1;
                if c == '[' {
                    count += 1;
                } else if c == ']' {
                    count -= 1;
                }
                if count == 0 {
                    break;
                }
            }
            if count != 0 {
                return Err(ProgramError::InvalidAddress);
            }
            let (deref, rest) = command.split_at(i + 1);
            let addr = self.fetch_address(&deref[1..deref.len() - 1])?;
            let addr = process
                .read_ptr(addr)
                .map_err(|_| ProgramError::InvalidAddress)?;
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('+') {
                Ok(addr + self.fetch_address(rest)?)
            } else if let Some(rest) = rest.strip_prefix('-') {
                Ok(addr - self.fetch_address(rest)?)
            } else {
                Ok(addr)
            }
        } else if let Some((lhs, rhs)) = command.split_once('+') {
            Ok(self.fetch_address(lhs)? + self.fetch_address(rhs)?)
        } else if let Some((lhs, rhs)) = command.split_once('-') {
            Ok(self.fetch_address(lhs)? - self.fetch_address(rhs)?)
        } else if command == "base" {
            Ok(process.base_address())
        } else if let Some(number) = command.strip_prefix("0x") {
            usize::from_str_radix(number, 16).map_err(|_| ProgramError::InvalidAddress)
        } else {
            command
                .parse::<usize>()
                .map_err(|_| ProgramError::InvalidAddress)
        }
    }
}

fn main() -> std::io::Result<()> {
    let process;
    if let Some(arg) = std::env::args().nth(1) {
        let pid = arg.parse::<u32>().unwrap() as Pid;
        process = Some(Process::try_new(pid)?);
        println!("Opened process with pid {pid}");
    } else {
        process = None;
    }

    let mut program = Program { process };

    let mut rl = rustyline::Editor::<()>::new().unwrap();
    loop {
        let line = match rl.readline(">> ") {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                line
            }
            Err(err) => {
                println!("{:?}", err);
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let (command, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        if let Err(e) = program.run_command(command, rest) {
            println!("Command failed: {e}");
        }
    }
    Ok(())
}
