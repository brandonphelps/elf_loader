use std::{env, error::Error, fs};

fn ndisasm(code: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio}
    };

    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}


fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("useage: elk FILE");
    let input = fs::read(&input_path)?;
    let file = match delf::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };

    println!("{:#?}", file);

    println!("Executing {:?}...", input_path);
    use std::process::Command;

    println!("Disassembling {:?}...", input_path);
    let code = &input[0x1000..];

    let code = &code[..std::cmp::min(0x25, code.len())];
    ndisasm(code)?;

    let status = Command::new(&input_path).status()?;
    if !status.success() {
        return Err("process did not exit successfully".into());
    }

    println!("Executing {:?} in memory...", input_path);
    let entry_point = code.as_ptr();
    println!("Entry point: {:?}", entry_point);
    unsafe  {
        jmp(entry_point);
    }


    Ok(())
}
