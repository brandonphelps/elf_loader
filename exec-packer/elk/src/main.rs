use std::{env, error::Error, fs};

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio}
    };

    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
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


fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press enter to {}...", reason);
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
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
    let code_ph = file.program_headers.iter().find(|ph| ph.mem_range().contains(&file.entry_point)).expect("Segement with entry point not found");
    ndisasm(&code_ph.data[..], file.entry_point)?;

    println!("Executing {:?} in memory...", input_path);

    use region::{protect, Protection};
    let code = &code_ph.data;
    pause("protect")?;
    unsafe {
        protect(code.as_ptr(), code.len(), Protection::READ_WRITE_EXECUTE)?;
    }

    let entry_offset = file.entry_point - code_ph.vaddr;
    let entry_point = unsafe { code.as_ptr().add(entry_offset.into()) };
    println!("        code @ {:?}", code.as_ptr());
    println!("entry offset @ {:?}", entry_offset);
    println!("entry point  @ {:?}", entry_point);

    pause("jmp")?;
    unsafe  {
        jmp(entry_point);
    }

    Ok(())
}
