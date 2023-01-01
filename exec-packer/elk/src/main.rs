use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};
use std::{env, error::Error, fs};

mod process;
mod name;

fn align_lo(x: usize) -> usize {
    x & !0xFFF
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    use std::{
        io::Write,
        process::{Command, Stdio},
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

fn main() {

    if let Err(e) = do_main() {
        eprintln!("Fatal error: {}", e);
    }
}

fn do_main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("useage: elk FILE");

    let mut proc = process::Process::new();
    let exec_index = proc.load_object_and_dependencies(input_path)?;
    proc.apply_relocations()?;
    proc.adjust_protections()?;
    
    let exec_obj = &proc.objects[exec_index];
    let entry_point = exec_obj.file.entry_point + exec_obj.base;
    unsafe { jmp(entry_point.as_ptr()) };
    return Ok(());

    println!("{:#?}", proc);
    return Ok(());

    let input = fs::read(&input_path)?;
    let file = match delf::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };

    println!("{:#?}", file);

    println!("Executing {:?}...", input_path);
    use std::process::Command;

    // println!("Disassembling {:?}...", input_path);
    let code_ph = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("Segement with entry point not found");
    // ndisasm(&code_ph.data[..], file.entry_point)?;

    println!("Dynamic entries:");
    if let Some(ds) = file
        .program_headers
        .iter()
        .find(|ph| ph.r#type == delf::SegmentType::Dynamic)
    {
        if let delf::SegmentContents::Dynamic(ref table) = ds.contents {
            for entry in table {
                println!(" - {:?}", entry);
            }
        }
    }

    let syms = file.read_syms().unwrap();
    println!(
        "Symbol table @ {:?} contains {} entries",
        file.dynamic_entry(delf::DynamicTag::SymTab).unwrap(),
        syms.len()
    );

    println!(
        "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
        "Num", "Value", "Size", "Type", "Bind", "Ndx", "Name"
    );
    for (num, s) in syms.iter().enumerate() {
        println!(
            "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
            format!("{}", num),
            format!("{:?}", s.value),
            format!("{:?}", s.size),
            format!("{:?}", s.r#type),
            format!("{:?}", s.bind),
            format!("{:?}", s.shndx),
            format!("{}", file.get_string(s.name).unwrap_or_default()),
        );
    }

    let msg = syms
        .iter()
        .find(|sym| file.get_string(sym.name).unwrap_or_default() == "msg")
        .expect("should find msg in symbol table");
    let msg_slice = file.slice_at(msg.value).expect("should find msg in memory");
    let msg_slice = &msg_slice[..msg.size as usize];
    println!("msg contents: {:?}", String::from_utf8_lossy(msg_slice));

    println!("Rela entries:");
    let rela_entries = file.read_rela_entries()?;
    for e in &rela_entries {
        println!("{:#?}", e);
        if let Some(seg) = file.segment_at(e.offset) {
            println!("... for {:#?}", seg);
        }
    }

    println!("Found {} rela entries", rela_entries.len());
    for entry in rela_entries.iter() {
        println!("{:?}", entry);
    }

    if let Some(dynseg) = file.segment_of_type(delf::SegmentType::Dynamic) {
        if let delf::SegmentContents::Dynamic(ref dyntab) = dynseg.contents {
            println!("Dynamic table entries:");
            for e in dyntab {
                println!("{:?}", e);
                match e.tag {
                    delf::DynamicTag::Needed | delf::DynamicTag::RPath => {
                        println!(" => {:?}", file.get_string(e.addr)?);
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some(entries) = file.dynamic_table() {
        for e in entries {
            println!("{:?}", e);
        }
    }

    for sh in &file.section_headers {
        println!("{:?}", sh);
    }

    let rela_entries = file.read_rela_entries()?;
    let base = 0x400000_usize;

    println!("Mapping {:?} in memory...", input_path);

    let mut mappings = Vec::new();

    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        // note:  mmap-ing would fail if the segemnts weren't aligned on pages,
        // but luckily, that is the case in the file already. That is not a coincidence.
        let mem_range = ph.mem_range();

        let len: usize = (mem_range.end - mem_range.start).into();

        let start: usize = mem_range.start.0 as usize + base;
        let aligned_start: usize = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        // `as` is the "cast" operator, and `_` is a  placeholder to force  rustc
        // to infer the type based on other hints
        let addr: *mut u8 = aligned_start as _;
        println!(
            "start: {:?} Addr: {:p}, Padding: {:08x}",
            start, addr, padding
        );

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data...");
        unsafe {
            std::ptr::copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        let mut num_relocs = 0;
        println!("Applying relocations (if any)...");
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                unsafe {
                    use std::mem::transmute as trans;

                    let real_segment_start = addr.add(padding);
                    let specified_reloc_offset = reloc.offset;
                    let specified_segment_start = mem_range.start;
                    let offset_into_segment = specified_reloc_offset - specified_segment_start;

                    println!(
                        "Applying {:?} relocation @ {:?} form segment start",
                        reloc.r#type, offset_into_segment
                    );

                    match reloc.r#type {
                        delf::RelType::Relative => {
                            let reloc_addr: *mut u64 =
                                trans(real_segment_start.add(offset_into_segment.into()));
                            let reloc_value = reloc.addend + delf::Addr(base as u64);
                            *reloc_addr = reloc_value.0;
                        },
                        t => {
                            panic!("Unsupported relocation type {:?}", t);
                        }
                    }
                }
            }
        }

        println!("Adjusting permissions...");

        let mut protection = Protection::NONE;

        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }

        unsafe {
            protect(addr, len, protection)?;
        }
        mappings.push(map);
    }

    println!("Executing {:?} in memory...", input_path);

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
    unsafe {
        jmp((file.entry_point.0 as usize + base) as _);
    }

    Ok(())
}
