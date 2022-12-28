use std::{env, error::Error, fs};


fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("useage: elk FILE");
    let input = fs::read(&input_path)?;
    let (_, file) = delf::File::parse_or_print_error(&input[..]).map_err(|e| format!("{:?}", e))?;
    println!("input is a suported Elf file!");

    println!("{:?}", file);

    Ok(())
}
