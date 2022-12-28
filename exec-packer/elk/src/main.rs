use std::{env, error::Error, fs};


fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("useage: elk FILE");
    let input = fs::read(&input_path)?;
    delf::File::parse(&input[..]).map_err(|e| format!("{:?}", e))?;
    println!("input is a suported Elf file!");
    Ok(())
}
