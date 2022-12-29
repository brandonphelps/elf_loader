

mod parse;


use derive_more::*;
use num_enum::{TryFromPrimitive};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Add, Sub)]
pub struct Addr(pub u64);


impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result  {
        write!(f, "{:08x}", self.0)
    }
}


impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result  {
        fmt::Debug::fmt(self, f)
    }
}

impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_from_enum!(Type, le_u16);
impl_parse_from_enum!(Machine, le_u16);


#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr, 
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{
            bytes::complete::{tag, take},
            error::context,
            combinator::map,
            sequence::tuple,
            number::complete::le_u16,
        };

        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            // only supporting 64 bit atm
            context("Class", tag(&[0x2])),
            // only supports little endian. 
            context("Endianness", tag(&[0x1])),
            context("Version", tag(&[0x1])),
            context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8_usize)),
        ))(i)?;

        use nom::{combinator::verify, number::complete::le_u32};

        let (i, (r#type, machine)) = tuple((Type::parse, Machine::parse))(i)?;

        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;
        let (i, entry_point) = Addr::parse(i)?;

        let res = Self {
            r#type,
            machine,
            entry_point,
        };

        Ok((i, res))
    }

    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                eprintln!("Parsing failed:");
                for (input, err) in err.errors {

                    use nom::Offset;
                    let offset = i.offset(input);
                    eprintln!("{:?} at position {}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }
}


pub struct HexDump<'a>(&'a [u8]);

use std::fmt;
impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x}", x)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Machine;
    use std::convert::TryFrom;

    use num_enum::TryFromPrimitiveError;

    #[test]
    fn type_to_u16() {
        assert_eq!(super::Type::Dyn as u16, 0x3);
        
    }

    #[test]
    fn try_enums() {
        assert_eq!(Machine::X86_64 as u16, 0x3E);
        assert_eq!(Machine::try_from(0x3E), Ok(Machine::X86_64));
        assert_eq!(Machine::try_from(0xFA), Err(TryFromPrimitiveError { number: 0xFA }));
    }

}
