mod parse;
use enumflags2::BitFlags;

use derive_more::*;
use enumflags2::*;
use num_enum::TryFromPrimitive;

#[derive(thiserror::Error, Debug)]
pub enum ReadRelError {
    #[error("Rela dynamic entry not found")]
    RelaNotFound,
    #[error("RelaSz dynamic entry not found")]
    RelaSzNotFound,

    #[error("RelaEnt dynamic entry not found")]
    RelaEntNotFound,

    #[error("RelaSeg dynamic entry not found")]
    RelaSegNotFound,

    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error")]
    ParsingError(nom::error::VerboseErrorKind),
}

#[derive(thiserror::Error, Debug)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}


#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

impl_parse_from_enum!(SegmentType, le_u32);

#[bitflags]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

impl_parse_for_enumflags!(SegmentFlag, le_u32);

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,
    pub contents: SegmentContents,
}

#[derive(Debug)]
pub enum SegmentContents {
    Dynamic(Vec<DynamicEntry>),
    Unknown,
}

#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}


#[derive(Debug, TryFromPrimitive, PartialEq, Eq)]
#[repr(u64)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 0xf,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    RunPath = 29,
    Flags = 30,
    Encoding = 32,
    LoOs = 0x60000000,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    VerNeedNum = 0x6fffffff,
    RelACount = 0x6ffffff9,    
    LoProc = 0x70000000,
    HiProc = 0x7fffffff,
}

impl_parse_from_enum!(DynamicTag, le_u64);

impl DynamicEntry {
    fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::sequence::tuple;
        let (i, (tag, addr)) = tuple((DynamicTag::parse, Addr::parse))(i)?;
        Ok((i,  Self { tag, addr }))
    }
}

#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KnownRelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}

impl_parse_from_enum!(KnownRelType, le_u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelType {
    Known(KnownRelType),
    Unknown(u32),
}

impl RelType {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{branch::alt, combinator::map, number::complete::le_u32};

        alt((
            map(KnownRelType::parse, Self::Known),
            map(le_u32, Self::Unknown)
        ))(i)
    }
}

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub r#type: RelType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        println!("Rela parse");
        use nom::{combinator::map, number::complete::le_u32, sequence::tuple};
        map(
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse)),
            |(offset, r#type, sym, addend)| Rela {
                offset,
                r#type,
                sym,
                addend
            }
        )(i)
    }
}


use std::ops::Range;

impl ProgramHeader {
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        use nom::sequence::tuple;

        println!("Program header parse");
        println!("{:?}", HexDump(i));

        let (i, (r#type, flags)) = tuple((SegmentType::parse, SegmentFlag::parse))(i)?;
        println!("Type: {:?}", r#type);


        let ap = Addr::parse;
        let (i, (offset, vaddr, paddr, filesz, memsz, align)) = tuple((ap, ap, ap, ap, ap, ap))(i)?;

        use nom::{combinator::{map, verify}, multi::many_till};
        // this used to be directly in the `Self` struct literal, but
        // we're going to use it in the next block to parse dynamic entries from it.
        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match r#type {
            SegmentType::Dynamic => {
                // *if* this is a Dynamic segment, we parse its contents. we haven't
                // implemented `DynamicEntry::parse` yet, but it's coming!
                map(
                    many_till(DynamicEntry::parse,
                              verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
                    ),
                    |(entries, _last)| SegmentContents::Dynamic(entries),
                )(slice)?
            }
            _ => (slice, SegmentContents::Unknown),
        };

        let res = Self {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            data: full_input[offset.into()..][..filesz.into()].to_vec(),
            contents,
        };
        Ok((i, res))
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            // the default Debug formatter for `enumflags2` is a bit
            // on the verbose side, let's print something like `RWX` instead
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X")
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.r#type,
        )
    }
}

#[derive(Debug)]
pub struct File {
    pub r#type: Type,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let full_input = i;

        use nom::{
            bytes::complete::{tag, take},
            combinator::map,
            error::context,
            number::complete::le_u16,
            sequence::tuple,
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

        // some values are stored as u16 to save storage, but they're actually
        // file offsets, or counts, so we want them as a `usize` in rust.
        // let u16_usize = map(le_u16, |x| x as usize);

        // ph = program header, sh = section header

        let (i, (ph_offset, sh_offset)) = tuple((Addr::parse, Addr::parse))(i)?;
        let (i, (flags, hdr_size)) = tuple((le_u32, le_u16))(i)?;
        let (i, (ph_entsize, ph_count)) =
            tuple((map(le_u16, |x| x as usize), map(le_u16, |x| x as usize)))(i)?;
        let (i, (sh_entsize, sh_count, sh_nidx)) = tuple((
            map(le_u16::<&[u8], _>, |x| x as usize),
            map(le_u16, |x| x as usize),
            map(le_u16, |x| x as usize),
        ))(i)?;

        println!("{:?}", sh_entsize + 1 as usize);

        let ph_slices = (&full_input[ph_offset.into()..]).chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        let res = Self {
            r#type,
            machine,
            entry_point,
            program_headers,
        };

        Ok((i, res))
    }

    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelError> {
        use DynamicTag as DT;
        use ReadRelError as E;

        let addr = self.dynamic_entry(DT::Rela).ok_or(E::RelaNotFound)?;
        let len = self.dynamic_entry(DT::RelaSz).ok_or(E::RelaSzNotFound)?;
        let ent = self.dynamic_entry(DT::RelaEnt).ok_or(E::RelaEntNotFound)?;

        let i = self.slice_at(addr).ok_or(E::RelaSegmentNotFound)?;
        let i = &i[..len.into()];

        let n = (len.0 / ent.0) as usize;

        use nom::multi::many_m_n;
        match many_m_n(n, n, Rela::parse)(i) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                let e = &err.errors[0];
                let (_input, error_kind) = e;
                Err(E::ParsingError(error_kind.clone()))
            },
            _ => unreachable!(),
        }
        
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

    pub fn segment_at(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.r#type == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    pub fn segment_of_type(&self, r#type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.r#type == r#type)
    }

    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        match self.segment_of_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContents::Dynamic(entries),
                ..
            }) => entries.iter().find(|e| e.tag == tag).map(|e| e.addr),
            _ => None
        }
    }

    pub fn slice_at(&self, mem_addr: Addr) -> Option<&[u8]> {
        self.segment_at(mem_addr)
            .map(|seg| &seg.data[(mem_addr - seg.mem_range().start).into()..])
    }

    pub fn get_string(&self, offset: Addr) -> Result<String, GetStringError> {
        use DynamicTag as DT;
        use GetStringError as E;

        let addr = self.dynamic_entry(DT::StrTab).ok_or(E::StrTabNotFound)?;
        let slice = self
            .slice_at(addr + offset)
            .ok_or(E::StrTabSegmentNotFound)?;

        // Our strings are null-terminated, so we lazily split the slice into
        // slices seperated by '\0' and take the first item.
        let string_slice = slice.split(|&c| c == 0).next().ok_or(E::StringNotFound)?;
        Ok(String::from_utf8_lossy(string_slice).into())
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
        assert_eq!(
            Machine::try_from(0xFA),
            Err(TryFromPrimitiveError { number: 0xFA })
        );
    }

    #[test]
    fn try_bit_flag() {
        use super::SegmentFlag;
        use enumflags2::BitFlags;

        let flags_integer: u32 = 6;
        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();
        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}
