use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use delf::DynamicTag::Needed;

use multimap::MultiMap;

use crate::name::Name;
use mmap::MemoryMap;

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O error: {0}: {1}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),

    #[error("Elf object has no load segments")]
    NoLoadSegments,

    #[error("Elf object could not be mapped in memory: {0}")]
    MapError(#[from] mmap::MapError),

    #[error("Could not read symbols from  ELF object: {0}")]
    ReadSymsError(#[from] delf::ReadSymsError),
}

#[derive(Debug, Clone)]
struct NamedSym {
    sym: delf::Sym,
    name: Name,
}

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,

    pub objects_by_path: HashMap<PathBuf, usize>,

    pub search_path: Vec<PathBuf>,
}

use enumflags2::BitFlags;

#[derive(custom_debug_derive::Debug)]
pub struct Segment {
    #[debug(skip)]
    pub map: MemoryMap,
    pub padding: delf::Addr,
    pub flags: BitFlags<delf::SegmentFlag>,
}

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}

use std::{
    cmp::{max, min},
    ops::Range,
};

fn dump_maps(msg: &str) {
    use std::{fs, process};

    println!("============== MEMORY MAPS: {}", msg);

    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{}", line));
    println!("==============================");
}

fn convex_hull(a: Range<delf::Addr>, b: Range<delf::Addr>) -> Range<delf::Addr> {
    (min(a.start, b.start))..(max(a.end, b.end))
}

impl Process {
    pub fn new() -> Self {
        Self {
            objects: vec![],
            objects_by_path: HashMap::new(),
            search_path: vec!["/usr/lib/x86_64-linux-gnu/".into()],
        }
    }

    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};

        for obj in &self.objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;
                for flag in seg.flags.iter() {
                    protection |= match flag {
                        delf::SegmentFlag::Read => Protection::READ,
                        delf::SegmentFlag::Write => Protection::WRITE,
                        delf::SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }
                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }
        Ok(())
    }

    pub fn lookup_symbol(
        &self,
        name: &str,
        ignore: Option<&Object>,
    ) -> Result<Option<(&Object, &delf::Sym)>, RelocationError> {
        for obj in &self.objects {
            if let Some(ignored) = ignore {
                if std::ptr::eq(ignored, obj) {
                    continue;
                }
            }

            for (i, sym) in obj.syms.iter().enumerate() {
                if obj.sym_name(i as u32)? == name {
                    return Ok(Some((obj, sym)));
                }
            }
        }
        Ok(None)
    }

    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        dump_maps("before relocations");

        for obj in self.objects.iter().rev() {
            println!("Applying relocations for {:?}", obj.path);
            match obj.file.read_rela_entries() {
                Ok(rels) => {
                    for rel in rels {
                        println!("Found {:?}", rel);
                        let reltype = rel.r#type;
                        use delf::RelType as RT;
                        match reltype { 
                            RT::_64 => {
                                let name = obj.sym_name(rel.sym)?;
                                println!("Looking up {:?}", name);
                                let (lib, sym) = self
                                    .lookup_symbol(&name, None)?
                                    .ok_or(RelocationError::UndefinedSymbol(name))?;
                                println!("Found at {:?} in {:?}", sym.value, lib.path);
                                let offset = obj.base + rel.offset;
                                let value = sym.value + lib.base + rel.addend;

                                unsafe {
                                    *offset.as_mut_ptr() = value.0;
                                }
                            },
                            RT::Copy => {
                                let name = obj.sym_name(rel.sym)?;
                                let (lib, sym) =
                                    self.lookup_symbol(&name, Some(obj))?.ok_or_else(|| {
                                        RelocationError::UndefinedSymbol(name.clone())
                                    })?;
                                println!("Found {:?} at {:?} (size {:?}) in {:?}",
                                         name, sym.value,  sym.size, lib.path);
                                println!("Copy: stub!");

                                unsafe {
                                    let src = (sym.value + lib.base).as_ptr();
                                    let dst = (rel.offset + obj.base).as_mut_ptr();
                                    std::ptr::copy_nonoverlapping::<u8>(
                                        src, dst, sym.size as usize
                                    );
                                }
                            }
                            t => return Err(RelocationError::UnimplementedRelocation(t)),
                        }
                    }
                },
                Err(e) => {
                    println!("Nevermind: {:?}", e)
                }
            }
        }
        Ok(())
    }

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|path| path.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn load_object_and_dependencies<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;

        let mut a = vec![index];
        while !a.is_empty() {
            a = a
                .into_iter()
                .map(|index| &self.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(Needed))
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
        }
        Ok(index)
    }

    pub fn load_object<P: AsRef<Path>>(&mut self, path: P) -> Result<usize, LoadError> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;

        use std::io::Read;
        let mut fs_file = std::fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        let mut input = Vec::new();
        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:#?}", path);
        let file = delf::File::parse_or_print_error(&input[..])
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RPath) // for some reason this is backwards? faster than lime uses RPATH
                .map(|path| path.replace("$ORIGIN", &origin))
                .inspect(|path| println!("Found RPATH entry {:?}", path))
                .map(PathBuf::from),
        );

        self.search_path.extend(
            file.dynamic_entry_strings(delf::DynamicTag::RunPath) // for some reason this is backwards? faster than lime uses RPATH
                .map(|path| path.replace("$ORIGIN", &origin))
                .inspect(|path| println!("Found RPATH entry {:?}", path))
                .map(PathBuf::from),
        );

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|ph| ph.r#type == delf::SegmentType::Load)
        };

        let mem_range = file
            .program_headers
            .iter()
            .filter(|ph| ph.r#type == delf::SegmentType::Load)
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = std::mem::ManuallyDrop::new(MemoryMap::new(mem_size, &[MapOption::MapReadable, MapOption::MapWritable])?);
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        use mmap::MapOption;

        use std::os::unix::io::AsRawFd;
        let segments = load_segments()
            .filter(|ph| ph.memsz.0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let filesz = ph.filesz + padding;

                let map = MemoryMap::new(
                    filesz.into(),
                    &[
                        MapOption::MapReadable,
                        MapOption::MapWritable,
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(offset.into()),
                        MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                    ],
                )?;

                if ph.memsz > ph.filesz {
                    // ... then we zero them!
                    // note: this works because we already reserved the *convex hull*
                    // of all segments in memoory in our initial `MemoryMap::new` call,
                    // so that memory is there.
                    let mut zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;
                    unsafe {
                        for i in zero_start.as_mut_slice(zero_len.into()) {
                            *i = 0u8;
                        }
                    }
                }

                Ok(Segment {
                    map,
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr: *const u8 = unsafe { (base + delf::Addr(0x2000)).as_ptr() };
            dbg!(msg_addr);
            let msg_slice = unsafe { std::slice::from_raw_parts(msg_addr, 0x26) };
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }

        let syms = file.read_syms()?;
        let strtab = file
            .get_dynamic_entry(delf::DynamicTag::StrTab)
            .unwrap_or_else(|_| panic!("String table not found in {:?}", path));

        let syms: Vec<_> = syms
            .into_iter()
            .map(|sym| unsafe {
                let name = Name::from_addr(base + strtab + sym.name);
                NamedSym { sym, name }
            })
            .collect();

        let index = self.objects.len();
        let res = Object {
            path: path.clone(),
            base,
            segments,
            mem_range,
            file,
            syms,
            sym_map,
        };

        self.objects.push(res);
        self.objects_by_path.insert(path, index);

        Ok(index)
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }
}

use custom_debug_derive::Debug as CustomDebug;

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,

    pub base: delf::Addr,

    pub segments: Vec<Segment>,

    pub mem_range: Range<delf::Addr>,

    #[debug(skip)]
    pub file: delf::File,

    #[debug(skip)]
    pub syms: Vec<delf::Sym>,

    #[debug(skip)]
    sym_map: MultiMap<Name, NamedSym>,

}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("unimplemented relocation: {0:?}")]
    UnimplementedRelocation(delf::RelType),
    #[error("unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("undefined symbol: {0}")]
    UndefinedSymbol(String),
}

impl Object {
    pub fn sym_name(&self, index: u32) -> Result<String, RelocationError> {
        self.file
            .get_string(self.syms[index as usize].name)
            .map_err(|_| RelocationError::UnknownSymbolNumber(index))
    }
}
