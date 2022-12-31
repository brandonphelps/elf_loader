use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use delf::DynamicTag::Needed;

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

use std::{ops::Range, cmp::{min, max}};

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

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self
            .search_path
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
        let path = path.as_ref().canonicalize().map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;

        use std::io::Read;
        let mut fs_file = std::fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        let mut input = Vec::new();
        fs_file.read_to_end(&mut input)
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
                .filter(|ph| ph.r#type ==  delf::SegmentType::Load)
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
        let mem_map = MemoryMap::new(mem_size, &[])?;
        let base = delf::Addr(mem_map.data() as _) - mem_range.start;

        use mmap::MapOption;

        use std::os::unix::io::AsRawFd;
        let segments = load_segments()
            .filter_map(|ph| {
                if ph.memsz.0 > 0 {
                    let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                    let padding = ph.vaddr - vaddr;
                    let offset = ph.offset - padding;
                    let memsz = ph.memsz + padding;
                    println!("> {:#?}", ph);
                    println!("< file {:#?} | mem {:#?}",
                             offset..(offset + memsz),
                             vaddr..(vaddr + memsz));
                    println!("T {:?}", base + vaddr);
                    let map_res = MemoryMap::new(
                        memsz.into(),
                        &[
                            MapOption::MapReadable,
                            MapOption::MapWritable,
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                        ],
                    );

                    Some(map_res.map(|map| Segment {
                        map,
                        padding,
                        flags: ph.flags,
                    }))
                } else {
                    None
                }
            }).collect::<Result<Vec<_>, _>>()?;


        if path.to_str().unwrap().ends_with("libmsg.so") {
            let msg_addr: *const u8 = unsafe { (base + delf::Addr(0x2000)).as_ptr() };
            dbg!(msg_addr);
            let msg_slice = unsafe { std::slice::from_raw_parts(msg_addr, 0x26) };
            let msg = std::str::from_utf8(msg_slice).unwrap();
            dbg!(msg);
        }
        
        let index = self.objects.len();
        let res = Object {
            path: path.clone(),
            base,
            segments,
            mem_range,
            file,
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
}
