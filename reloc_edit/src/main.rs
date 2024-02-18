#![allow(non_camel_case_types)]
#![allow(unused)]
#![allow(non_snake_case)]

use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::{fs, io, mem, fmt};
use std::ffi::{CString, CStr};
use std::collections::HashMap;

extern crate num;
extern crate num_derive;
use num_derive::FromPrimitive;

/*
/* 64-bit ELF base types. */
typedef __u64	Elf64_Addr;
typedef __u16	Elf64_Half;
typedef __s16	Elf64_SHalf;
typedef __u64	Elf64_Off;
typedef __s32	Elf64_Sword;
typedef __u32	Elf64_Word;
typedef __u64	Elf64_Xword;
typedef __s64	Elf64_Sxword;
*/

#[derive(Debug, Clone, Copy)]
enum EI_CLASS {
    Bits32 = 1,
    Bits64 = 2,
}

#[derive(Debug, Clone, Copy)]
enum EI_DATA {
    Little = 1,
    Big = 2,
}

#[derive(Debug, Clone, Copy)]
enum EI_OSABI {
    SystemV = 0x00,
    HP_UX,
    NetBSD,
    Linux,
    GNU_Hurd,
    Solaris = 0x06,
    AIX,
    IRIX,
    FreeBSD,
    Tru64,
    NovelModesto,
    OpenBSD,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ElfIdent {
    ei_magic: [u8; 4],
    ei_class: EI_CLASS,
    ei_data: EI_DATA,
    ei_version: u8,
    ei_osabi: EI_OSABI,
    ei_abiversion: u8,
    ei_pad: [u8; 7],
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
enum E_TYPE {
    ET_NONE = 0x00,
    ET_REL,
    ET_EXEC,
    ET_DYN,
    ET_CORE,
}

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
enum E_MACHINE {
    UNKNOWN = 0x00,
    AT,
    SPARC,
    x86,
    Motorola_68,
    Motorola_88,
    Intel_MCU,
    Intel_80860,
    MIPS,
    HP_PA = 0x0F,
    Intel_80960 = 0x13,
    PowerPC_32,
    PowerPC_64,
    S390,
    AArch32 = 0x28,
    AMD64 = 0x3e,
    AArch64 = 0xB7,
    RISC_V = 0xF3,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct ElfHdr {
    e_ident: ElfIdent,
    e_type: E_TYPE,
    e_machine: E_MACHINE,
    e_version: u32,
    e_entry: u64	,	/* Entry point virtual address */
    e_phoff: u64,		/* Program header table file offset */
    e_shoff: u64,		/* Section header table file offset */
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum P_TYPE {
    PT_NULL = 0x00, /* Program header table entry unused.  */
    PT_LOAD, /* Loadable segment.  */
    PT_DYNAMIC, /* Dynamic linking information.  */
    PT_INTERP, /* Interpreter information.  */
    PT_NOTE, /* Auxiliary information.  */
    PT_SHLIB, /* Reserved.  */
    PT_PHDR, /* Segment containing program header table itself.  */
    PT_TLS, /* Thread-Local Storage template.  */
    PT_LOOS,
    PT_GNU_EH_FRAME = 0x6474E550, /* The array element specifies the location and size of the exception handling information as defined by the .eh_frame_hdr section. */
    PT_GNU_STACK,
    PT_GNU_RELRO,
    PT_GNU_PROPERTY
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Elf64_Phdr {
    p_type: P_TYPE,
    p_flags: u32,
    p_offset: u64,		/* Segment file offset */
    p_vaddr: u64,		/* Segment virtual address */
    p_paddr: u64,		/* Segment physical address */
    p_fileszu: u64,		/* Segment size in file */
    p_memsz: u64,		/* Segment size in memory */
    p_align: u64,		/* Segment alignment, file & memory */
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
enum SH_TYPE {
    SHT_NULL = 0x00, /* Section header table entry unused */
    SHT_PROGBITS,
    SHT_SYMTAB,
    SHT_STRTAB,
    SHT_RELA,
    SHT_HASH,
    SHT_DYNAMIC,
    SHT_NOTE,
    SHT_NOBITS,
    SHT_REL,
    SHT_SHLIB,
    SHT_DYNSYM,
    SHT_INIT_ARRAY,
    SHT_FINI_ARRAY,
    SHT_PREINIT_ARRAY,
    SHT_GROUP,
    SHT_SYMTAB_SHNDX,
    SHT_NUM,
    SHT_GNU_HASH = 0x6ffffff6,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Elf64_Shdr {
    sh_name: u32 ,		/* Section name, index in string tbl */
    sh_type: SH_TYPE,		/* Type of section */
    sh_flags: u64,		/* Miscellaneous section attributes */
    sh_addr: u64,		/* Section virtual addr at execution */
    sh_offset: u64,		/* Section file offset */
    sh_size: u64,		/* Size of section in bytes */
    sh_link: u32,		/* Index of another section */
    sh_info: u32,		/* Additional section information */
    sh_addralign: u64,	/* Section alignment */
    sh_entsize: u64,	/* Entry size if section holds table */
}

fn read_file_offset_size(filename: &String, offset: u64, size: usize) -> Result<Vec<u8>, io::Error> {
    let mut f = File::open(&filename)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0; size];
    f.read_exact(&mut buffer).expect("buffer overflow");

    Ok(buffer)
}

fn read_file(filename: &String)-> Result<Vec<u8>, io::Error>{
    let metadata = fs::metadata(filename)?;
    read_file_offset_size(filename, 0, metadata.len() as usize)
}

#[derive(Debug)]
struct Elf {
    header: ElfHdr,
    program_header: Option<Vec<Elf64_Phdr>>,
    programHdr: Option<Vec<ProgramHdr>>,
    section_header: Option<Vec<Elf64_Shdr>>,
    sectionHdr: Option<HashMap<String, SectionHdr>>,
    content: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u64)]
enum D_TAG {
    DT_NULL = 0,
    DT_NEEDED,
    DT_PLTRELSZ,
    DT_PLTGOT,
    DT_HASH,
    DT_STRTAB,
    DT_SYMTAB,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_STRSZ,
    DT_SYMENT,
    DT_INIT,
    DT_FINI,
    DT_SONAME,
    DT_RPATH,
    DT_SYMBOLIC,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_DEBUG,
    DT_TEXTREL,
    DT_JMPREL,
    DT_BIND_NOW,
    DT_INIT_ARRAY = 25,
    DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_FINI_ARRAYSZ,
    DT_GNU_HASH = 0x6ffffef5,
    DT_VERSYM = 0x6ffffff0,
    DT_RELACOUNT = 0x6ffffff9,
    DT_FLAGS_1 = 0x6ffffffb,
    DT_VERDEF,
    DT_VERDEFNUM,
    DT_VERNEED,
    DT_VERNEEDNUM,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Elf64_Dyn {
    d_tag: D_TAG,
    d_un: u64,
}



#[derive( Copy, Clone)]
#[repr(C, packed)]
struct ST_INFO {
    value: u8
}

#[derive(Debug, FromPrimitive)]
enum ST_TYPE {
    STT_NOTYPE = 	0, // The symbol's type is not specified. 
    STT_OBJECT = 	1, // The symbol is associated with a data object, such as a variable, an array, and so on. 
    STT_FUNC = 	2, // The symbol is associated with a function or other executable code. 
    STT_SECTION = 	3, // The symbol is associated with a section. 
    STT_FILE = 	4, // Conventionally, the symbol's name gives the name of the source file associated with the object file.
    STT_COMMON = 	5, // The symbol labels an uninitialized common block
    STT_TLS = 	6, // The symbol specifies a Thread-Local Storage entity.
    STT_LOOS = 	10,
    STT_HIOS = 	12,
    STT_LOPROC = 	13,
    STT_HIPROC = 	15,
}

#[derive(Debug, FromPrimitive)]
enum ST_BIND {
    STB_LOCAL = 0,
    STB_GLOBAL,
    STB_WEAK,
    STB_LOOS = 10,
    STB_HIOS = 12,
    STB_LOPROC,
    STB_HIPROC = 15
}

impl fmt::Debug for ST_INFO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let st_type: ST_TYPE = num::FromPrimitive::from_u8(self.value & 0xf).unwrap() ;
        let st_bind: ST_BIND = num::FromPrimitive::from_u8(self.value >> 4).unwrap();
        write!(f, "{} = {:?} {:?}", self.value, st_type, st_bind)
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Elf64_Sym {
    st_name: u32,   /* Offset into the corresponding table's string table */
    st_info: ST_INFO,    /* Symbol type and binding attributes */
    st_other: u8,   /* Symbol visibility */
    st_shndx: u16,  /* Each symbol is defined for a particular section */
    st_value: u64,  /* Either an address or offset */
    st_size: u64,   /* Size of the actual reference */
}

#[derive(Debug)]
struct SectionHdr {
    name: String,
    r#type: SH_TYPE,
    offset: usize,
    size: usize,
}


#[derive(Debug, Copy, Clone)]
struct ProgramHdr {
    
}

#[derive( Copy, Clone)]
#[repr(C, packed)]
struct R_INFO {
    value: u64
}

#[derive(Debug, FromPrimitive)]
enum R_SYM {
    STT_NOTYPE = 	0, // The symbol's type is not specified. 
    STT_OBJECT = 	1, // The symbol is associated with a data object, such as a variable, an array, and so on. 
    STT_FUNC = 	2, // The symbol is associated with a function or other executable code. 
    STT_SECTION = 	3, // The symbol is associated with a section. 
    STT_FILE = 	4, // Conventionally, the symbol's name gives the name of the source file associated with the object file.
    STT_COMMON = 	5, // The symbol labels an uninitialized common block
    STT_TLS = 	6, // The symbol specifies a Thread-Local Storage entity.
    STT_LOOS = 	10,
    STT_HIOS = 	12,
    STT_LOPROC = 	13,
    STT_HIPROC = 	15,
}

#[derive(Debug, FromPrimitive)]
enum R_TYPE {
    R_AMD64_NONE = 0,
    R_AMD64_64,
    R_AMD64_PC32,
    R_AMD64_GOT32,
    R_X86_64_PLT32,//,
    R_X86_64_COPY,
    R_X86_64_GLOB_DAT,
    R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE,
    R_X86_64_GOTPCREL,
    R_X86_64_32,// 	10 	word32 	S + A
    R_X86_64_32S,// 	11 	word32 	S + A
    R_X86_64_16,// 	12 	word16 	S + A
    R_X86_64_PC16,// 	13 	word16 	S + A - P
    R_X86_64_8,// 	14 	word8 	S + A
    R_X86_64_PC8,// 	15 	word8 	S + A - P
    R_X86_64_DPTMOD64,// 	16 	word64 	 
    R_X86_64_DTPOFF64,// 	17 	word64 	 
    R_X86_64_TPOFF64,// 	18 	word64 	 
    R_X86_64_TLSGD,// 	19 	word32 	 
    R_X86_64_TLSLD,// 	20 	word32 	 
    R_X86_64_DTPOFF32,// 	21 	word32 	 
    R_X86_64_GOTTPOFF,// 	22 	word32 	 
    R_X86_64_TPOFF32,// 	23 	word32 	 
}

impl fmt::Debug for R_INFO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.value;
        let r_type: R_TYPE = num::FromPrimitive::from_u64(value & 0xffffffff).unwrap() ;
        let r_bind = self.value >> 32;
        write!(f, "{} = {:?} {:?}", value, r_type, r_bind)
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Elf64_Rela {
    r_offset: u64,
    r_info: R_INFO,
    r_addend: u64
}

impl Elf {
    pub fn load(file: &String) -> Result<Elf, ()>{
        // ELF Header
        let hdr_b: Vec<u8> = read_file_offset_size(file, 0, mem::size_of::<ElfHdr>() as usize).expect("Error while reading header");
        println!("Start {:?}", hdr_b);
        let (head, body, _tail) = unsafe { hdr_b.align_to::<ElfHdr>() };
        assert!(head.is_empty(), "Data was not aligned");
        let hdr = &body[0];
        println!("{:?}", hdr);
        let entry = hdr.e_entry;
        println!("{:x}", entry);

        // Program header table
        let e_phoff = hdr.e_phoff as u64;
        let e_phentsize = hdr.e_phentsize as usize;
        let e_phnum = hdr.e_phnum as usize;
        let phdr_b = read_file_offset_size(file, e_phoff, e_phentsize*e_phnum).expect("Error while reading phdr");
        let mut phdr = Vec::<Elf64_Phdr>::new();
        for i in (0..e_phentsize*e_phnum).step_by(e_phentsize) {
            let (head, body, _tail) = unsafe { &phdr_b[i..i+e_phentsize].align_to::<Elf64_Phdr>() };
            assert!(head.is_empty(), "Data was not aligned");
            phdr.push(body[0]);
            println!("{:?}" , phdr[phdr.len()-1]);
        }

        // Section header table
        let e_shoff = hdr.e_shoff as u64;
        let e_shentsize = hdr.e_shentsize as usize;
        let e_shnum = hdr.e_shnum as usize;
        let shdr_b = read_file_offset_size(file, e_shoff, e_shentsize*e_shnum).expect("Error while reading shdr");
        let mut shdr = Vec::<Elf64_Shdr>::new();
        for i in (0..e_shentsize*e_shnum).step_by(e_shentsize) {
            let (head, body, _tail) = unsafe { &shdr_b[i..i+e_shentsize].align_to::<Elf64_Shdr>() };
            assert!(head.is_empty(), "Data was not aligned");
            shdr.push(body[0]);
            println!("{:?}" , shdr[shdr.len()-1]);
        }
        let content = read_file(file).expect("Unable to read he hole file");

        // Build internal representation
        let shstrtab = shdr[hdr.e_shstrndx as usize];
        let shstrtab_b = &content[shstrtab.sh_offset as usize..(shstrtab.sh_offset+shstrtab.sh_size) as usize];
        let mut sectionHdr: HashMap<String, SectionHdr> = HashMap::new();
        for i in shdr.iter() {
            let name = CStr::from_bytes_until_nul(&shstrtab_b[i.sh_name as usize..]).unwrap().to_str().unwrap().to_owned();
            println!("{} {:?}" , name, i);
            sectionHdr.insert(name.clone(), SectionHdr{
                name: name,
                r#type: i.sh_type,
                offset: i.sh_offset as usize,
                size: i.sh_size as usize,
            });
        }

        Ok(Elf {
            header: *hdr,
            program_header: Some(phdr),
            programHdr: None,
            section_header: Some(shdr),
            content: content,
            sectionHdr: Some(sectionHdr),
        })
    }

    pub fn is_dynamic(&self) -> bool {
        match &self.section_header {
            Some(shdr) => {
                shdr.iter().filter(|x| {let y=x.sh_type; y == SH_TYPE::SHT_DYNAMIC} ).count() >= 1
            }
            None => false
        }
    }

    pub fn parse_dynamic(&self){
        match &self.section_header {
            Some(shdr) => {
                let sht_dynamic = shdr.iter().filter(|x| {let y=x.sh_type; y == SH_TYPE::SHT_DYNAMIC} ).next().expect("In not dynamic");

                let sh_offset = sht_dynamic.sh_offset as usize;
                let sh_size = sht_dynamic.sh_size as usize;
                let dyn_b = &self.content[sh_offset..sh_offset+sh_size];
                for i in (0..sh_size).step_by(0x10) {
                    let (head, body, _tail) = unsafe { &dyn_b[i..i+0x10].align_to::<Elf64_Dyn>() };
                    assert!(head.is_empty(), "Data was not aligned");
                    let toto = &body[0];
                    println!("{:?}" , toto);
                }
            }
            None => {}
        }
    }

    pub fn has_section(&self, section: SH_TYPE) -> bool {
        match &self.section_header {
            Some(shdr) => {
                shdr.iter().filter(|x| {let y=x.sh_type; y == section} ).count() >= 1
            }
            None => false
        }
    }

    pub fn has_symbols(&self) -> bool{
        self.has_section(SH_TYPE::SHT_SYMTAB)
    }

    pub fn parse_symbols(&self) {
        match &self.sectionHdr {
            Some(shdr) => {
                let sht_symtab = &shdr[".symtab"];
                let symtab_b = &self.content[sht_symtab.offset..sht_symtab.offset+sht_symtab.size];
                let sht_strtab = &shdr[".strtab"];
                let strtab_b = &self.content[sht_strtab.offset..sht_strtab.offset+sht_strtab.size];
                for i in (0..sht_symtab.size).step_by(mem::size_of::<Elf64_Sym>()) {
                    let (head, body, _tail) = unsafe { &symtab_b[i..i+mem::size_of::<Elf64_Sym>()].align_to::<Elf64_Sym>() };
                    assert!(head.is_empty(), "Data was not aligned");
                    let toto = &body[0];
                    let name = CStr::from_bytes_until_nul(&strtab_b[toto.st_name as usize..]).unwrap();
                    println!("{:?} {:?}" , name, toto);
                }
            }
            None => {}
        }
    }

    pub fn parse_relocations(&self) {
        match (&self.sectionHdr, &self.program_header) {
            (Some(shdr), Some(phdr)) => {
                let sht_reladyn = &shdr[".rela.dyn"];
                let reladyn_b = &self.content[sht_reladyn.offset..sht_reladyn.offset+sht_reladyn.size];

                for i in (0..sht_reladyn.size).step_by(mem::size_of::<Elf64_Rela>()) {
                    let (head, body, _tail) = unsafe { &reladyn_b[i..i+mem::size_of::<Elf64_Rela>()].align_to::<Elf64_Rela>() };
                    assert!(head.is_empty(), "Data was not aligned");
                    let toto = &body[0];
                    println!("{:?}", toto);
                }
            }
            _ => {}
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Nb args {} != 2", args.len());
        return
    }

    let file = &args[1];
    println!("Analysing {}", file);
    let elf = Elf::load(file).expect("Error loading elf");
    // println!("{:?}", elf);

    if elf.is_dynamic() {
        elf.parse_dynamic();
        elf.parse_relocations();
    }

    // if elf.has_symbols() {
    //     elf.parse_symbols();
    // }
} 
