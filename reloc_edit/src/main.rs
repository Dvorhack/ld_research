use std::env;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::fs;
use std::io;
use std::mem;
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

#[derive(Debug, Clone, Copy)]
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct Elf64_Shdr {
    sh_name: u32 ,		/* Section name, index in string tbl */
    sh_type: u32,		/* Type of section */
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

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Nb args {} != 2", args.len());
        return
    }

    let file = &args[1];

    println!("Analysing {}", file);

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
    //println!("{:?}", phdr_b);
    for i in (0..e_phentsize*e_phnum).step_by(e_phentsize) {
        let (head, body, _tail) = unsafe { &phdr_b[i..i+e_phentsize].align_to::<Elf64_Phdr>() };
        assert!(head.is_empty(), "Data was not aligned");
        let phdr = &body[0];
        println!("Header {:x} {:?}",i , phdr);
    }

    // Section header table
    let e_shoff = hdr.e_shoff as u64;
    let e_shentsize = hdr.e_shentsize as usize;
    let e_shnum = hdr.e_shnum as usize;
    let phdr_b = read_file_offset_size(file, e_shoff, e_shentsize*e_shnum).expect("Error while reading shdr");
    //println!("{:?}", phdr_b);
    for i in (0..e_shentsize*e_shnum).step_by(e_shentsize) {
        let (head, body, _tail) = unsafe { &phdr_b[i..i+e_shentsize].align_to::<Elf64_Shdr>() };
        assert!(head.is_empty(), "Data was not aligned");
        let phdr = &body[0];
        println!("Header {:?}" , phdr);
    }
}
