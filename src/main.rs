use disasm::disassemble;
use read::*;
use std::{fs::File, io::Result};

mod disasm;
mod read;

#[derive(Debug, Clone, PartialEq)]
enum SegmentKind {
    Unknown,
    Linked,
    HostSegment,
    SegmentProcedure,
    UnitSegment,
    SeparateProcedureSegment,
    UnlinkedIntrinsicUnit,
    LinkedIntrinsicUnit,
    DataSegment,
}

#[derive(Debug, Clone, PartialEq)]
enum MachineType {
    Unknown,
    PCodeAppleII, // LSB
    Native6502,
}

#[derive(Debug, Clone)]
struct SegmentInfo {
    code_addr: u16,
    code_len: u16,
    name: String,
    kind: SegmentKind,
    text_addr: u16,
    num: u8,
    machine_type: MachineType,
    version: u8,
}

impl Default for SegmentInfo {
    fn default() -> Self {
        Self {
            code_addr: 0,
            code_len: 0,
            name: String::new(),
            kind: SegmentKind::Linked,
            text_addr: 0,
            num: 0,
            machine_type: MachineType::Unknown,
            version: 0,
        }
    }
}

fn parse_segment_kind(value: u16) -> SegmentKind {
    match value {
        0 => SegmentKind::Linked,
        1 => SegmentKind::HostSegment,
        2 => SegmentKind::SegmentProcedure,
        3 => SegmentKind::UnitSegment,
        4 => SegmentKind::SeparateProcedureSegment,
        5 => SegmentKind::UnlinkedIntrinsicUnit,
        6 => SegmentKind::LinkedIntrinsicUnit,
        7 => SegmentKind::DataSegment,
        _ => SegmentKind::Unknown,
    }
}

fn parse_machine_type(value: u8) -> MachineType {
    match value {
        2 => MachineType::PCodeAppleII,
        7 => MachineType::Native6502,
        _ => MachineType::Unknown,
    }
}

fn parse_segment_dictionary(mut codefile: &[u8]) -> Result<Vec<SegmentInfo>> {
    let mut vec: [SegmentInfo; 16] = core::array::from_fn(|_| SegmentInfo::default());
    for e in &mut vec {
        e.code_addr = codefile.read_u16_le()?;
        e.code_len = codefile.read_u16_le()?;
    }
    for e in &mut vec {
        e.name = codefile.read_string(8)?;
    }
    for e in &mut vec {
        e.kind = parse_segment_kind(codefile.read_u16_le()?);
    }
    for e in &mut vec {
        e.text_addr = codefile.read_u16_le()?;
    }
    for e in &mut vec {
        e.num = codefile.read_u8()?;
        let info = codefile.read_u8()?;
        e.machine_type = parse_machine_type(info & 15);
        e.version = info >> 5;
    }
    Ok(vec.into_iter().filter(|seg| seg.code_addr > 0).collect())
}

fn dump_p_code_procedure(segment: &[u8], info: &SegmentInfo, jtab: usize) -> Result<()> {
    let attr_end = jtab + 2;
    let attr_start = attr_end - 10;
    let mut attr_table = &segment[attr_start..attr_end];

    let data_size = attr_table.read_u16_le()?;
    let param_size = attr_table.read_u16_le()?;
    let exit_ic = attr_table.read_u16_le()?;
    let enter_ic = attr_table.read_u16_le()?;
    let proc_num = attr_table.read_u8()?;
    let lex = attr_table.read_u8()?;

    let enter_addr = attr_end - 4 - enter_ic as usize;
    let exit_addr = attr_end - 6 - exit_ic as usize;

    println!("; Procedure {}_{}", info.name, proc_num);
    println!(";   Type: Pascal P-Code");
    println!(";   Lexical Level: {}", lex);
    println!(";   Data Size: {} bytes", data_size);
    println!(";   Param Size: {} bytes", param_size);
    println!(";   Enter At: {:04x}h", enter_addr);
    println!(";   Exit At: {:04x}h", exit_addr);
    println!();

    disassemble(segment, enter_addr, exit_addr, jtab);
    println!();

    Ok(())
}

fn dump_6502_procedure(
    segment: &[u8],
    info: &SegmentInfo,
    proc_num: usize,
    jtab: usize,
) -> Result<()> {
    let attr_end = jtab + 2;
    let mut attr_table = &segment[..attr_end];

    let relocseg_num = attr_table.read_down_u8()?;
    let _ = attr_table.read_down_u8()?;
    let enter_ic = attr_table.read_down_u16_le()?;

    let base_reloc_table_len = attr_table.read_down_u16_le()? as usize;
    let mut base_reloc_table = vec![0u16; base_reloc_table_len];
    attr_table.read_down_u16_le_into(&mut base_reloc_table)?;

    let seg_reloc_table_len = attr_table.read_down_u16_le()? as usize;
    let mut seg_reloc_table = vec![0u16; seg_reloc_table_len];
    attr_table.read_down_u16_le_into(&mut seg_reloc_table)?;

    let proc_reloc_table_len = attr_table.read_down_u16_le()? as usize;
    let mut proc_reloc_table = vec![0u16; proc_reloc_table_len];
    attr_table.read_down_u16_le_into(&mut proc_reloc_table)?;

    let interpreter_reloc_table_len = attr_table.read_down_u16_le()? as usize;
    let mut interpreter_reloc_table = vec![0u16; interpreter_reloc_table_len];
    attr_table.read_down_u16_le_into(&mut interpreter_reloc_table)?;

    let attr_start = attr_table.len();
    let enter_addr = attr_end - 4 - enter_ic as usize;

    println!("; Procedure {}_{}", info.name, proc_num);
    println!(";   Type: 6502");
    println!(";   RelocSeg Number: {}", relocseg_num);
    println!(
        ";   Base-Relative Relocation Table Size: {} pointers",
        base_reloc_table_len
    );
    println!(
        ";   Segment-Relative Relocation Table Size: {} pointers",
        seg_reloc_table_len
    );
    println!(
        ";   Procedure-Relative Relocation Table Size: {} pointers",
        proc_reloc_table_len
    );
    println!(
        ";   Interpreter-Relative Relocation Table Size: {} pointers",
        interpreter_reloc_table_len
    );
    println!(";   Enter At: {:04x}h", enter_addr);
    println!(";   Code Size: {} bytes", attr_start - enter_addr);
    println!();

    println!(";   Note: disassembling 6502 isn't supported");
    println!();
    Ok(())
}

fn dump_segment(codefile: &[u8], info: &SegmentInfo) -> Result<()> {
    println!("; Code Segment \"{}\" (Num: {})", info.name, info.num);
    println!(
        ";   Code Addr: {} ({:x}h)",
        info.code_addr,
        (info.code_addr as usize) * 512
    );
    println!(";   Code Len: {} bytes", info.code_len);
    println!(";   Segment Kind: {:?}", info.kind);
    println!(";   Machine Type: {:?}", info.machine_type);
    println!(";   Version: {}", info.version);

    if info.kind == SegmentKind::Linked && info.machine_type != MachineType::Unknown {
        let start: usize = (info.code_addr as usize) * 512;
        let len: usize = info.code_len.into();
        let segment = &codefile[start..(start + len)];

        let proc_count = segment[segment.len() - 1] as usize;

        println!(";   Number of Procedures: {}", proc_count);
        println!();

        for i in 1..proc_count + 1 {
            let pointer_position = segment.len() - 2 - i * 2;
            let pointer = segment.read_word_at(pointer_position)?;

            let jtab = pointer_position - (pointer as usize);

            if segment[jtab] == 0 {
                dump_6502_procedure(segment, info, i, jtab)?;
            } else {
                dump_p_code_procedure(segment, info, jtab)?;
            }
        }
    } else {
        println!();
    }

    Ok(())
}

fn main() {
    let mut f = File::open("test_data/STARTUP.CODE").unwrap();
    let mut codefile = Vec::new();
    f.read_to_end(&mut codefile).unwrap();

    let dict = parse_segment_dictionary(&codefile).unwrap();
    for info in &dict {
        dump_segment(&codefile, info).unwrap();
    }
}
