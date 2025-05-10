use byteorder::{LittleEndian, ReadBytesExt};
use std::{
    fs::File,
    io::{Error, ErrorKind, Read}
};

#[derive(Debug, Clone, PartialEq)]
enum SegmentKind {
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

fn parse_segment_kind(value: u16) -> std::io::Result<SegmentKind> {
    match value {
        0 => Ok(SegmentKind::Linked),
        1 => Ok(SegmentKind::HostSegment),
        2 => Ok(SegmentKind::SegmentProcedure),
        3 => Ok(SegmentKind::UnitSegment),
        4 => Ok(SegmentKind::SeparateProcedureSegment),
        5 => Ok(SegmentKind::UnlinkedIntrinsicUnit),
        6 => Ok(SegmentKind::LinkedIntrinsicUnit),
        7 => Ok(SegmentKind::DataSegment),
        _ => Err(Error::from(ErrorKind::InvalidData)),
    }
}

fn parse_machine_type(value: u8) -> std::io::Result<MachineType> {
    Ok(match value {
        2 => MachineType::PCodeAppleII,
        7 => MachineType::Native6502,
        _ => MachineType::Unknown,
    })
}

fn read_string(read: &mut impl Read, len: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; len];
    read.read_exact(&mut buf)?;
    Ok(std::str::from_utf8(&buf)
        .or(Err(Error::from(ErrorKind::InvalidData)))?
        .trim_ascii()
        .to_string())
}

fn parse_segment_dictionary(mut codefile: &[u8]) -> std::io::Result<Vec<SegmentInfo>> {
    let mut vec: [SegmentInfo; 16] = core::array::from_fn(|_| SegmentInfo::default());
    for e in &mut vec {
        e.code_addr = codefile.read_u16::<LittleEndian>()?;
        e.code_len = codefile.read_u16::<LittleEndian>()?;
    }
    for e in &mut vec {
        e.name = read_string(&mut codefile, 8)?;
    }
    for e in &mut vec {
        e.kind = parse_segment_kind(codefile.read_u16::<LittleEndian>()?)?;
    }
    for e in &mut vec {
        e.text_addr = codefile.read_u16::<LittleEndian>()?;
    }
    for e in &mut vec {
        e.num = codefile.read_u8()?;
        let info = codefile.read_u8()?;
        e.machine_type = parse_machine_type(info & 15)?;
        e.version = info >> 5;
    }
    Ok(vec.into_iter().filter(|seg| seg.code_addr > 0).collect())
}

struct PCodeReader<'a> {
    segment: &'a [u8],
    cursor: usize,
    jtab: usize,
}

impl<'a> PCodeReader<'a> {
    fn new(segment: &'a [u8], enter: usize, jtab: usize) -> Self {
        Self {
            segment,
            cursor: enter,
            jtab,
        }
    }

    fn align_to_word(&mut self) {
        if self.cursor & 1 != 0 {
            self.cursor += 1;
        }
    }

    fn read_jump_table(&self, sb: i8) -> usize {
        let i = self.jtab.checked_add_signed(sb.into()).unwrap();
        i - (&self.segment[i..]).read_u16::<LittleEndian>().unwrap() as usize
    }
}

impl Read for PCodeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = (&self.segment[self.cursor..]).read(buf);
        if let Ok(n) = ret {
            self.cursor += n;
        }
        ret
    }
}

fn parse_param_w(code: &mut PCodeReader) -> std::io::Result<i16> {
    code.read_i16::<LittleEndian>()
}

fn parse_param_b(code: &mut PCodeReader) -> std::io::Result<u16> {
    let v = code.read_u8()? as u16;
    Ok(if v & 128 != 0 {
        (v & 127) | code.read_u8()? as u16
    } else {
        v
    })
}

fn parse_param_db(code: &mut PCodeReader) -> std::io::Result<u8> {
    code.read_u8()
}

fn parse_param_ub(code: &mut PCodeReader) -> std::io::Result<u8> {
    code.read_u8()
}

fn parse_param_sb(code: &mut PCodeReader) -> std::io::Result<i8> {
    code.read_i8()
}

fn parse_ldc_params(code: &mut PCodeReader) -> std::io::Result<String> {
    let n = parse_param_ub(code)?;
    Ok(if n > 0 {
        code.align_to_word();

        let mut data = vec![0u16; n.into()];
        code.read_u16_into::<LittleEndian>(&mut data)?;

        let data = data
            .iter()
            .map(|w| format!("{:04x}h", w))
            .collect::<Vec<String>>()
            .join(", ");

        format!("{}, {}", n, data)
    } else {
        "0".to_string()
    })
}

fn parse_lsa_params(code: &mut PCodeReader) -> std::io::Result<String> {
    let n = parse_param_ub(code)?;
    Ok(if n > 0 {
        format!("{}, `{}`", n, read_string(code, n.into())?)
    } else {
        "0".to_string()
    })
}

fn parse_lpa_params(code: &mut PCodeReader) -> std::io::Result<String> {
    let n = parse_param_ub(code)?;
    Ok(if n > 0 {
        let mut data = vec![0u8; n.into()];
        code.read_exact(&mut data)?;

        let data = data
            .iter()
            .map(|w| format!("{:04x}h", w))
            .collect::<Vec<String>>()
            .join(" ");

        format!("{}, {}", n, data)
    } else {
        "0".to_string()
    })
}

fn parse_xjp_params(code: &mut PCodeReader) -> std::io::Result<String> {
    code.align_to_word();
    let w1 = parse_param_w(code)?;
    let w2 = parse_param_w(code)?;

    let mut cases = vec![0i16; (w2 - w1 + 1) as usize * 2];
    code.read_i16_into::<LittleEndian>(&mut cases)?;

    let w3 = parse_param_w(code)?;

    let cases = cases
        .iter()
        .map(|w| format!("{:04x}h", w))
        .collect::<Vec<String>>()
        .join(", ");

    Ok(format!("{}, {}, {}, {:x}h", w1, w2, cases, w3))
}

fn parse_jump_param(code: &mut PCodeReader, ipc: usize) -> std::io::Result<String> {
    Ok(match parse_param_sb(code)? {
        0 => "0 ; NOP".to_string(),
        off if off < 0 => format!(
            "{:x}h ; {:04x} (thru jump table)",
            off,
            code.read_jump_table(off)
        ),
        off => format!("{:x}h ; {:04x}", off, ipc + off as usize),
    })
}

fn dump_instruction(code: &mut PCodeReader) -> std::io::Result<()> {
    let pos = code.cursor;
    match code.read_u8()? {
        159 => println!("LDCN"),
        199 => println!("LDCI {}", parse_param_w(code)?),
        202 => println!("LDL {}", parse_param_b(code)?),
        198 => println!("LLA {}", parse_param_b(code)?),
        204 => println!("STL {}", parse_param_b(code)?),
        169 => println!("LDO {}", parse_param_b(code)?),
        165 => println!("LAO {}", parse_param_b(code)?),
        171 => println!("SRO {}", parse_param_b(code)?),
        182 => println!("LOD {}, {}", parse_param_db(code)?, parse_param_b(code)?),
        178 => println!("LDA {}, {}", parse_param_db(code)?, parse_param_b(code)?),
        184 => println!("STR {}, {}", parse_param_db(code)?, parse_param_b(code)?),
        163 => println!("IND {}", parse_param_b(code)?),
        154 => println!("STO"),
        157 => println!("LDE {}, {}", parse_param_ub(code)?, parse_param_b(code)?),
        167 => println!("LAE {}, {}", parse_param_ub(code)?, parse_param_b(code)?),
        209 => println!("STR {}, {}", parse_param_ub(code)?, parse_param_b(code)?),
        179 => println!("LDC {}", parse_ldc_params(code)?),
        188 => println!("LDM {}", parse_param_ub(code)?),
        189 => println!("STM {}", parse_param_ub(code)?),
        190 => println!("LDB"),
        191 => println!("STB"),
        166 => println!("LSA {}", parse_lsa_params(code)?),
        170 => println!("SAS {}", parse_param_ub(code)?),
        155 => println!("IXS"),
        168 => println!("MOV {}", parse_param_b(code)?),
        162 => println!("INC {}", parse_param_b(code)?),
        164 => println!("IXA {}", parse_param_b(code)?),
        192 => println!("IXP {}, {}", parse_param_ub(code)?, parse_param_ub(code)?),
        208 => println!("LPA {}", parse_lpa_params(code)?),
        186 => println!("LDP"),
        187 => println!("STP"),
        128 => println!("ABI"),
        130 => println!("ADI"),
        145 => println!("NGI"),
        149 => println!("SBI"),
        143 => println!("MPI"),
        152 => println!("SQI"),
        134 => println!("DVI"),
        142 => println!("MODI"),
        136 => println!("CHK"),
        195 => println!("EQUI"),
        203 => println!("NEQI"),
        200 => println!("LEQI"),
        201 => println!("LESI"),
        196 => println!("GEQI"),
        197 => println!("GRTI"),
        175 => match code.read_u8()? {
            2 => println!("EQUREAL"),
            4 => println!("EQUSTR"),
            6 => println!("EQUBOOL"),
            8 => println!("EQUPOWR"),
            10 => println!("EQUBYT {}", parse_param_b(code)?),
            12 => println!("EQUWORD {}", parse_param_b(code)?),
            x => panic!("Unknown flavor of EQU: {}", x),
        },
        183 => match code.read_u8()? {
            2 => println!("NEQREAL"),
            4 => println!("NEQSTR"),
            6 => println!("NEQBOOL"),
            8 => println!("NEQPOWR"),
            10 => println!("NEQBYT {}", parse_param_b(code)?),
            12 => println!("NEQWORD {}", parse_param_b(code)?),
            x => panic!("Unknown flavor of NEQ: {}", x),
        },
        180 => match code.read_u8()? {
            2 => println!("LEQREAL"),
            4 => println!("LEQSTR"),
            6 => println!("LEQBOOL"),
            8 => println!("LEQPOWR"),
            10 => println!("LEQBYT {}", parse_param_b(code)?),
            x => panic!("Unknown flavor of LEQ: {}", x),
        },
        181 => match code.read_u8()? {
            2 => println!("LESREAL"),
            4 => println!("LESSTR"),
            6 => println!("LESBOOL"),
            10 => println!("LESBYT {}", parse_param_b(code)?),
            x => panic!("Unknown flavor of LES: {}", x),
        },
        176 => match code.read_u8()? {
            2 => println!("GEQREAL"),
            4 => println!("GEQSTR"),
            6 => println!("GEQBOOL"),
            8 => println!("GEQPOWR"),
            10 => println!("GEQBYT {}", parse_param_b(code)?),
            x => panic!("Unknown flavor of GEQ: {}", x),
        },
        177 => match code.read_u8()? {
            2 => println!("GRTREAL"),
            4 => println!("GRTSTR"),
            6 => println!("GRTBOOL"),
            10 => println!("GRTBYT {}", parse_param_b(code)?),
            x => panic!("Unknown flavor of GRT: {}", x),
        },
        138 => println!("FLT"),
        137 => println!("FLO"),
        129 => println!("ABR"),
        131 => println!("ADR"),
        146 => println!("NGR"),
        150 => println!("SBR"),
        144 => println!("MPR"),
        153 => println!("SQR"),
        135 => println!("DVR"),
        132 => println!("LAND"),
        141 => println!("LOR"),
        147 => println!("LNOT"),
        160 => println!("ADJ {}", parse_param_ub(code)?),
        151 => println!("SGS"),
        148 => println!("SRS"),
        139 => println!("INN"),
        156 => println!("UNI"),
        140 => println!("INT"),
        133 => println!("DIF"),
        214 => println!("XIT"),
        215 => println!("NOP"),
        213 => println!("BPT {}", parse_param_b(code)?),
        185 => println!("UJP {}", parse_jump_param(code, pos)?),
        161 => println!("FJP {}", parse_jump_param(code, pos)?),
        172 => println!("XJP {}", parse_xjp_params(code)?),
        206 => println!("CLP {}", parse_param_ub(code)?),
        207 => println!("CGP {}", parse_param_ub(code)?),
        174 => println!("CIP {}", parse_param_ub(code)?),
        194 => println!("CBP {}", parse_param_ub(code)?),
        205 => println!("CXP {}, {}", parse_param_ub(code)?, parse_param_ub(code)?),
        173 => println!("RNP {}", parse_param_db(code)?),
        193 => println!("RBP {}", parse_param_db(code)?),
        158 => match code.read_u8()? {
            1 => println!("NEW"),
            4 => println!("EXIT"),
            10 => println!("FLC"),
            11 => println!("SCN"),
            2 => println!("MVL"),
            3 => println!("MVR"),
            9 => println!("TIM"),
            31 => println!("MRK"),
            32 => println!("RLS"),
            22 => println!("TNC"),
            23 => println!("RND"),
            35 => println!("POT"),
            x => println!("CSP {}", x),
        },
        x @ 216..232 => println!("SLDL {}", x - 215),
        x @ 232..248 => println!("SLDO {}", x - 231),
        x @ 248..=255 => println!("SIND {}", x - 248),
        x @ 0..128 => println!("SLDC {}", x),
        x => panic!("Unknown opcode: {}", x),
    }
    Ok(())
}

fn dump_p_code(code: &mut PCodeReader, exit_at: usize) {
    while code.cursor <= exit_at {
        print!("{:04x}\t", code.cursor);
        dump_instruction(code).unwrap()
    }
}

fn dump_segment(codefile: &[u8], info: &SegmentInfo) -> std::io::Result<()> {
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

    if info.machine_type != MachineType::PCodeAppleII || info.kind != SegmentKind::Linked {
        println!();
        return Ok(());
    }

    let start: usize = (info.code_addr as usize) * 512;
    let len: usize = info.code_len.into();
    let block = &codefile[start..(start + len)];

    let proc_count = block[len - 1] as usize;
    // TODO: let segment_num = block[len - 2];

    println!(";   Number of Procedures: {}", proc_count);
    println!();

    for i in 1..proc_count + 1 {
        let pointer_position = len - 2 - i * 2;
        let pointer = (&block[pointer_position..]).read_u16::<LittleEndian>()?;

        let jtab = pointer_position - (pointer as usize);
        let footer_end = jtab + 2;
        let footer_start = footer_end - 10;
        let mut footer = &block[footer_start..footer_end];

        let data_size = footer.read_u16::<LittleEndian>()?;
        let param_size = footer.read_u16::<LittleEndian>()?;
        let exit_ic = footer.read_u16::<LittleEndian>()?;
        let enter_ic = footer.read_u16::<LittleEndian>()?;
        let proc_num = footer.read_u8()?;
        let lex = footer.read_u8()?;

        let enter_addr = footer_end - 4 - enter_ic as usize;
        let exit_addr = footer_end - 6 - exit_ic as usize;

        println!("; Procedure {}_{}", info.name, proc_num);
        println!(";   Lexical Level: {}", lex);
        println!(";   Data Size: {} bytes", data_size);
        println!(";   Param Size: {} bytes", param_size);
        println!(";   Enter At: {:04x}h", enter_addr);
        println!(";   Exit At: {:04x}h", exit_addr);
        println!();

        let mut reader = PCodeReader::new(block, enter_addr, jtab);
        dump_p_code(&mut reader, exit_addr);
        println!();

        if reader.cursor < footer_start {
            println!("; Jump table for {}_{}", info.name, proc_num);
            println!();

            while reader.cursor < footer_start {
                let pos = reader.cursor;
                let offset = reader.read_i16::<LittleEndian>()?;
                println!("{:04x}\t{:04x}h", pos, offset);
            }

            println!();
        }
    }

    Ok(())
}

fn main() {
    let mut f = File::open("test_data/TEST.CODE").unwrap();
    let mut codefile = Vec::new();
    f.read_to_end(&mut codefile).unwrap();

    let segment_info = parse_segment_dictionary(&codefile).unwrap();

    for info in &segment_info {
        dump_segment(&codefile, info).unwrap();
    }
}
