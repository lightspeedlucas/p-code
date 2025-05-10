// Handles disassembly of Apple II Pascal P-Code

use crate::read::*;
use std::io::Result;

struct Reader<'a> {
    segment: &'a [u8],
    cursor: usize,
    jtab: usize,
}

impl<'a> Reader<'a> {
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
        i - (&self.segment[i..]).read_u16_le().unwrap() as usize
    }
}

impl Read for Reader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let ret = (&self.segment[self.cursor..]).read(buf);
        if let Ok(n) = ret {
            self.cursor += n;
        }
        ret
    }
}

// Word
fn do_w(code: &mut Reader) -> Result<i16> {
    code.read_i16_le()
}

// Big: one or two-byte sized word
fn do_b(code: &mut Reader) -> Result<u16> {
    let v = code.read_u8()? as u16;
    Ok(if v & 128 != 0 {
        (v & 127) | code.read_u8()? as u16
    } else {
        v
    })
}

// Don't Care Byte
fn do_db(code: &mut Reader) -> Result<u8> {
    code.read_u8()
}

// Unsigned Byte
fn do_ub(code: &mut Reader) -> Result<u8> {
    code.read_u8()
}

// Signed Byte
fn do_sb(code: &mut Reader) -> Result<i8> {
    code.read_i8()
}

fn do_ldc_args(code: &mut Reader) -> Result<String> {
    let n = do_ub(code)?;
    Ok(if n > 0 {
        code.align_to_word();

        let mut data = vec![0u16; n.into()];
        code.read_u16_le_into(&mut data)?;

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

fn do_lsa_args(code: &mut Reader) -> Result<String> {
    let n = do_ub(code)?;
    Ok(if n > 0 {
        format!("{}, `{}`", n, code.read_string(n.into())?)
    } else {
        "0".to_string()
    })
}

fn do_lpa_args(code: &mut Reader) -> Result<String> {
    let n = do_ub(code)?;
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

fn do_xjp_args(code: &mut Reader) -> Result<String> {
    code.align_to_word();
    let w1 = do_w(code)?;
    let w2 = do_w(code)?;

    let mut cases = vec![0i16; (w2 - w1 + 1) as usize * 2];
    code.read_i16_le_into(&mut cases)?;

    let w3 = do_w(code)?;

    let cases = cases
        .iter()
        .map(|w| format!("{:x}h", w))
        .collect::<Vec<String>>()
        .join(", ");

    Ok(format!("{}, {}, {}, {:x}h", w1, w2, cases, w3))
}

fn do_jump_arg(code: &mut Reader, ipc: usize) -> Result<String> {
    Ok(match do_sb(code)? {
        0 => "0 ; NOP".to_string(),
        off if off < 0 => format!(
            "{:x}h ; {:04x} (thru jump table)",
            off,
            code.read_jump_table(off)
        ),
        off => format!("{:x}h ; {:04x}", off, ipc + off as usize),
    })
}

fn do_instruction(code: &mut Reader) -> Result<()> {
    let pos = code.cursor;
    match code.read_u8()? {
        159 => println!("LDCN"),
        199 => println!("LDCI {}", do_w(code)?),
        202 => println!("LDL {}", do_b(code)?),
        198 => println!("LLA {}", do_b(code)?),
        204 => println!("STL {}", do_b(code)?),
        169 => println!("LDO {}", do_b(code)?),
        165 => println!("LAO {}", do_b(code)?),
        171 => println!("SRO {}", do_b(code)?),
        182 => println!("LOD {}, {}", do_db(code)?, do_b(code)?),
        178 => println!("LDA {}, {}", do_db(code)?, do_b(code)?),
        184 => println!("STR {}, {}", do_db(code)?, do_b(code)?),
        163 => println!("IND {}", do_b(code)?),
        154 => println!("STO"),
        157 => println!("LDE {}, {}", do_ub(code)?, do_b(code)?),
        167 => println!("LAE {}, {}", do_ub(code)?, do_b(code)?),
        209 => println!("STR {}, {}", do_ub(code)?, do_b(code)?),
        179 => println!("LDC {}", do_ldc_args(code)?),
        188 => println!("LDM {}", do_ub(code)?),
        189 => println!("STM {}", do_ub(code)?),
        190 => println!("LDB"),
        191 => println!("STB"),
        166 => println!("LSA {}", do_lsa_args(code)?),
        170 => println!("SAS {}", do_ub(code)?),
        155 => println!("IXS"),
        168 => println!("MOV {}", do_b(code)?),
        162 => println!("INC {}", do_b(code)?),
        164 => println!("IXA {}", do_b(code)?),
        192 => println!("IXP {}, {}", do_ub(code)?, do_ub(code)?),
        208 => println!("LPA {}", do_lpa_args(code)?),
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
            10 => println!("EQUBYT {}", do_b(code)?),
            12 => println!("EQUWORD {}", do_b(code)?),
            x => panic!("Unknown flavor of EQU: {}", x),
        },
        183 => match code.read_u8()? {
            2 => println!("NEQREAL"),
            4 => println!("NEQSTR"),
            6 => println!("NEQBOOL"),
            8 => println!("NEQPOWR"),
            10 => println!("NEQBYT {}", do_b(code)?),
            12 => println!("NEQWORD {}", do_b(code)?),
            x => panic!("Unknown flavor of NEQ: {}", x),
        },
        180 => match code.read_u8()? {
            2 => println!("LEQREAL"),
            4 => println!("LEQSTR"),
            6 => println!("LEQBOOL"),
            8 => println!("LEQPOWR"),
            10 => println!("LEQBYT {}", do_b(code)?),
            x => panic!("Unknown flavor of LEQ: {}", x),
        },
        181 => match code.read_u8()? {
            2 => println!("LESREAL"),
            4 => println!("LESSTR"),
            6 => println!("LESBOOL"),
            10 => println!("LESBYT {}", do_b(code)?),
            x => panic!("Unknown flavor of LES: {}", x),
        },
        176 => match code.read_u8()? {
            2 => println!("GEQREAL"),
            4 => println!("GEQSTR"),
            6 => println!("GEQBOOL"),
            8 => println!("GEQPOWR"),
            10 => println!("GEQBYT {}", do_b(code)?),
            x => panic!("Unknown flavor of GEQ: {}", x),
        },
        177 => match code.read_u8()? {
            2 => println!("GRTREAL"),
            4 => println!("GRTSTR"),
            6 => println!("GRTBOOL"),
            10 => println!("GRTBYT {}", do_b(code)?),
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
        160 => println!("ADJ {}", do_ub(code)?),
        151 => println!("SGS"),
        148 => println!("SRS"),
        139 => println!("INN"),
        156 => println!("UNI"),
        140 => println!("INT"),
        133 => println!("DIF"),
        214 => println!("XIT"),
        215 => println!("NOP"),
        213 => println!("BPT {}", do_b(code)?),
        185 => println!("UJP {}", do_jump_arg(code, pos)?),
        161 => println!("FJP {}", do_jump_arg(code, pos)?),
        172 => println!("XJP {}", do_xjp_args(code)?),
        206 => println!("CLP {}", do_ub(code)?),
        207 => println!("CGP {}", do_ub(code)?),
        174 => println!("CIP {}", do_ub(code)?),
        194 => println!("CBP {}", do_ub(code)?),
        205 => println!("CXP {}, {}", do_ub(code)?, do_ub(code)?),
        173 => println!("RNP {}", do_db(code)?),
        193 => println!("RBP {}", do_db(code)?),
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

pub fn disassemble(segment: &[u8], enter_addr: usize, exit_addr: usize, jtab_addr: usize) {
    let mut reader = Reader::new(segment, enter_addr, jtab_addr);

    while reader.cursor <= exit_addr {
        print!("{:04x}\t", reader.cursor);
        do_instruction(&mut reader).unwrap()
    }
}
