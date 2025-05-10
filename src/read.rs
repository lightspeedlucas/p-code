// Helper methods for binary deserialization

use byteorder::LittleEndian;
pub use byteorder::ReadBytesExt;
pub use std::io::Read;
use std::io::{Error, ErrorKind, Result};

pub trait CrateReadExt: Read {
    fn read_string(&mut self, len: usize) -> Result<String> {
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        Ok(std::str::from_utf8(&buf)
            .or(Err(Error::from(ErrorKind::InvalidData)))?
            .trim_ascii()
            .to_string())
    }

    fn read_u16_le(&mut self) -> Result<u16> {
        self.read_u16::<LittleEndian>()
    }

    fn read_i16_le(&mut self) -> Result<i16> {
        self.read_i16::<LittleEndian>()
    }

    fn read_u16_le_into(&mut self, buf: &mut [u16]) -> Result<()> {
        self.read_u16_into::<LittleEndian>(buf)
    }

    fn read_i16_le_into(&mut self, buf: &mut [i16]) -> Result<()> {
        self.read_i16_into::<LittleEndian>(buf)
    }
}

impl<T: Read> CrateReadExt for T {}

pub trait CrateSliceExt {
    fn read_word_at(&self, pos: usize) -> Result<u16>;
    fn read_down_u8(&mut self) -> Result<u8>;
    fn read_down_u16_le(&mut self) -> Result<u16>;
    fn read_down_u16_le_into(&mut self, buf: &mut [u16]) -> Result<()>;
}

impl CrateSliceExt for &[u8] {
    fn read_word_at(&self, pos: usize) -> Result<u16> {
        (&self[pos..]).read_u16::<LittleEndian>()
    }

    fn read_down_u8(&mut self) -> Result<u8> {
        let n = std::cmp::min(self.len(), 1);
        let value = (&self[self.len() - n..]).read_u8()?;
        *self = &self[..self.len() - n];
        Ok(value)
    }

    fn read_down_u16_le(&mut self) -> Result<u16> {
        let n = std::cmp::min(self.len(), 2);
        let value = (&self[self.len() - n..]).read_u16_le()?;
        *self = &self[..self.len() - n];
        Ok(value)
    }

    fn read_down_u16_le_into(&mut self, buf: &mut [u16]) -> Result<()> {
        let n = std::cmp::min(self.len(), buf.len() * 2);
        (&self[self.len() - n..]).read_u16_le_into(buf)?;
        *self = &self[..self.len() - n];
        Ok(())
    }
}
