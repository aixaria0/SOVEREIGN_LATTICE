use std::fs::{OpenOptions, File};
use std::io::{Write, Read, Seek, SeekFrom};
use std::path::Path;
use bls12_381::G1Projective;
use group::Curve;

pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }

    pub fn append_entry(&mut self, view: u64, seq: u64, phase_u8: u8, sender_id: u32, digest: &[u8; 32], signature: &G1Projective) -> std::io::Result<()> {
        self.file.write_all(&view.to_be_bytes())?;
        self.file.write_all(&seq.to_be_bytes())?;
        self.file.write_all(&[phase_u8])?;
        self.file.write_all(&sender_id.to_be_bytes())?;
        self.file.write_all(digest)?;
        
        let affine = signature.to_affine();
        let sig_bytes = affine.to_compressed();
        self.file.write_all(&sig_bytes)?;
        
        self.file.flush()?;
        Ok(())
    }

    pub fn replay_log<F>(&mut self, mut callback: F) -> std::io::Result<()> 
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective)
    {
        self.file.seek(SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf)?;

        let mut cursor = 0;
        while cursor + 101 <= buf.len() {
            let view = u64::from_be_bytes(buf[cursor..cursor+8].try_into().unwrap());
            let seq = u64::from_be_bytes(buf[cursor+8..cursor+16].try_into().unwrap());
            let phase_u8 = buf[cursor+16];
            let sender_id = u32::from_be_bytes(buf[cursor+17..cursor+21].try_into().unwrap());
            
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&buf[cursor+21..cursor+53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&buf[cursor+53..cursor+101]);
            
            let signature = bls12_381::G1Affine::from_compressed(&sig_bytes)
                .map(G1Projective::from)
                .unwrap_or_else(G1Projective::identity);

            callback(view, seq, phase_u8, sender_id, digest, signature);
            cursor += 101;
        }
        Ok(())
    }
}
