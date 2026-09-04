use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use bls12_381::{G1Affine, G1Projective};

// Format per entry:
// 8 (view) + 8 (seq) + 1 (phase) + 4 (sender_id) + 32 (digest) + 48 (compressed G1 signature) = 101 bytes
pub const WAL_RECORD_SIZE: usize = 8 + 8 + 1 + 4 + 32 + 48;

pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        Ok(Self { file })
    }

    pub fn append_entry(
        &mut self,
        view: u64,
        seq: u64,
        phase: u8,
        sender_id: u32,
        digest: &[u8; 32],
        signature: &G1Projective,
    ) -> io::Result<()> {
        let affine = G1Affine::from(signature);
        let sig_bytes = affine.to_compressed();

        let mut buffer = Vec::with_capacity(WAL_RECORD_SIZE);
        buffer.extend_from_slice(&view.to_be_bytes());
        buffer.extend_from_slice(&seq.to_be_bytes());
        buffer.push(phase);
        buffer.extend_from_slice(&sender_id.to_be_bytes());
        buffer.extend_from_slice(digest);
        buffer.extend_from_slice(&sig_bytes);

        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&buffer)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn replay_log<F>(&mut self, mut on_record: F) -> io::Result<usize>
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective),
    {
        self.file.seek(SeekFrom::Start(0))?;
        let mut count = 0;

        loop {
            let mut record_buf = [0u8; WAL_RECORD_SIZE];
            match self.file.read_exact(&mut record_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            let view = u64::from_be_bytes(record_buf[0..8].try_into().unwrap());
            let seq = u64::from_be_bytes(record_buf[8..16].try_into().unwrap());
            let phase = record_buf[16];
            let sender_id = u32::from_be_bytes(record_buf[17..21].try_into().unwrap());

            let mut digest = [0u8; 32];
            digest.copy_from_slice(&record_buf[21..53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&record_buf[53..101]);

            let affine_opt = G1Affine::from_compressed(&sig_bytes);
            let signature = if bool::from(affine_opt.is_some()) {
                G1Projective::from(affine_opt.unwrap())
            } else {
                G1Projective::identity()
            };

            on_record(view, seq, phase, sender_id, digest, signature);
            count += 1;
        }

        Ok(count)
    }

    pub fn truncate_log(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.sync_all()
    }
}
