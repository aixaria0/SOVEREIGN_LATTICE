use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use bls12_381::{G1Affine, G1Projective};
use group::Curve;

pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    pub fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }

    pub fn append_entry(
        &mut self,
        view: u64,
        seq_or_packed: u64,
        phase: u8,
        sender_id: u32,
        digest: &[u8; 32],
        signature: &G1Projective,
    ) -> io::Result<()> {
        let mut record = Vec::with_capacity(1 + 8 + 8 + 4 + 32 + 48);
        record.push(phase);
        record.extend_from_slice(&view.to_be_bytes());
        record.extend_from_slice(&seq_or_packed.to_be_bytes());
        record.extend_from_slice(&sender_id.to_be_bytes());
        record.extend_from_slice(digest);
        record.extend_from_slice(&signature.to_affine().to_compressed());

        let len = record.len() as u32;
        self.file.write_all(&len.to_be_bytes())?;
        self.file.write_all(&record)?;
        self.file.flush()?;
        Ok(())
    }

    pub fn replay_log<F>(&mut self, mut callback: F) -> Result<(), &'static str>
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective),
    {
        self.file.seek(SeekFrom::Start(0)).map_err(|_| "WAL_SEEK_FAILED")?;
        let mut buffer = Vec::new();
        self.file.read_to_end(&mut buffer).map_err(|_| "WAL_READ_FAILED")?;

        let mut cursor = 0;
        while cursor < buffer.len() {
            if cursor + 4 > buffer.len() {
                return Err("WAL_CORRUPTION_FATAL: Truncated frame length header.");
            }
            let mut len_bytes = [0u8; 4];
            len_bytes.copy_from_slice(&buffer[cursor..cursor + 4]);
            let record_len = u32::from_be_bytes(len_bytes) as usize;
            cursor += 4;

            if cursor + record_len > buffer.len() {
                return Err("WAL_CORRUPTION_FATAL: Truncated record payload.");
            }

            let record = &buffer[cursor..cursor + record_len];
            cursor += record_len;

            if record.len() < 1 + 8 + 8 + 4 + 32 + 48 {
                return Err("WAL_CORRUPTION_FATAL: Invalid record size.");
            }

            let phase = record[0];
            let mut view_bytes = [0u8; 8];
            view_bytes.copy_from_slice(&record[1..9]);
            let view = u64::from_be_bytes(view_bytes);

            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&record[9..17]);
            let seq_or_packed = u64::from_be_bytes(seq_bytes);

            let mut sender_bytes = [0u8; 4];
            sender_bytes.copy_from_slice(&record[17..21]);
            let sender_id = u32::from_be_bytes(sender_bytes);

            let mut digest = [0u8; 32];
            digest.copy_from_slice(&record[21..53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&record[53..101]);

            let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
            let signature = match affine_opt {
                Some(affine) => G1Projective::from(affine),
                None => {
                    return Err("WAL_CORRUPTION_FATAL: Encountered malformed or tampered cryptographic signature bytes in log record!");
                }
            };

            callback(view, seq_or_packed, phase, sender_id, digest, signature);
        }

        Ok(())
    }
}
