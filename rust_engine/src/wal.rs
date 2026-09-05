use bls12_381::{G1Affine, G1Projective};
use group::Curve;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const ENTRY_SIZE: usize = 8 + 8 + 1 + 4 + 32 + 48; // 101 bytes

pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
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
    ) -> Result<(), std::io::Error> {
        self.file.seek(SeekFrom::End(0))?;

        let mut record = Vec::with_capacity(ENTRY_SIZE);
        record.extend_from_slice(&view.to_be_bytes());
        record.extend_from_slice(&seq.to_be_bytes());
        record.push(phase);
        record.extend_from_slice(&sender_id.to_be_bytes());
        record.extend_from_slice(digest);
        record.extend_from_slice(&signature.to_affine().to_compressed());

        self.file.write_all(&record)?;
        self.file.flush()?;
        self.file.sync_data()?;

        Ok(())
    }

    pub fn replay_log<F>(&mut self, mut callback: F) -> Result<usize, std::io::Error>
    where
        F: FnMut(u64, u64, u8, u32, [u8; 32], G1Projective),
    {
        self.file.seek(SeekFrom::Start(0))?;

        let mut buffer = Vec::new();
        self.file.read_to_end(&mut buffer)?;

        let mut offset = 0;
        let mut count = 0;

        while offset + ENTRY_SIZE <= buffer.len() {
            let chunk = &buffer[offset..offset + ENTRY_SIZE];

            let mut view_bytes = [0u8; 8];
            view_bytes.copy_from_slice(&chunk[0..8]);
            let view = u64::from_be_bytes(view_bytes);

            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&chunk[8..16]);
            let seq = u64::from_be_bytes(seq_bytes);

            let phase = chunk[16];

            let mut sender_bytes = [0u8; 4];
            sender_bytes.copy_from_slice(&chunk[17..21]);
            let sender_id = u32::from_be_bytes(sender_bytes);

            let mut digest = [0u8; 32];
            digest.copy_from_slice(&chunk[21..53]);

            let mut sig_bytes = [0u8; 48];
            sig_bytes.copy_from_slice(&chunk[53..101]);

            let affine_opt: Option<G1Affine> = G1Affine::from_compressed(&sig_bytes).into();
            if let Some(affine) = affine_opt {
                let signature = G1Projective::from(affine);
                callback(view, seq, phase, sender_id, digest, signature);
                count += 1;
            } else {
                break;
            }

            offset += ENTRY_SIZE;
        }

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use rand::rngs::OsRng;
    use std::fs;

    #[test]
    fn test_wal_append_sync_and_replay() {
        let test_path = "test_durability_wal.log";
        let _ = fs::remove_file(test_path);

        let mut wal = WriteAheadLog::open(test_path).expect("Failed to open test WAL");

        let sk = bls12_381::Scalar::random(&mut OsRng);
        let sig = G1Projective::generator() * sk;
        let digest = [0x42; 32];

        wal.append_entry(1, 10, 2, 3, &digest, &sig)
            .expect("Failed to append entry with sync");

        let mut replayed = 0;
        let count = wal
            .replay_log(|v, s, p, id, d, _| {
                assert_eq!(v, 1);
                assert_eq!(s, 10);
                assert_eq!(p, 2);
                assert_eq!(id, 3);
                assert_eq!(d, [0x42; 32]);
                replayed += 1;
            })
            .expect("Failed to replay log");

        assert_eq!(count, 1);
        assert_eq!(replayed, 1);

        let _ = fs::remove_file(test_path);
    }
}
