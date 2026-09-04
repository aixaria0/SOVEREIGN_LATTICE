use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const WAL_ENTRY_HEADER_SIZE: usize = 25; // 8 (view) + 8 (seq) + 1 (phase) + 4 (sender) + 4 (payload_len)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalRecord {
    pub view: u64,
    pub seq: u64,
    pub phase: u8,
    pub sender_id: u32,
    pub digest: [u8; 32],
    pub payload: Vec<u8>,
}

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
        signature_bytes: &[u8],
    ) -> io::Result<()> {
        let mut buffer = Vec::with_capacity(WAL_ENTRY_HEADER_SIZE + 32 + signature_bytes.len());
        buffer.extend_from_slice(&view.to_be_bytes());
        buffer.extend_from_slice(&seq.to_be_bytes());
        buffer.push(phase);
        buffer.extend_from_slice(&sender_id.to_be_bytes());
        buffer.extend_from_slice(&(signature_bytes.len() as u32).to_be_bytes());
        buffer.extend_from_slice(digest);
        buffer.extend_from_slice(signature_bytes);

        self.file.seek(SeekFrom::End(0))?;
        self.file.write_all(&buffer)?;
        self.file.flush()?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn replay_records<F>(&mut self, mut on_record: F) -> io::Result<usize>
    where
        F: FnMut(WalRecord),
    {
        self.file.seek(SeekFrom::Start(0))?;
        let mut count = 0;

        loop {
            let mut header = [0u8; WAL_ENTRY_HEADER_SIZE];
            match self.file.read_exact(&mut header) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            let view = u64::from_be_bytes(header[0..8].try_into().unwrap());
            let seq = u64::from_be_bytes(header[8..16].try_into().unwrap());
            let phase = header[16];
            let sender_id = u32::from_be_bytes(header[17..21].try_into().unwrap());
            let payload_len = u32::from_be_bytes(header[21..25].try_into().unwrap()) as usize;

            let mut digest = [0u8; 32];
            self.file.read_exact(&mut digest)?;

            let mut payload = vec![0u8; payload_len];
            self.file.read_exact(&mut payload)?;

            on_record(WalRecord {
                view,
                seq,
                phase,
                sender_id,
                digest,
                payload,
            });
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

