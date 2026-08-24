use alloc::sync::Arc;
use spin::Mutex;

use crate::vfs::VfsFile;

struct NicDevice {
    idx: usize,
}

impl NicDevice {
    pub fn new(idx: usize) -> Result<Self, ()> {
        if idx < crate::net::NICS.lock().len() {
            Ok(Self { idx })
        } else {
            Err(())
        }
    }
}

impl VfsFile for NicDevice {
    fn size(&mut self) -> usize {
        0
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut nics = crate::net::NICS.lock();
        let nic = &mut nics[self.idx];

        // reject buffers smaller than a largest ethernet frame
        if buf.len() < 1518 {
            0
        } else {
            if let Ok(frame) = nic.pop_frame() {
                buf[..frame.len()].copy_from_slice(&frame);
                frame.len()
            } else {
                nic.poll();
                if let Ok(frame) = nic.pop_frame() {
                    buf[..frame.len()].copy_from_slice(&frame);
                    frame.len()
                } else {
                    // call nic.poll() at most once per read() call
                    0
                }
            }
        }
    }

    fn write(&mut self, _buf: &[u8]) -> usize {
        0
    }

    fn seek(&mut self, _pos: crate::vfs::SeekFrom) -> usize {
        0
    }
}

pub(super) fn open(path: &str) -> Result<Arc<Mutex<dyn VfsFile>>, ()> {
    let Some(number) = path.strip_prefix("/nic") else {
        return Err(());
    };

    let Ok(idx) = number.parse() else {
        return Err(());
    };

    Ok(Arc::new(Mutex::new(NicDevice::new(idx)?)))
}
