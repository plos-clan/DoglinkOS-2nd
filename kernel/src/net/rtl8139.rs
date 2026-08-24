use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use x86_64::instructions::port::{PortReadOnly, PortWriteOnly};

use crate::{
    mm::{dma::DmaBuffer, page_alloc::PAGE_SIZE},
    net::Nic,
    pcie::enumrate::PCIConfigSpace,
    println,
};

struct Rtl8139 {
    io_base: u16,
    mac: [u8; 6],
    rx_buffer: DmaBuffer,
    cur_rx: u16,
}

impl Rtl8139 {
    pub fn new(config: &PCIConfigSpace) -> Self {
        // enable Bus Mastering
        let command = config.read_u16(4);
        unsafe { config.write_u16(4, command | (1 << 2)) }

        // BAR0 is I/O Space BAR
        let io_base = (config.bar[0] & !0b11) as u16;
        Self::from_io_base(io_base)
    }

    fn from_io_base(io_base: u16) -> Self {
        // read MAC address
        let mut mac = [0u8; 6];
        for (i, b) in mac.iter_mut().enumerate() {
            *b = unsafe { PortReadOnly::new(io_base + i as u16).read() };
        }

        // software reset
        unsafe {
            PortWriteOnly::new(io_base + 0x37).write(0x10u8);
        }
        while unsafe { PortReadOnly::<u8>::new(io_base + 0x37).read() } & 0x10 != 0 {}

        // init receive buffer
        let rx_buffer = DmaBuffer::new(8208, PAGE_SIZE).unwrap();
        let phys_addr: u32 = rx_buffer
            .physical_address()
            .try_into()
            .expect("DMA buffer address cannot fit in 32-bit");
        unsafe {
            PortWriteOnly::new(io_base + 0x30).write(phys_addr);
        }

        // skip setting up IMR+ISR because we use polling for now

        // configure receive buffer
        unsafe {
            PortWriteOnly::new(io_base + 0x44).write(0xfu8);
        }

        // enable receive and transmitter
        unsafe {
            PortWriteOnly::new(io_base + 0x37).write(0x0cu8);
        }

        Self {
            io_base,
            mac,
            rx_buffer,
            cur_rx: 0,
        }
    }
}

unsafe impl Send for Rtl8139 {}

impl super::Nic for Rtl8139 {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn poll(&mut self) {
        const CMD_BUFFER_EMPTY: u8 = 0x01;
        const ROK: u16 = 0x0001;
        const TOK: u16 = 0x0004;
        const RX_RING_SIZE: usize = 8192;
        const MIN_PACKET_SIZE: usize = 4; // Ethernet FCS
        const MAX_PACKET_SIZE: usize = 1522; // Ethernet frame plus FCS
        const MAX_PACKETS_PER_POLL: usize = 64;
        let status: u16 = unsafe { PortReadOnly::new(self.io_base + 0x3e).read() };
        unsafe {
            PortWriteOnly::new(self.io_base + 0x3e).write(status);
        }
        if status & TOK != 0 {
            println!("[DEBUG] rtl8139: sent packet");
        }
        if status & ROK != 0 {
            let mut packets = 0;
            while packets < MAX_PACKETS_PER_POLL
                && unsafe { PortReadOnly::<u8>::new(self.io_base + 0x37).read() } & CMD_BUFFER_EMPTY
                    == 0
            {
                let read_index = self.cur_rx;
                let rx_buffer_ptr = self.rx_buffer.as_ptr();
                let rx_header: u32 =
                    unsafe { *(rx_buffer_ptr.add(read_index as usize) as *const _) };
                let rx_status = (rx_header & 0xffff) as u16;
                let rx_size = (rx_header >> 16) as u16;
                println!(
                    "[DEBUG] rtl8139: cur_rx={} header={:#010x} status={:#06x} size={}",
                    read_index, rx_header, rx_status, rx_size
                );
                let rx_size = rx_size as usize;
                if !(MIN_PACKET_SIZE..=MAX_PACKET_SIZE).contains(&rx_size) {
                    // An invalid length cannot be used to find the next ring
                    // entry.  Leaving cur_rx unchanged would make poll() read
                    // this same header forever.
                    println!("[WARN] rtl8139: invalid RX size {rx_size}; stopping receive poll");
                    break;
                }
                if rx_status & 0x0001 != 0 {
                    let packet = if read_index as usize + rx_size > RX_RING_SIZE {
                        let len = rx_size - 4;
                        let mut res = Vec::with_capacity(len);
                        res.extend_from_slice(unsafe {
                            core::slice::from_raw_parts(
                                rx_buffer_ptr.add(read_index as usize + 4).cast_const(),
                                RX_RING_SIZE - read_index as usize - 4,
                            )
                        });
                        res.extend_from_slice(unsafe {
                            core::slice::from_raw_parts(
                                rx_buffer_ptr,
                                read_index as usize + rx_size - RX_RING_SIZE,
                            )
                        });
                        res
                    } else {
                        unsafe {
                            let data_ptr = rx_buffer_ptr.add(read_index as usize + 4).cast_const();
                            let len = rx_size - 4;
                            core::slice::from_raw_parts(data_ptr, len).to_owned()
                        }
                    };
                    println!("[DEBUG] rtl8139: rx packet {packet:?}");
                }
                let read_index = (read_index as usize + rx_size + 7) & !3;
                let read_index = (read_index % RX_RING_SIZE) as u16;
                unsafe {
                    PortWriteOnly::new(self.io_base + 0x38).write(read_index.wrapping_sub(16));
                }
                self.cur_rx = read_index;
                packets += 1;
            }
            if packets == MAX_PACKETS_PER_POLL {
                println!("[WARN] rtl8139: receive poll budget exhausted");
            }
        }
    }
}

pub(super) fn init() {
    crate::pcie::enumrate::doit(|bus, device, function, config| {
        if config.vendor_id == 0x10ec && config.device_id == 0x8139 {
            println!("[INFO] rtl8139: found at {bus:02x}:{device:02x}.{function}");
            let nic = Rtl8139::new(config);
            println!("[INFO] rtl8139: physical address is {}", nic.format_mac());
            super::NICS.lock().push(Box::new(nic));
        }
    });
}
