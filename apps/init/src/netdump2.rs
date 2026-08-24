use dlos_app_rt::*;

/// Standard 14-byte Ethernet II frame header.
///
/// Note: This does not include the optional 802.1Q VLAN tag (which adds 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    /// Destination MAC address (6 bytes)
    pub dst_mac: [u8; 6],

    /// Source MAC address (6 bytes)
    pub src_mac: [u8; 6],

    /// EtherType or Length field (2 bytes).
    /// Stored as raw bytes to preserve network byte order (Big-Endian).
    pub ether_type: [u8; 2],
}

impl EthernetHeader {
    /// The exact size of the header in bytes.
    pub const SIZE: usize = 14;

    /// Helper to convert the raw EtherType bytes into a `u16`.
    pub fn ether_type_u16(&self) -> u16 {
        u16::from_be_bytes(self.ether_type)
    }

    /// Safely parses an Ethernet header from a raw byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        // SAFETY: EthernetHeader is `#[repr(C)]`, consists entirely of `[u8; N]`
        // arrays (alignment 1), and has no padding. It is safe to cast.
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }
}

/// Represents an IPv4-over-Ethernet ARP packet (28 bytes).
///
/// # Memory Layout
/// - `#[repr(C)]` guarantees the fields are laid out in the exact order declared.
/// - All 16-bit fields are represented as `[u8; 2]` to ensure the struct has
///   an alignment of 1. This prevents Undefined Behavior when casting from
///   network buffers that might not be 2-byte aligned.
/// - All multi-byte integers are in Network Byte Order (Big-Endian).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    /// Hardware type (e.g., 1 for Ethernet)
    pub htype: [u8; 2],
    /// Protocol type (e.g., 0x0800 for IPv4)
    pub ptype: [u8; 2],
    /// Hardware address length (e.g., 6 for MAC-48)
    pub hlen: u8,
    /// Protocol address length (e.g., 4 for IPv4)
    pub plen: u8,
    /// Operation (1 = Request, 2 = Reply)
    pub oper: [u8; 2],

    /// Sender Hardware Address (MAC)
    pub sha: [u8; 6],
    /// Sender Protocol Address (IPv4)
    pub spa: [u8; 4],
    /// Target Hardware Address (MAC)
    pub tha: [u8; 6],
    /// Target Protocol Address (IPv4)
    pub tpa: [u8; 4],
}

// Compile-time assertion to ensure the struct is exactly 28 bytes
// and has no hidden padding.
const _: () = assert!(core::mem::size_of::<ArpPacket>() == 28);
const _: () = assert!(core::mem::align_of::<ArpPacket>() == 1);

#[allow(dead_code)]
impl ArpPacket {
    // Hardware Types
    pub const HTYPE_ETHERNET: [u8; 2] = [0x00, 0x01];

    // Protocol Types
    pub const PTYPE_IPV4: [u8; 2] = [0x08, 0x00];

    // Operations
    pub const OPER_REQUEST: [u8; 2] = [0x00, 0x01];
    pub const OPER_REPLY: [u8; 2] = [0x00, 0x02];

    // Lengths
    pub const HLEN_ETHERNET: u8 = 6;
    pub const PLEN_IPV4: u8 = 4;

    /// Safely parses an ARP packet from a byte slice.
    /// Returns None if the slice is not exactly 28 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() != core::mem::size_of::<Self>() {
            return None;
        }

        // SAFETY:
        // 1. ArpPacket is #[repr(C)] and consists entirely of u8 and [u8; N] arrays.
        // 2. The size of the slice exactly matches the size of the struct.
        // 3. The alignment of ArpPacket is 1, so any byte slice is safely aligned.
        // 4. All bit patterns of u8 are valid.
        Some(unsafe { &*(bytes.as_ptr() as *const Self) })
    }

    // --- Helper Getters (Handling Big-Endian conversion) ---

    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes(self.htype)
    }

    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.ptype)
    }

    pub fn operation(&self) -> u16 {
        u16::from_be_bytes(self.oper)
    }

    pub fn sender_ipv4(&self) -> [u8; 4] {
        self.spa
    }

    pub fn target_ipv4(&self) -> [u8; 4] {
        self.tpa
    }

    pub fn is_request(&self) -> bool {
        self.oper == Self::OPER_REQUEST
    }

    pub fn is_reply(&self) -> bool {
        self.oper == Self::OPER_REPLY
    }
}

pub fn main(cnt: usize) {
    let fd = sys_open("/dev/nic0", false).unwrap();
    let mut buf = [0u8; 1518]; // largest ethernet frame
    for _ in 0..cnt {
        let mut len = sys_read3(fd, &mut buf);
        while len == 0 {
            len = sys_read3(fd, &mut buf);
        }
        let ethernet_header = EthernetHeader::from_bytes(&buf[..len]).unwrap();
        let dst_mac = ethernet_header.dst_mac;
        let src_mac = ethernet_header.src_mac;
        let ether_type = ethernet_header.ether_type_u16();
        println!("--------------------------------");
        println!(
            "Destination MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]
        );
        println!(
            "Source MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]
        );
        print!("EtherType: 0x{ether_type:04x}");
        match ether_type {
            0x0806 => {
                println!(" (ARP)");
                let arp_packet = ArpPacket::from_bytes(&buf[14..42]).unwrap();
                let sender_mac = arp_packet.sha;
                let sender_ip = arp_packet.spa;
                let target_mac = arp_packet.tha;
                let target_ip = arp_packet.tpa;
                println!("Hardware Type: 0x{:04x}", arp_packet.hardware_type());
                println!("Protocol Type: 0x{:04x}", arp_packet.protocol_type());
                println!("HW Address Len: {}", arp_packet.hlen);
                println!("Proto Address Len: {}", arp_packet.plen);
                println!("Operation Code: {}", arp_packet.operation());
                println!(
                    "Sender MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    sender_mac[0],
                    sender_mac[1],
                    sender_mac[2],
                    sender_mac[3],
                    sender_mac[4],
                    sender_mac[5]
                );
                println!(
                    "Sender IP: {}.{}.{}.{}",
                    sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]
                );
                println!(
                    "Target MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    target_mac[0],
                    target_mac[1],
                    target_mac[2],
                    target_mac[3],
                    target_mac[4],
                    target_mac[5]
                );
                println!(
                    "Target IP: {}.{}.{}.{}",
                    target_ip[0], target_ip[1], target_ip[2], target_ip[3]
                );
            }
            _ => println!(),
        }
    }
}
