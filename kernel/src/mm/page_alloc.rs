use limine::request::MemoryMapRequest;
use crate::println;
use crate::mm::bitmap::PageMan;
use super::convert_unit;
use super::phys_to_virt;
use spin::{Mutex, Lazy};
use x86_64::structures::paging::FrameAllocator;
use x86_64::addr::PhysAddr;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::Size4KiB;

#[used]
#[link_section = ".requests"]
static MMAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

static ALLOCATOR_STATE: Lazy<Mutex<PageMan>> = Lazy::new(|| {
    let res = MMAP_REQUEST.get_response().unwrap();

    let usable_mem = res
        .entries()
        .iter()
        .filter(|e| e.entry_type == limine::memory_map::EntryType::USABLE);

    let max_address = usable_mem
        .clone()
        .last()
        .map(|e| e.base + e.length).unwrap();

    let conv_res = convert_unit(max_address);
    let total_pages = max_address / 4096;
    println!("[DEBUG] mm: need to manage {} pages (aka {} {})", total_pages, conv_res.0, conv_res.1);

    let bitmap_size = PageMan::calc_size(total_pages); // unit: (count, count, bytes)
    let conv_res = convert_unit(bitmap_size.2);
    println!("[DEBUG] mm: need bitmap size of {} {}", conv_res.0, conv_res.1);

    let bitmap_address = usable_mem
        .clone()
        .find(|region| region.length >= bitmap_size.2)
        .map(|region| region.base)
        .unwrap();

    let bitmap_buffer1 = unsafe {
        core::slice::from_raw_parts_mut(phys_to_virt(bitmap_address) as *mut usize, bitmap_size.0 as usize)
    };

    let bitmap_buffer2 = unsafe {
        core::slice::from_raw_parts_mut(phys_to_virt(bitmap_address + bitmap_size.0 * 8) as *mut u8, bitmap_size.1 as usize)
    };

    println!("[DEBUG] mm: bitmap_buffer1 is {:?}", bitmap_buffer1.as_ptr());
    println!("[DEBUG] mm: bitmap_buffer2 is {:?}", bitmap_buffer2.as_ptr());

    let mut bitmap = PageMan::new(bitmap_buffer1, bitmap_buffer2);

    for region in usable_mem.clone() {
        let start_page = region.base / 4096;
        let end_page = start_page + region.length / 4096;
        bitmap.set_range(start_page as usize, end_page as usize, true);
    }

    let bitmap_start_page = bitmap_address / 4096;
    let bitmap_end_page = bitmap_start_page + bitmap_size.2.div_ceil(4096);
    bitmap.set_range(bitmap_start_page as usize, bitmap_end_page as usize, false);

    println!("[DEBUG] mm: bitmap_end_page is 0x{:x}", bitmap_end_page * 4096);

    bitmap.set_range(32, 2080, false); // kernel heap

    Mutex::new(bitmap)
});

// reserved for future use
pub fn get_entry_type_string(entry: &limine::memory_map::Entry) -> &str {
    match entry.entry_type {
        limine::memory_map::EntryType::USABLE => {"USABLE"},
        limine::memory_map::EntryType::RESERVED => {"RESERVED"},
        limine::memory_map::EntryType::ACPI_RECLAIMABLE => {"ACPI_RECLAIMABLE"},
        limine::memory_map::EntryType::ACPI_NVS => {"ACPI_NVS"},
        limine::memory_map::EntryType::BAD_MEMORY => {"BAD_MEMORY"},
        limine::memory_map::EntryType::BOOTLOADER_RECLAIMABLE => {"BOOTLOADER_RECLAIMABLE"},
        limine::memory_map::EntryType::KERNEL_AND_MODULES => {"KERNEL_AND_MODULES"},
        limine::memory_map::EntryType::FRAMEBUFFER => {"FRAMEBUFFER"},
        _ => {"UNK"}
    }
}

pub fn init() {
    Lazy::force(&ALLOCATOR_STATE);
}

pub fn alloc_physical_page() -> Option<u64> {
    let mut allocator_state = ALLOCATOR_STATE.lock();
    for i in 0..allocator_state.len() {
        if allocator_state.get(i) {
            allocator_state.set(i, false);
            return Some((i * 4096) as u64);
        }
    }
    None
}

pub fn dealloc_physical_page(addr: u64) {
    let index = addr / 4096;
    ALLOCATOR_STATE.lock().set(index as usize, true);
}

pub struct DLOSFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for DLOSFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        Some(
            PhysFrame::from_start_address(
                PhysAddr::new(
                    alloc_physical_page().unwrap()
                )
            ).unwrap()
        )
    }
}

pub fn test() {
    let mut addresses = [0u64; 10];
    for i in 0..10 {
        addresses[i] = alloc_physical_page().unwrap();
        println!("[DEBUG] page_alloc: Allocation #1-{}: 0x{:x}", i, addresses[i]);
    }
    for i in 0..10 {
        dealloc_physical_page(addresses[i]);
    }
    for i in 0..10 {
        addresses[i] = alloc_physical_page().unwrap();
        println!("[DEBUG] page_alloc: Allocation #2-{}: 0x{:x}", i, addresses[i]);
    }
    for i in 0..10 {
        dealloc_physical_page(addresses[i]);
    }
}
