#![no_std]
#![no_main]

use core::arch::asm;
use DoglinkOS_2nd::console::{init as init_console, clear as clear_console, puts as console_puts};
use DoglinkOS_2nd::int::{init as init_interrupt, register as register_interrupt_handler};
use DoglinkOS_2nd::mm::init as init_mm;
use DoglinkOS_2nd::apic::{local::init as init_lapic, io::init as init_ioapic};
use DoglinkOS_2nd::acpi::{init as init_acpi, parse_madt};
use DoglinkOS_2nd::println;
use limine::request::{FramebufferRequest, HhdmRequest, RsdpRequest, RequestsEndMarker, RequestsStartMarker};
use limine::BaseRevision;

#[used]
#[link_section = ".requests"]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[link_section = ".requests"]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

/// Define the stand and end markers for Limine requests.
#[used]
#[link_section = ".requests_start_marker"]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[link_section = ".requests_end_marker"]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[no_mangle]
extern "C" fn kmain() -> ! {
    assert!(BASE_REVISION.is_supported());

    if let Some(framebuffer_response) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(framebuffer) = framebuffer_response.framebuffers().next() {
            init_console(&framebuffer);
        }
    }

    clear_console();
    println!("Loading DoglinkOS GNU/MicroFish...");
    let hhdm_response = HHDM_REQUEST.get_response().unwrap();
    init_mm(&hhdm_response);
    init_interrupt();
    init_lapic();
    let rsdp_response = RSDP_REQUEST.get_response().unwrap();
    init_acpi(&rsdp_response);
    let ioapic_phys_addr = parse_madt();
    init_ioapic(ioapic_phys_addr);
    hang();
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic: {:#?}", info);
    hang();
}

fn hang() -> ! {
    loop {
        unsafe {
            asm!("hlt");
        }
    }
}
