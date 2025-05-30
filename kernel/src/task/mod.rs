pub mod process;
pub mod sched;
pub mod syscall;

use core::arch::asm;
use spin::Lazy;
use x86_64::addr::PhysAddr;
use x86_64::addr::VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::registers::segmentation::{Segment, SegmentSelector, CS, DS, ES, SS};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::structures::tss::TaskStateSegment;
use x86_64::PrivilegeLevel;

pub static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    let rsp0_pa = crate::mm::page_alloc::find_continuous_mem(16) + 0x10000; // 64k rsp0
    tss.privilege_stack_table[0] = VirtAddr::new(crate::mm::phys_to_virt(rsp0_pa));
    tss
});

pub static GDT: Lazy<GlobalDescriptorTable> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    gdt.append(Descriptor::kernel_code_segment());
    gdt.append(Descriptor::kernel_data_segment());
    gdt.append(Descriptor::user_code_segment());
    gdt.append(Descriptor::user_data_segment());
    gdt.append(Descriptor::tss_segment(&TSS));
    gdt
});

pub fn reset_gdt() {
    GDT.load();
    unsafe {
        CS::set_reg(SegmentSelector::new(1, PrivilegeLevel::Ring0));
        DS::set_reg(SegmentSelector::new(2, PrivilegeLevel::Ring0));
        SS::set_reg(SegmentSelector::new(2, PrivilegeLevel::Ring0));
        ES::set_reg(SegmentSelector::new(2, PrivilegeLevel::Ring0));
        // FS::set_reg(SegmentSelector::new(2, PrivilegeLevel::Ring0));
        // GS::set_reg(SegmentSelector::new(2, PrivilegeLevel::Ring0));
        x86_64::instructions::tables::load_tss(SegmentSelector::new(5, PrivilegeLevel::Ring0));
    }
}

#[allow(named_asm_labels)]
pub fn init() {
    unsafe {
        let flags = Cr3::read().1;
        let new_cr3_va;
        {
            let mut tasks = self::process::TASKS.lock();
            tasks[0] = Some(self::process::Process::task_0());
            new_cr3_va = tasks[0].as_ref().unwrap().page_table.level_4_table() as *const _ as u64;
        }
        let new_cr3 =
            PhysFrame::from_start_address(PhysAddr::new(new_cr3_va - crate::mm::phys_to_virt(0)))
                .unwrap();
        crate::println!("[DEBUG] task: will load task 0's cr3 {:?}", new_cr3);
        Cr3::write(new_cr3, flags);
        x86_64::instructions::interrupts::enable(); // the last thing to do in Ring 0
        DS::set_reg(SegmentSelector::new(4, PrivilegeLevel::Ring3));
        ES::set_reg(SegmentSelector::new(4, PrivilegeLevel::Ring3));
        // FS::set_reg(SegmentSelector::new(4, PrivilegeLevel::Ring3));
        // GS::set_reg(SegmentSelector::new(4, PrivilegeLevel::Ring3));
        asm!(
            "mov rax, rsp",
            "push 0x23",
            "push rax",
            "pushfq",
            "push 0x1b",
            "push offset cd",
            "iretq",
            "cd:",
            out("rax") _,
        );
    }
}

pub fn init_sse() {
    use x86_64::registers::control::{Cr0Flags, Cr4Flags};
    unsafe {
        x86_64::registers::control::Cr0::update(|f| {
            f.insert(Cr0Flags::MONITOR_COPROCESSOR);
            f.remove(Cr0Flags::EMULATE_COPROCESSOR | Cr0Flags::TASK_SWITCHED);
        });
        x86_64::registers::control::Cr4::update(|f| {
            f.insert(Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }
}
