use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every operation delegates unchanged to the system allocator; the
// counter is observational and does not affect allocation semantics.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is forwarded unchanged from the allocator caller.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` are forwarded unchanged from the
        // corresponding allocation.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `layout` is forwarded unchanged from the allocator caller.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: all arguments are forwarded unchanged from the allocator
        // caller.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

#[test]
fn container_iteration_allocates_zero_heap_objects() {
    let thin_bytes = macho_test_support::thin64_arm64(0);
    let fat_bytes = macho_test_support::fat32(&[
        (macho_test_support::CPU_TYPE_ARM64, 0, thin_bytes.clone()),
        (
            macho_test_support::CPU_TYPE_X86_64,
            3,
            macho_test_support::thin64_x86_64(0),
        ),
    ]);
    let thin = macho::core::parse(&thin_bytes).expect("thin fixture");
    let fat = macho::core::parse(&fat_bytes).expect("fat fixture");

    ALLOCATIONS.store(0, Ordering::SeqCst);
    let thin_count = thin.macho_files().count();
    let fat_count = fat.macho_files().count();
    let measured_allocations = ALLOCATIONS.load(Ordering::SeqCst);

    assert_eq!(thin_count, 1);
    assert_eq!(fat_count, 2);
    assert_eq!(measured_allocations, 0);
}
