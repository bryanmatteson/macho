#![cfg(feature = "cli")]

//! Borrowed byte-source contracts through the public façade.
#![cfg(target_os = "macos")]

use std::ops::Range;

struct MappedMachO {
    mmap: memmap2::Mmap,
    range: Range<usize>,
}

impl AsRef<[u8]> for MappedMachO {
    fn as_ref(&self) -> &[u8] {
        &self.mmap[self.range.clone()]
    }
}

fn load_true() -> MappedMachO {
    let file = std::fs::File::open("/usr/bin/true").expect("open /usr/bin/true");
    // SAFETY: the mapping is read-only and retained for every consumer call.
    let mmap = unsafe { memmap2::Mmap::map(&file).expect("map /usr/bin/true") };
    let container = macho::parse(&mmap).expect("parse /usr/bin/true");
    let range = match &container {
        macho::model::container::MachoContainer::Thin(_) => 0..mmap.len(),
        macho::model::container::MachoContainer::Fat(fat) => {
            let arch = &fat.arches()[0];
            let start = usize::try_from(arch.fat_offset().0).expect("slice offset fits usize");
            let size = usize::try_from(arch.size()).expect("slice size fits usize");
            start
                ..start
                    .checked_add(size)
                    .expect("slice range does not overflow")
        }
    };
    drop(container);
    MappedMachO { mmap, range }
}

#[test]
fn language_leaf_apis_accept_a_borrowed_file_mapping() {
    let mmap = load_true();

    macho::objc::parse_objc_metadata_from_source(&mmap).expect("Objective-C source parses");
    macho::swift::SwiftTypeIndex::build_from_source(&mmap).expect("Swift source parses");
    macho::cpp::VtableIndex::build_from_source(&mmap).expect("C++ vtable source parses");
    macho::cpp::build_typeinfo_index_from_source(&mmap).expect("C++ typeinfo source parses");
}
