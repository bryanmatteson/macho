use macho::addr::ThinFileOffset;
use macho::model::container::MachContainer;
use macho::model::owned::OwnedFatBinary;

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn owned_from_thin() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let owned = mach.to_owned_mach();
    assert_eq!(owned.bytes().len(), mach.bytes().len());
    assert_eq!(owned.header().ncmds, mach.header().ncmds);
    assert_eq!(owned.segments().len(), mach.segments().len());
    assert_eq!(owned.load_commands().len(), mach.load_commands().len());
}

#[test]
fn owned_re_parse() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let owned = mach.to_owned_mach();
    let reparsed = owned.as_mach_file().expect("re-parse failed");
    assert_eq!(reparsed.header().ncmds, mach.header().ncmds);
    assert_eq!(reparsed.segments().len(), mach.segments().len());
}

#[test]
fn write_bytes_at_offset() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut owned = mach.to_owned_mach();
    let offset = ThinFileOffset(0x100);
    let original = owned.bytes()[0x100..0x104].to_vec();

    // Write different bytes
    let patch = [0xDE, 0xAD, 0xBE, 0xEF];
    owned.write_bytes_at(offset, &patch).expect("write failed");
    assert_eq!(&owned.bytes()[0x100..0x104], &patch);

    // Restore original
    owned
        .write_bytes_at(offset, &original)
        .expect("restore failed");
    assert_eq!(&owned.bytes()[0x100..0x104], &original[..]);
}

#[test]
fn write_bytes_at_va() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut owned = mach.to_owned_mach();

    // Find a section with data we can patch
    let section = mach.section("__TEXT", "__text").expect("no __text section");
    let va = section.addr;

    let original = owned
        .as_mach_file()
        .unwrap()
        .read_bytes_at_va(va, 4)
        .unwrap()
        .to_vec();

    let patch = [0x00, 0x00, 0x00, 0x00];
    owned
        .write_bytes_at_va(va, &patch)
        .expect("write_va failed");

    // Verify via re-parse
    let reparsed = owned.as_mach_file().unwrap();
    let read_back = reparsed.read_bytes_at_va(va, 4).unwrap();
    assert_eq!(read_back, &patch);

    // Restore
    owned
        .write_bytes_at_va(va, &original)
        .expect("restore failed");
}

#[test]
fn write_pod_at() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut owned = mach.to_owned_mach();
    let val: u32 = 0xCAFEBABE;
    owned
        .write_pod_at(ThinFileOffset(0x200), &val)
        .expect("write_pod_at failed");

    let read_back: u32 = macho::io::pod::read_pod(owned.bytes(), 0x200).expect("read_pod failed");
    assert_eq!(read_back, val);
}

#[test]
fn write_bounds_check() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut owned = mach.to_owned_mach();
    let offset = ThinFileOffset(owned.bytes().len() as u64 - 2);
    // Try to write 4 bytes at 2 bytes before end — should fail
    assert!(owned.write_bytes_at(offset, &[0; 4]).is_err());
}

#[test]
fn save_to_vec() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let owned = mach.to_owned_mach();
    let mut buf = Vec::new();
    owned.save_to(&mut buf).expect("save_to failed");
    assert_eq!(buf.len(), mach.bytes().len());
    assert_eq!(buf, mach.bytes());
}

#[test]
fn into_bytes() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let owned = mach.to_owned_mach();
    let bytes = owned.into_bytes();
    assert_eq!(bytes.len(), mach.bytes().len());
}

#[test]
fn owned_fat_binary() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    if let MachContainer::Fat(ref fat) = container {
        let owned = OwnedFatBinary::from_fat(fat, &mmap);
        assert_eq!(owned.arches().len(), fat.arches().len());

        // Verify each arch is accessible
        for i in 0..fat.arches().len() {
            let arch = owned.arch(i).expect("arch not found");
            assert_eq!(arch.bytes().len(), fat.arches()[i].size as usize);
        }
    }
}

#[test]
fn owned_fat_arch_mut() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    if let MachContainer::Fat(ref fat) = container {
        let mut owned = OwnedFatBinary::from_fat(fat, &mmap);

        // Patch a byte in the first arch
        let arch = owned.arch_mut(0).expect("arch_mut failed");
        let _original = arch.bytes()[0x100];
        arch.write_bytes_at(ThinFileOffset(0x100), &[0xFF])
            .expect("write failed");
        assert_eq!(arch.bytes()[0x100], 0xFF);

        // Sync back to container
        let bytes = owned.into_bytes();
        assert_eq!(bytes.len(), mmap.len());

        // The patched byte should be reflected in the container at the arch's offset
        let fat_offset = fat.arches()[0].fat_offset.0 as usize;
        assert_eq!(bytes[fat_offset + 0x100], 0xFF);
    }
}
