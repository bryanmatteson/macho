use crate::format::parse;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::mutate::MachoEditor;
use crate::mutate::preview::build_structural_preview;
pub use crate::mutate::preview::{SignatureOutcome, StructuralPatchPreview};
pub use crate::operation::PatchOp;
use crate::section::AddSection;
use crate::{Error, Result};

/// Validated structural patch plan.
#[derive(Debug, Clone, Default)]
pub struct PatchPlan<'section> {
    ops: Vec<PatchOp<'section>>,
    expected: Vec<(u64, Vec<u8>)>,
}

impl<'section> PatchPlan<'section> {
    /// Create a plan from operations. Validation occurs against concrete input
    /// bytes before any candidate buffer is changed.
    pub fn new(ops: Vec<PatchOp<'section>>) -> Self {
        Self {
            ops,
            expected: Vec::new(),
        }
    }

    /// Require exact original bytes at a slice-relative file offset.
    pub fn expect_bytes(mut self, offset: u64, bytes: Vec<u8>) -> Self {
        self.expected.push((offset, bytes));
        self
    }

    /// Borrow the ordered operations.
    pub fn operations(&self) -> &[PatchOp<'section>] {
        &self.ops
    }

    /// Validate byte ranges, overlap, arithmetic, and original-byte
    /// preconditions against an immutable input buffer.
    pub fn validate(&self, input: &[u8]) -> Result<()> {
        let mut ranges = Vec::new();
        for op in &self.ops {
            if let PatchOp::PatchBytes { offset, bytes } = op {
                let start = usize::try_from(*offset)
                    .map_err(|_| Error::bounds(*offset, bytes.len() as u64, input.len() as u64))?;
                let end = start.checked_add(bytes.len()).ok_or_else(|| {
                    Error::bounds(*offset, bytes.len() as u64, input.len() as u64)
                })?;
                if end > input.len() {
                    return Err(Error::bounds(
                        *offset,
                        bytes.len() as u64,
                        input.len() as u64,
                    ));
                }
                ranges.push((start, end));
            }
        }
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(Error::validation(format!(
                    "patch byte ranges overlap at {:#x}..{:#x}",
                    pair[1].0, pair[0].1
                )));
            }
        }
        for (offset, expected) in &self.expected {
            let start = usize::try_from(*offset)
                .map_err(|_| Error::bounds(*offset, expected.len() as u64, input.len() as u64))?;
            let end = start
                .checked_add(expected.len())
                .ok_or_else(|| Error::bounds(*offset, expected.len() as u64, input.len() as u64))?;
            if input.get(start..end) != Some(expected.as_slice()) {
                return Err(Error::validation(format!(
                    "expected original bytes do not match at offset {offset:#x}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
/// The PreparedPatch type.
pub struct PreparedPatch {
    /// The preview field.
    pub preview: StructuralPatchPreview,
    /// The bytes field.
    pub bytes: Vec<u8>,
}

/// The PatchTransaction type.
pub struct PatchTransaction<'image, 'section> {
    macho: &'image MachoFile<'image>,
    ops: Vec<PatchOp<'section>>,
}

impl<'image, 'section> PatchTransaction<'image, 'section> {
    /// Performs new.
    pub fn new(macho: &'image MachoFile<'image>) -> Self {
        Self {
            macho,
            ops: Vec::new(),
        }
    }

    /// Performs add_op.
    pub fn add_op(&mut self, op: PatchOp<'section>) {
        self.ops.push(op);
    }

    /// Performs add_rpath.
    pub fn add_rpath(&mut self, path: impl Into<String>) {
        self.ops.push(PatchOp::AddRpath(path.into()));
    }

    /// Performs remove_rpath.
    pub fn remove_rpath(&mut self, path: impl Into<String>) {
        self.ops.push(PatchOp::RemoveRpath(path.into()));
    }

    /// Performs add_dylib.
    pub fn add_dylib(&mut self, name: impl Into<String>, compat: u32, current: u32) {
        self.ops.push(PatchOp::AddDylib {
            name: name.into(),
            compat_version: compat,
            current_version: current,
        });
    }

    /// Performs add_command.
    pub fn add_command(&mut self, cmd: LoadCommand) {
        self.ops.push(PatchOp::AddCommand(cmd));
    }

    /// Performs remove_command.
    pub fn remove_command(&mut self, index: usize) {
        self.ops.push(PatchOp::RemoveCommand(index));
    }

    /// Performs replace_command.
    pub fn replace_command(&mut self, index: usize, cmd: LoadCommand) {
        self.ops.push(PatchOp::ReplaceCommand(index, cmd));
    }

    /// Stage a section addition to an existing segment.
    pub fn add_section(&mut self, section: AddSection<'section>) {
        self.ops.push(PatchOp::AddSection(section));
    }

    /// Performs remove_code_signature.
    pub fn remove_code_signature(&mut self) {
        self.ops.push(PatchOp::RemoveCodeSignature);
    }

    /// Performs ops.
    pub fn ops(&self) -> &[PatchOp<'section>] {
        &self.ops
    }

    /// Performs preview.
    pub fn preview(&self) -> Result<StructuralPatchPreview> {
        Ok(self.prepare()?.preview)
    }

    /// Performs prepare.
    pub fn prepare(&self) -> Result<PreparedPatch> {
        PatchPlan::new(self.ops.clone()).validate(self.macho.bytes())?;
        let mut editor = MachoEditor::new(self.macho);
        apply_ops(&mut editor, &self.ops)?;
        let mut candidate = editor.build()?;
        apply_byte_patches(&mut candidate, &self.ops)?;
        let reparsed = parse(&candidate)?;
        let reparsed_mach = reparsed.first_macho().ok_or_else(|| {
            Error::validation("patched container does not contain a Mach-O image")
        })?;

        let preview =
            build_structural_preview(self.macho, candidate.as_slice(), reparsed_mach, &self.ops)?;

        Ok(PreparedPatch {
            preview,
            bytes: candidate,
        })
    }

    /// Performs patch_bytes.
    pub fn patch_bytes(&mut self, offset: u64, bytes: Vec<u8>) {
        self.ops.push(PatchOp::PatchBytes { offset, bytes });
    }

    /// Performs build_unchecked.
    pub fn build_unchecked(&self) -> Result<Vec<u8>> {
        let mut editor = MachoEditor::new(self.macho);
        apply_ops(&mut editor, &self.ops)?;
        let mut output = editor.build()?;
        apply_byte_patches(&mut output, &self.ops)?;
        Ok(output)
    }

    /// Build the candidate, reparse, validate, and return bytes only if valid.
    pub fn commit(&self) -> Result<Vec<u8>> {
        let prepared = self.prepare()?;

        if !prepared.preview.validation_errors.is_empty() {
            return Err(Error::invalid(format!(
                "candidate binary failed validation:\n  {}",
                prepared.preview.validation_errors.join("\n  ")
            )));
        }

        Ok(prepared.bytes)
    }
}

fn apply_ops<'section>(
    editor: &mut MachoEditor<'_, 'section>,
    ops: &[PatchOp<'section>],
) -> Result<()> {
    for op in ops {
        match op {
            PatchOp::AddRpath(path) => editor.add_rpath(path),
            PatchOp::RemoveRpath(path) => editor.remove_rpath(path),
            PatchOp::AddDylib {
                name,
                compat_version,
                current_version,
            } => editor.add_load_dylib(name, *compat_version, *current_version),
            PatchOp::RemoveCodeSignature => editor.remove_code_signature(),
            PatchOp::AddCommand(cmd) => editor.add_command(cmd.clone()),
            PatchOp::RemoveCommand(idx) => {
                editor.remove_command(*idx)?;
            }
            PatchOp::ReplaceCommand(idx, cmd) => {
                editor.replace_command(*idx, cmd.clone())?;
            }
            PatchOp::AddSection(section) => editor.add_section(section.clone())?,
            PatchOp::PatchBytes { .. } => {
                // Byte patches are applied after build, not through MachoEditor
            }
        }
    }
    Ok(())
}

fn apply_byte_patches(output: &mut [u8], ops: &[PatchOp<'_>]) -> Result<()> {
    for op in ops {
        if let PatchOp::PatchBytes { offset, bytes } = op {
            let start = usize::try_from(*offset)
                .map_err(|_| Error::bounds(*offset, bytes.len() as u64, output.len() as u64))?;
            let end = start
                .checked_add(bytes.len())
                .ok_or_else(|| Error::bounds(*offset, bytes.len() as u64, output.len() as u64))?;
            if end > output.len() {
                return Err(Error::bounds(
                    *offset,
                    bytes.len() as u64,
                    output.len() as u64,
                ));
            }
            output[start..end].copy_from_slice(bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddSection, MutationErrorKind, MutationOperation};

    #[test]
    fn plan_rejects_overlap_without_mutating_input() {
        let input = macho_test_support::thin64_arm64(2);
        let original = input.clone();
        let plan = PatchPlan::new(vec![
            PatchOp::PatchBytes {
                offset: 4,
                bytes: vec![1, 2, 3, 4],
            },
            PatchOp::PatchBytes {
                offset: 6,
                bytes: vec![5, 6],
            },
        ]);
        let error = plan.validate(&input).expect_err("overlap must fail");
        assert_eq!(error.kind, MutationErrorKind::Validation);
        assert_eq!(error.operation, MutationOperation::Validate);
        assert_eq!(input, original);
    }

    #[test]
    fn plan_rejects_stale_expected_bytes() {
        let input = macho_test_support::thin64_arm64(2);
        let plan = PatchPlan::default().expect_bytes(0, vec![0, 0, 0, 0]);
        let error = plan
            .validate(&input)
            .expect_err("stale precondition must fail");
        assert_eq!(error.kind, MutationErrorKind::Validation);
    }

    #[test]
    fn failed_strict_reparse_leaves_original_unchanged() {
        let input = macho_test_support::thin64_arm64(2);
        let original = input.clone();
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction.patch_bytes(0, vec![0, 0, 0, 0]);
        let error = transaction.prepare().expect_err("invalid magic must fail");
        assert_eq!(error.kind, MutationErrorKind::Parse);
        assert_eq!(input, original);
    }

    #[test]
    fn add_file_backed_section_commits_payload_and_metadata() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let original_text = input[0x400..0x404].to_vec();
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        let section = AddSection::new("__LINKEDIT", "__macho", &[1, 2, 3, 4, 5])
            .expect("valid section")
            .with_alignment(3)
            .expect("valid alignment");
        transaction.add_section(section);

        let committed = transaction.commit().expect("section addition commits");
        let reparsed = macho_core::parse(&committed).expect("candidate reparses");
        let macho = reparsed.first_macho().unwrap();
        let section = macho
            .section("__LINKEDIT", "__macho")
            .expect("section is present");
        assert_eq!(section.align(), 3);
        assert_eq!(section.offset().0 % 8, 0);
        assert_eq!(section.size(), 5);
        assert_eq!(
            macho
                .section_bytes("__LINKEDIT", "__macho")
                .expect("file-backed payload"),
            &[1, 2, 3, 4, 5]
        );
        assert_eq!(
            &committed[0x400..0x404],
            original_text.as_slice(),
            "existing __TEXT payload must remain at its original offset"
        );
    }

    #[test]
    fn add_section_and_byte_patch_share_stable_original_offsets() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction.add_section(
            AddSection::new("__LINKEDIT", "__payload", &[1, 2, 3, 4]).expect("valid section"),
        );
        transaction.patch_bytes(0x400, vec![0xAA, 0xBB, 0xCC, 0xDD]);

        let committed = transaction.commit().expect("mixed edit commits");
        assert_eq!(&committed[0x400..0x404], &[0xAA, 0xBB, 0xCC, 0xDD]);
        let reparsed = macho_core::parse(&committed).expect("candidate reparses");
        assert_eq!(
            reparsed
                .first_macho()
                .unwrap()
                .section_bytes("__LINKEDIT", "__payload")
                .expect("added payload"),
            &[1, 2, 3, 4]
        );
    }

    #[test]
    fn add_zero_fill_section_has_no_file_payload() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let container = macho_core::parse(&input).expect("fixture parses");
        let original = container.first_macho().unwrap();
        let original_len = input.len();
        let mut transaction = PatchTransaction::new(original);
        transaction.add_section(
            AddSection::zero_fill("__LINKEDIT", "__scratch", 0x20)
                .expect("valid section")
                .with_alignment(4)
                .expect("valid alignment"),
        );

        let committed = transaction.commit().expect("section addition commits");
        assert_eq!(committed.len(), original_len);
        let reparsed = macho_core::parse(&committed).expect("candidate reparses");
        let macho = reparsed.first_macho().unwrap();
        let section = macho
            .section("__LINKEDIT", "__scratch")
            .expect("section is present");
        assert!(section.section_type().is_zerofill());
        assert_eq!(section.size(), 0x20);
        assert!(macho.section_bytes("__LINKEDIT", "__scratch").is_err());
    }

    #[test]
    fn add_section_rejects_duplicate_and_segment_relocation() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let container = macho_core::parse(&input).expect("fixture parses");
        let original = container.first_macho().unwrap();

        let mut duplicate = PatchTransaction::new(original);
        duplicate
            .add_section(AddSection::new("__TEXT", "__text", &[0]).expect("valid request syntax"));
        assert!(duplicate.prepare().is_err());

        let mut no_space = PatchTransaction::new(original);
        no_space
            .add_section(AddSection::new("__TEXT", "__extra", &[0]).expect("valid request syntax"));
        let error = no_space
            .prepare()
            .expect_err("later segment must not be relocated");
        assert_eq!(error.kind, MutationErrorKind::InvalidInput);
        assert_eq!(input, original.bytes());
    }

    #[test]
    fn add_section_consumes_bounded_gap_before_later_segment() {
        let input = macho_test_support::signable_thin64_x86_64_with_data_gap(2);
        let container = macho_core::parse(&input).expect("fixture parses");
        let macho = container.first_macho().expect("thin Mach-O");
        let mut transaction = PatchTransaction::new(macho);
        transaction.add_section(
            AddSection::new("__DATA", "__payload", &[1, 2, 3, 4]).expect("valid section request"),
        );

        let output = transaction.commit().expect("gap-backed insertion succeeds");
        let reparsed = macho_core::parse(&output).expect("output reparses");
        let macho = reparsed.first_macho().expect("thin Mach-O");
        let section = macho
            .section("__DATA", "__payload")
            .expect("new section is present");
        assert_eq!(section.offset().0, 0x1100);
        assert_eq!(
            macho.section_bytes("__DATA", "__payload").unwrap(),
            &[1, 2, 3, 4]
        );
        assert_eq!(&output[0x1200..0x1210], &input[0x1200..0x1210]);
    }

    #[test]
    fn add_sections_reject_load_command_payload_relocation() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let original = input.clone();
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        let payloads = (0..50).map(|index| [index as u8]).collect::<Vec<_>>();
        for (index, payload) in payloads.iter().enumerate() {
            transaction.add_section(
                AddSection::new("__LINKEDIT", format!("__macho{index:02}"), payload)
                    .expect("valid section"),
            );
        }

        let error = transaction
            .commit()
            .expect_err("existing payload relocation must fail closed");
        assert_eq!(error.kind, MutationErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains("insufficient load-command slack")
        );
        assert_eq!(input, original);
    }

    #[test]
    fn add_file_backed_section_rejects_existing_zero_fill_overlap() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction.add_section(
            AddSection::zero_fill("__LINKEDIT", "__scratch", 0x20)
                .expect("valid zero-fill section"),
        );
        transaction.add_section(
            AddSection::new("__LINKEDIT", "__payload", &[1, 2, 3, 4])
                .expect("valid file-backed section"),
        );
        let error = transaction
            .prepare()
            .expect_err("overlapping VM ranges must fail");
        assert_eq!(error.kind, MutationErrorKind::InvalidInput);
    }

    #[test]
    fn add_file_backed_section_rejects_unowned_trailing_bytes() {
        let mut input = macho_test_support::signable_thin64_arm64(2);
        input.push(0xAA);
        let container = macho_core::parse(&input).expect("fixture with trailing data parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction
            .add_section(AddSection::new("__LINKEDIT", "__payload", &[1]).expect("valid section"));
        let error = transaction
            .prepare()
            .expect_err("unowned trailing data must not be absorbed into a segment");
        assert_eq!(error.kind, MutationErrorKind::InvalidInput);
        assert!(error.to_string().contains("declared file range ends"));
    }

    #[test]
    fn load_command_strings_reject_nul_without_truncation() {
        let input = macho_test_support::signable_thin64_arm64(2);
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction.add_rpath("/bad\0hidden");
        let error = transaction
            .prepare()
            .expect_err("interior NUL must not change encoded meaning");
        assert_eq!(error.kind, MutationErrorKind::InvalidInput);
    }

    fn thin32_with_linkedit(big_endian: bool) -> Vec<u8> {
        fn push_u32(bytes: &mut Vec<u8>, value: u32, big_endian: bool) {
            let encoded = if big_endian {
                value.to_be_bytes()
            } else {
                value.to_le_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        fn push_name(bytes: &mut Vec<u8>, name: &str) {
            let mut encoded = [0u8; 16];
            encoded[..name.len()].copy_from_slice(name.as_bytes());
            bytes.extend_from_slice(&encoded);
        }
        fn push_segment(bytes: &mut Vec<u8>, name: &str, fields: [u32; 5], big_endian: bool) {
            let [vmaddr, vmsize, fileoff, filesize, nsects] = fields;
            push_u32(bytes, 1, big_endian);
            push_u32(bytes, 56 + nsects * 68, big_endian);
            push_name(bytes, name);
            for value in [vmaddr, vmsize, fileoff, filesize, 5, 5, nsects, 0] {
                push_u32(bytes, value, big_endian);
            }
        }

        let mut bytes = Vec::new();
        push_u32(&mut bytes, 0xfeed_face, big_endian);
        for value in [7, 3, 2, 2, 124 + 56, 0] {
            push_u32(&mut bytes, value, big_endian);
        }
        push_segment(
            &mut bytes,
            "__TEXT",
            [0x1000, 0x1000, 0, 0x1000, 1],
            big_endian,
        );
        push_name(&mut bytes, "__text");
        push_name(&mut bytes, "__TEXT");
        for value in [0x1400, 4, 0x400, 2, 0, 0, 0, 0, 0] {
            push_u32(&mut bytes, value, big_endian);
        }
        push_segment(
            &mut bytes,
            "__LINKEDIT",
            [0x2000, 0x1000, 0x1000, 0x10, 0],
            big_endian,
        );
        bytes.resize(0x1010, 0);
        bytes[0x400..0x404].copy_from_slice(&[1, 2, 3, 4]);
        bytes
    }

    #[test]
    fn add_section_encodes_32_bit_little_and_big_endian() {
        for big_endian in [false, true] {
            let input = thin32_with_linkedit(big_endian);
            let container = macho_core::parse(&input).expect("32-bit fixture parses");
            let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
            transaction.add_section(
                AddSection::new("__LINKEDIT", "__meta", &[9, 8, 7, 6]).expect("valid section"),
            );
            let committed = transaction.commit().expect("32-bit section commits");
            let reparsed = macho_core::parse(&committed).expect("candidate reparses");
            assert_eq!(
                reparsed
                    .first_macho()
                    .unwrap()
                    .section_bytes("__LINKEDIT", "__meta")
                    .expect("added payload"),
                &[9, 8, 7, 6]
            );
            assert_eq!(&committed[0x400..0x404], &[1, 2, 3, 4]);
        }
    }

    #[test]
    fn add_section_rejects_64_bit_only_reserved_word_on_32_bit() {
        let input = thin32_with_linkedit(false);
        let container = macho_core::parse(&input).expect("32-bit fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction.add_section(
            AddSection::new("__LINKEDIT", "__meta", &[1])
                .expect("valid section")
                .with_reserved(0, 0, 1),
        );
        let error = transaction
            .prepare()
            .expect_err("reserved3 must not be silently discarded");
        assert_eq!(error.kind, MutationErrorKind::InvalidInput);
    }
}
