use super::types::{
    CppBodyAnalysis, CppBodyKind, CppConfidence, CppEvidence, CppEvidenceKind, CppReturnChannel,
};
use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::{Symbol, SymbolTable};

pub fn analyze_symbol_body(
    macho: &MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    symbol: &Symbol<'_>,
) -> Option<CppBodyAnalysis> {
    if !symbol.is_defined() || symbol.value == 0 {
        return None;
    }

    let bytes = symbol_bytes(macho, symtab, symbol, 16)?;
    let arch = macho.header().cpu_type.name().to_string();
    let (kind, return_channel, likely_wrapper) = if arch.starts_with("arm64") {
        classify_arm64(bytes)
    } else if arch == "x86_64" {
        classify_x86_64(bytes)
    } else {
        (CppBodyKind::Unknown, CppReturnChannel::Unknown, false)
    };

    Some(CppBodyAnalysis {
        arch,
        kind,
        return_channel,
        this_adjustment: None,
        likely_wrapper,
        evidence: vec![CppEvidence {
            kind: CppEvidenceKind::BodyAnalysis,
            confidence: CppConfidence::Low,
            detail: "lightweight prologue and branch classification".to_string(),
        }],
    })
}

fn symbol_bytes<'a>(
    macho: &'a MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    symbol: &Symbol<'_>,
    max_len: usize,
) -> Option<&'a [u8]> {
    let next_va = symtab
        .defined()
        .filter(|candidate| candidate.value > symbol.value)
        .map(|candidate| candidate.value)
        .min()
        .unwrap_or(symbol.value + max_len as u64);
    let len = (next_va - symbol.value).min(max_len as u64) as usize;
    macho.read_bytes_at_va(Va(symbol.value), len.max(1)).ok()
}

fn classify_arm64(bytes: &[u8]) -> (CppBodyKind, CppReturnChannel, bool) {
    if bytes.len() >= 4 {
        let word = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if word == 0xD65F03C0 {
            return (CppBodyKind::Stub, CppReturnChannel::Unknown, true);
        }
        if word & 0x7C00_0000 == 0x1400_0000 || word & 0xFC00_0000 == 0x9400_0000 {
            return (CppBodyKind::Thunk, CppReturnChannel::Unknown, true);
        }
    }
    (CppBodyKind::Standard, CppReturnChannel::Unknown, false)
}

fn classify_x86_64(bytes: &[u8]) -> (CppBodyKind, CppReturnChannel, bool) {
    if bytes.starts_with(&[0xE9]) || bytes.starts_with(&[0xEB]) || bytes.starts_with(&[0xFF, 0x25])
    {
        return (CppBodyKind::Thunk, CppReturnChannel::Unknown, true);
    }
    if bytes.starts_with(&[0xC3]) {
        return (CppBodyKind::Stub, CppReturnChannel::Unknown, true);
    }
    if bytes.starts_with(&[0x55, 0x48, 0x89, 0xE5]) {
        return (
            CppBodyKind::Standard,
            CppReturnChannel::GeneralPurpose,
            false,
        );
    }
    (CppBodyKind::Unknown, CppReturnChannel::Unknown, false)
}

#[cfg(test)]
mod tests {
    use super::{classify_arm64, classify_x86_64};
    use crate::reconstruct::cpp::types::{CppBodyKind, CppReturnChannel};

    #[test]
    fn classifies_x86_jmp_thunk() {
        let (kind, channel, wrapper) = classify_x86_64(&[0xE9, 0, 0, 0, 0]);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(matches!(channel, CppReturnChannel::Unknown));
        assert!(wrapper);
    }

    #[test]
    fn classifies_arm64_branch_thunk() {
        let word = 0x1400_0001u32.to_le_bytes();
        let (kind, _, wrapper) = classify_arm64(&word);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }
}
