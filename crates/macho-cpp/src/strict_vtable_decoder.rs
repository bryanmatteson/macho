//! Strict absolute-pointer Itanium vtable and VTT decoding.

use std::collections::{BTreeMap, BTreeSet};

use macho_core::model::addr::Va;
use macho_core::model::macho_file::MachoFile;
use macho_core::model::symbol::{Symbol, SymbolTable};

use super::*;
use crate::strict_rtti::decoder::{StrictDecoder, checked_add};
use crate::strict_rtti::{StrictPointerTarget, StrictRttiGapCode};
use crate::{Error, Result};

#[derive(Clone, Copy)]
struct Extent {
    byte_length: u64,
    source: ItaniumVtableExtentSource,
}

struct VtableDecoder<'a, 'data> {
    reader: StrictDecoder<'a, 'data>,
    limits: StrictVtableLimits,
    symbols_by_va: BTreeMap<u64, Vec<String>>,
    defined_vas: Vec<u64>,
    total_words: u64,
}

impl<'a, 'data> VtableDecoder<'a, 'data> {
    fn new(
        macho: &'a MachoFile<'data>,
        limits: StrictVtableLimits,
        symbols: &[Symbol<'_>],
    ) -> Result<Self> {
        let mut symbols_by_va = BTreeMap::<u64, Vec<String>>::new();
        let mut defined_vas = Vec::new();
        for symbol in symbols
            .iter()
            .filter(|value| value.is_defined() && value.value != 0)
        {
            symbols_by_va
                .entry(symbol.value)
                .or_default()
                .push(symbol.name.to_owned());
            defined_vas.push(symbol.value);
        }
        for names in symbols_by_va.values_mut() {
            names.sort();
            names.dedup();
        }
        defined_vas.sort_unstable();
        defined_vas.dedup();
        let mut reader = StrictDecoder::new(macho, limits.reader_limits())?;
        reader.symbols_by_va = symbols_by_va
            .iter()
            .filter_map(|(va, names)| names.first().cloned().map(|name| (*va, name)))
            .collect();
        Ok(Self {
            reader,
            limits,
            symbols_by_va,
            defined_vas,
            total_words: 0,
        })
    }

    fn extent(&self, symbol: &Symbol<'_>) -> Result<Extent> {
        let section = self
            .reader
            .macho
            .all_sections()
            .find(|section| {
                let start = section.addr().0;
                start
                    .checked_add(section.size())
                    .is_some_and(|end| symbol.value >= start && symbol.value < end)
            })
            .ok_or_else(|| Error::address("vtable symbol is not inside a section"))?;
        if section.section_type().is_zerofill() {
            return Err(Error::format("vtable symbol is in a zero-fill section"));
        }
        let section_end = section
            .addr()
            .0
            .checked_add(section.size())
            .ok_or_else(|| Error::format("vtable section end overflows"))?;
        let next = self
            .defined_vas
            .iter()
            .copied()
            .find(|va| *va > symbol.value && *va <= section_end);
        let (end, source) = next
            .map_or((section_end, ItaniumVtableExtentSource::SectionEnd), |va| {
                (va, ItaniumVtableExtentSource::NextDefinedSymbol)
            });
        let byte_length = end
            .checked_sub(symbol.value)
            .ok_or_else(|| Error::format("vtable symbol extent underflows"))?;
        let pointer_width = self.reader.pointer_size;
        if byte_length == 0 || byte_length % pointer_width != 0 {
            return Err(Error::format(
                "vtable symbol extent is empty or not pointer aligned",
            ));
        }
        Ok(Extent {
            byte_length,
            source,
        })
    }

    fn admit_words(&mut self, extent: Extent) -> Result<u64> {
        let words = extent.byte_length / self.reader.pointer_size;
        self.total_words = self
            .total_words
            .checked_add(words)
            .ok_or_else(|| Error::format("strict vtable word count overflows"))?;
        if self.total_words > self.limits.max_words {
            return Err(Error::format("strict vtable word limit exceeded"));
        }
        Ok(words)
    }

    fn decode_group(
        &mut self,
        symbol: &Symbol<'_>,
        kind: ItaniumVtableSymbolKind,
    ) -> Result<ItaniumVtableGroupRecord> {
        let extent = self.extent(symbol)?;
        let word_count = self.admit_words(extent)?;
        let ptr = self.reader.pointer_size;
        let raw = (0..word_count)
            .map(|ordinal| {
                let va = checked_add(
                    symbol.value,
                    ordinal
                        .checked_mul(ptr)
                        .ok_or_else(|| Error::format("vtable word address overflows"))?,
                )?;
                self.reader.peek_word(va)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut headers = Vec::new();
        for offset_word in 0..word_count.saturating_sub(1) {
            let typeinfo_word = offset_word + 1;
            let va = checked_add(symbol.value, typeinfo_word * ptr)?;
            if self.is_typeinfo_target(va)? {
                headers.push((offset_word, ItaniumVtableAddressPointSource::TypeinfoSymbol));
            }
        }
        if headers.is_empty() && word_count >= 2 && raw[1] == 0 {
            headers.push((
                0,
                ItaniumVtableAddressPointSource::NullTypeinfoAtSymbolStart,
            ));
        }
        if headers.is_empty() {
            return Err(Error::format(
                "vtable group has no structurally proven address point",
            ));
        }
        let header_words = headers
            .iter()
            .flat_map(|(word, _)| [*word, *word + 1])
            .collect::<BTreeSet<_>>();
        if header_words.len() != headers.len() * 2 {
            return Err(Error::format("vtable address-point headers overlap"));
        }

        let mut address_points = Vec::new();
        let mut ambiguous_words = Vec::new();
        let first_header = headers[0].0;
        let mut first_prefix = Vec::new();
        for word in 0..first_header {
            first_prefix.push(self.offset_record(symbol, word, raw[word as usize])?);
        }
        for (index, (offset_word, source)) in headers.iter().copied().enumerate() {
            let offset_va = checked_add(symbol.value, offset_word * ptr)?;
            let offset_observation = self.reader.observe(
                symbol.name,
                format!("address_point[{index}].offset_to_top"),
                offset_va,
                ptr,
                StrictRttiObservationKind::Integer,
            )?;
            let typeinfo = self.reader.pointer(
                symbol.name,
                format!("address_point[{index}].typeinfo"),
                checked_add(offset_va, ptr)?,
            )?;
            let next_header = headers
                .get(index + 1)
                .map(|(word, _)| *word)
                .unwrap_or(word_count);
            let slot_start = offset_word + 2;
            let mut slots = Vec::new();
            let mut cursor = slot_start;
            while cursor < next_header {
                let va = checked_add(symbol.value, cursor * ptr)?;
                if index + 1 < headers.len() && !self.is_exact_callable_or_null(va)? {
                    break;
                }
                slots.push(self.slot_record(symbol, index as u64, slots.len() as u64, cursor)?);
                cursor += 1;
            }
            while cursor < next_header {
                let va = checked_add(symbol.value, cursor * ptr)?;
                let observation_ordinal = self.reader.observe(
                    symbol.name,
                    format!("inter_address_point[{cursor}]"),
                    va,
                    ptr,
                    StrictRttiObservationKind::Integer,
                )?;
                ambiguous_words.push(ItaniumVtableAmbiguousWordRecord {
                    word_ordinal: cursor,
                    observation_ordinal,
                    raw_value: raw[cursor as usize],
                });
                cursor += 1;
            }
            address_points.push(ItaniumVtableAddressPointRecord {
                ordinal: index as u64,
                va: checked_add(symbol.value, (offset_word + 2) * ptr)?,
                source,
                offset_to_top_word: offset_word,
                prefix_offsets: if index == 0 {
                    std::mem::take(&mut first_prefix)
                } else {
                    Vec::new()
                },
                offset_to_top_observation_ordinal: offset_observation,
                offset_to_top: sign_extend(raw[offset_word as usize], ptr as u8),
                typeinfo,
                slots,
            });
        }
        Ok(ItaniumVtableGroupRecord {
            symbol: symbol.name.to_owned(),
            kind,
            va: symbol.value,
            file_offset: self
                .reader
                .macho
                .address_map()
                .va_to_thin_offset(Va(symbol.value))?
                .0,
            byte_length: extent.byte_length,
            extent_source: extent.source,
            pointer_width: ptr as u8,
            address_points,
            ambiguous_words,
            weak_definition: symbol.is_weak_def(),
        })
    }

    fn decode_vtt(&mut self, symbol: &Symbol<'_>) -> Result<ItaniumVttRecord> {
        let extent = self.extent(symbol)?;
        let word_count = self.admit_words(extent)?;
        let ptr = self.reader.pointer_size;
        let mut entries = Vec::new();
        for ordinal in 0..word_count {
            let pointer = self.reader.pointer(
                symbol.name,
                format!("vtt[{ordinal}]"),
                checked_add(symbol.value, ordinal * ptr)?,
            )?;
            if matches!(pointer.target, StrictPointerTarget::Null) {
                return Err(Error::format("VTT entry is null"));
            }
            entries.push(ItaniumVttEntryRecord {
                ordinal,
                address_point: pointer,
            });
        }
        Ok(ItaniumVttRecord {
            symbol: symbol.name.to_owned(),
            va: symbol.value,
            file_offset: self
                .reader
                .macho
                .address_map()
                .va_to_thin_offset(Va(symbol.value))?
                .0,
            byte_length: extent.byte_length,
            extent_source: extent.source,
            entries,
            weak_definition: symbol.is_weak_def(),
        })
    }

    fn is_typeinfo_target(&self, va: u64) -> Result<bool> {
        Ok(match self.reader.peek_pointer_target(va) {
            Ok(StrictPointerTarget::Local { va }) => self
                .symbols_by_va
                .get(&va)
                .is_some_and(|names| names.iter().any(|name| is_typeinfo_symbol(name))),
            Ok(StrictPointerTarget::External { symbol, .. }) => is_typeinfo_symbol(&symbol),
            Ok(StrictPointerTarget::Null) | Err(_) => false,
        })
    }

    fn is_exact_callable_or_null(&self, va: u64) -> Result<bool> {
        Ok(match self.reader.peek_pointer_target(va) {
            Ok(StrictPointerTarget::Null) => true,
            Ok(StrictPointerTarget::External { symbol, .. }) => !is_typeinfo_symbol(&symbol),
            Ok(StrictPointerTarget::Local { va }) => self
                .symbols_by_va
                .get(&va)
                .is_some_and(|names| names.iter().any(|name| !is_data_special_name(name))),
            Err(_) => false,
        })
    }

    fn offset_record(
        &mut self,
        symbol: &Symbol<'_>,
        word_ordinal: u64,
        raw_value: u64,
    ) -> Result<ItaniumVtableOffsetRecord> {
        let va = checked_add(symbol.value, word_ordinal * self.reader.pointer_size)?;
        let observation_ordinal = self.reader.observe(
            symbol.name,
            format!("prefix_offset[{word_ordinal}]"),
            va,
            self.reader.pointer_size,
            StrictRttiObservationKind::Integer,
        )?;
        Ok(ItaniumVtableOffsetRecord {
            word_ordinal,
            observation_ordinal,
            raw_value,
            signed_value: sign_extend(raw_value, self.reader.pointer_size as u8),
            role: ItaniumVtableOffsetRole::VcallOrVbase,
        })
    }

    fn slot_record(
        &mut self,
        symbol: &Symbol<'_>,
        point: u64,
        ordinal: u64,
        word_ordinal: u64,
    ) -> Result<ItaniumVtableSlotRecord> {
        let pointer = self.reader.pointer(
            symbol.name,
            format!("address_point[{point}].slot[{ordinal}]"),
            checked_add(symbol.value, word_ordinal * self.reader.pointer_size)?,
        )?;
        let target_symbol = exact_target_symbol(&pointer.target, &self.symbols_by_va);
        let (role, this_adjustment, return_adjustment) =
            classify_slot(target_symbol.as_deref(), &pointer.target)?;
        Ok(ItaniumVtableSlotRecord {
            ordinal,
            word_ordinal,
            pointer,
            target_symbol,
            role,
            this_adjustment,
            return_adjustment,
        })
    }
}

/// Decode one selected thin Mach-O into strict absolute-pointer vtable records.
pub fn decode_strict_vtables(
    macho: &MachoFile<'_>,
    limits: StrictVtableLimits,
) -> Result<StrictVtableBatch> {
    limits.validate()?;
    let input_bytes = macho.bytes().len() as u64;
    if input_bytes > limits.max_input_bytes {
        return preflight_batch("input_bytes", limits);
    }
    let symtab = macho.ext::<SymbolTable<'_>>()?;
    if symtab.symbols().len() as u64 > limits.max_symbols {
        return preflight_batch("symbol_registry", limits);
    }
    let mut candidates = symtab
        .symbols()
        .iter()
        .filter_map(|symbol| classify_symbol(symbol.name).map(|kind| (symbol, kind)))
        .collect::<Vec<_>>();
    candidates.sort_by(|(left, _), (right, _)| {
        left.name
            .cmp(right.name)
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.index.cmp(&right.index))
    });
    let attempted = candidates.len() as u64;
    if attempted == 0 {
        let batch = StrictVtableBatch {
            outcome: StrictRttiOutcome::Absent,
            records: Vec::new(),
            observations: Vec::new(),
            gaps: Vec::new(),
            conservation: StrictRttiConservation {
                attempted: 0,
                included: 0,
                unknown: 0,
                excluded: 0,
            },
        };
        batch.validate(limits)?;
        return Ok(batch);
    }
    if attempted > limits.max_records {
        let batch = StrictVtableBatch {
            outcome: StrictRttiOutcome::Rejected,
            records: Vec::new(),
            observations: Vec::new(),
            gaps: vec![StrictRttiGap {
                symbol: None,
                field: "candidate_registry".into(),
                code: StrictRttiGapCode::StructuralLimitExceeded,
                source_code: None,
            }],
            conservation: StrictRttiConservation {
                attempted,
                included: 0,
                unknown: 0,
                excluded: attempted,
            },
        };
        batch.validate(limits)?;
        return Ok(batch);
    }
    let mut decoder = VtableDecoder::new(macho, limits, symtab.symbols())?;
    let mut records = Vec::new();
    let mut gaps = Vec::new();
    let mut included = 0;
    let mut unknown = 0;
    for (symbol, kind) in candidates {
        if symbol.is_undefined() {
            records.push(StrictVtableRecord::External {
                symbol_kind: kind,
                symbol: symbol.name.to_owned(),
                library_ordinal: i32::from(symbol.library_ordinal() as i8),
                weak: symbol.is_weak_ref(),
            });
            included += 1;
            continue;
        }
        let decoded = if !symbol.is_defined() || symbol.value == 0 {
            Err(Error::format("vtable symbol is not a nonzero definition"))
        } else {
            match kind {
                ItaniumVtableSymbolKind::CompleteGroup
                | ItaniumVtableSymbolKind::ConstructionGroup => decoder
                    .decode_group(symbol, kind)
                    .map(|record| StrictVtableRecord::Group {
                        record: Box::new(record),
                    }),
                ItaniumVtableSymbolKind::Vtt => {
                    decoder
                        .decode_vtt(symbol)
                        .map(|record| StrictVtableRecord::Vtt {
                            record: Box::new(record),
                        })
                }
            }
        };
        match decoded {
            Ok(record) => {
                records.push(record);
                included += 1;
            }
            Err(error) => {
                let code = if error.message().contains("limit") {
                    StrictRttiGapCode::StructuralLimitExceeded
                } else if error.kind == crate::CppErrorKind::InvalidAddress {
                    StrictRttiGapCode::PointerUnresolved
                } else if error.kind == crate::CppErrorKind::Unsupported {
                    StrictRttiGapCode::FamilyUnsupported
                } else {
                    StrictRttiGapCode::RecordMalformed
                };
                gaps.push(StrictRttiGap {
                    symbol: Some(symbol.name.to_owned()),
                    field: match kind {
                        ItaniumVtableSymbolKind::Vtt => "vtt",
                        _ => "vtable_group",
                    }
                    .into(),
                    code,
                    source_code: Some(error.code().to_owned()),
                });
                unknown += 1;
            }
        }
    }
    let batch = StrictVtableBatch {
        outcome: if gaps.is_empty() {
            StrictRttiOutcome::Complete
        } else {
            StrictRttiOutcome::Rejected
        },
        records,
        observations: decoder.reader.observations,
        gaps,
        conservation: StrictRttiConservation {
            attempted,
            included,
            unknown,
            excluded: 0,
        },
    };
    batch.validate(limits)?;
    Ok(batch)
}

fn preflight_batch(field: &str, limits: StrictVtableLimits) -> Result<StrictVtableBatch> {
    let batch = StrictVtableBatch {
        outcome: StrictRttiOutcome::Rejected,
        records: Vec::new(),
        observations: Vec::new(),
        gaps: vec![StrictRttiGap {
            symbol: None,
            field: field.into(),
            code: StrictRttiGapCode::StructuralLimitExceeded,
            source_code: None,
        }],
        conservation: StrictRttiConservation {
            attempted: 0,
            included: 0,
            unknown: 0,
            excluded: 0,
        },
    };
    batch.validate(limits)?;
    Ok(batch)
}

/// Decode strict vtables from one borrowed thin-image byte source.
pub fn decode_strict_vtables_from_source<S>(
    source: &S,
    limits: StrictVtableLimits,
) -> Result<StrictVtableBatch>
where
    S: AsRef<[u8]> + ?Sized,
{
    let macho = crate::parse_source(source)?;
    decode_strict_vtables(&macho, limits)
}

pub(super) fn classify_symbol(name: &str) -> Option<ItaniumVtableSymbolKind> {
    let value = name.strip_prefix('_').unwrap_or(name);
    if value.starts_with("_ZTV") {
        Some(ItaniumVtableSymbolKind::CompleteGroup)
    } else if value.starts_with("_ZTC") {
        Some(ItaniumVtableSymbolKind::ConstructionGroup)
    } else if value.starts_with("_ZTT") {
        Some(ItaniumVtableSymbolKind::Vtt)
    } else {
        None
    }
}

fn is_typeinfo_symbol(name: &str) -> bool {
    let value = name.strip_prefix('_').unwrap_or(name);
    value.starts_with("_ZTI")
}

fn is_data_special_name(name: &str) -> bool {
    let value = name.strip_prefix('_').unwrap_or(name);
    ["_ZTI", "_ZTS", "_ZTV", "_ZTT", "_ZTC"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn exact_target_symbol(
    target: &StrictPointerTarget,
    symbols: &BTreeMap<u64, Vec<String>>,
) -> Option<String> {
    match target {
        StrictPointerTarget::Local { va } => symbols.get(va).and_then(|names| {
            names
                .iter()
                .find(|name| !is_data_special_name(name))
                .or_else(|| names.first())
                .cloned()
        }),
        StrictPointerTarget::External { symbol, .. } => Some(symbol.clone()),
        StrictPointerTarget::Null => None,
    }
}

fn classify_slot(
    symbol: Option<&str>,
    target: &StrictPointerTarget,
) -> Result<(
    ItaniumVtableSlotRole,
    Option<ItaniumThunkAdjustment>,
    Option<ItaniumThunkAdjustment>,
)> {
    if matches!(target, StrictPointerTarget::Null) {
        return Ok((ItaniumVtableSlotRole::Null, None, None));
    }
    let Some(symbol) = symbol else {
        return Ok((ItaniumVtableSlotRole::Unknown, None, None));
    };
    let abi = symbol.strip_prefix('_').unwrap_or(symbol);
    if abi == "__cxa_pure_virtual" {
        return Ok((ItaniumVtableSlotRole::PureVirtual, None, None));
    }
    if abi == "__cxa_deleted_virtual" {
        return Ok((ItaniumVtableSlotRole::DeletedVirtual, None, None));
    }
    if abi.ends_with("D0Ev") {
        return Ok((ItaniumVtableSlotRole::DeletingDestructor, None, None));
    }
    if abi.ends_with("D1Ev") {
        return Ok((ItaniumVtableSlotRole::CompleteDestructor, None, None));
    }
    if abi.ends_with("D2Ev") {
        return Ok((ItaniumVtableSlotRole::BaseDestructor, None, None));
    }
    if let Some(rest) = abi.strip_prefix("_ZTh") {
        let (offset, _) = parse_number(rest)?;
        return Ok((
            ItaniumVtableSlotRole::NonVirtualThunk,
            Some(ItaniumThunkAdjustment::NonVirtual { offset }),
            None,
        ));
    }
    if let Some(rest) = abi.strip_prefix("_ZTv") {
        let (offset, rest) = parse_number(rest)?;
        let rest = rest
            .strip_prefix('_')
            .ok_or_else(|| Error::format("virtual thunk lacks adjustment separator"))?;
        let (virtual_offset, _) = parse_number(rest)?;
        return Ok((
            ItaniumVtableSlotRole::VirtualThunk,
            Some(ItaniumThunkAdjustment::Virtual {
                offset,
                virtual_offset,
            }),
            None,
        ));
    }
    if let Some(rest) = abi.strip_prefix("_ZTc") {
        let (this_adjustment, rest) = parse_call_offset(rest)?;
        let (return_adjustment, _) = parse_call_offset(rest)?;
        return Ok((
            ItaniumVtableSlotRole::CovariantThunk,
            Some(this_adjustment),
            Some(return_adjustment),
        ));
    }
    Ok((ItaniumVtableSlotRole::Function, None, None))
}

fn parse_call_offset(value: &str) -> Result<(ItaniumThunkAdjustment, &str)> {
    if let Some(rest) = value.strip_prefix('h') {
        let (offset, rest) = parse_number(rest)?;
        let rest = rest
            .strip_prefix('_')
            .ok_or_else(|| Error::format("non-virtual call offset lacks terminator"))?;
        Ok((ItaniumThunkAdjustment::NonVirtual { offset }, rest))
    } else if let Some(rest) = value.strip_prefix('v') {
        let (offset, rest) = parse_number(rest)?;
        let rest = rest
            .strip_prefix('_')
            .ok_or_else(|| Error::format("virtual call offset lacks first separator"))?;
        let (virtual_offset, rest) = parse_number(rest)?;
        let rest = rest
            .strip_prefix('_')
            .ok_or_else(|| Error::format("virtual call offset lacks terminator"))?;
        Ok((
            ItaniumThunkAdjustment::Virtual {
                offset,
                virtual_offset,
            },
            rest,
        ))
    } else {
        Err(Error::format("unknown thunk call-offset discriminator"))
    }
}

fn parse_number(value: &str) -> Result<(i64, &str)> {
    let (negative, digits) = value
        .strip_prefix('n')
        .map_or((false, value), |rest| (true, rest));
    let length = digits.bytes().take_while(u8::is_ascii_digit).count();
    if length == 0 {
        return Err(Error::format("thunk adjustment lacks a number"));
    }
    let magnitude = digits[..length]
        .parse::<i64>()
        .map_err(|_| Error::format("thunk adjustment overflows Int64"))?;
    let number = if negative {
        magnitude
            .checked_neg()
            .ok_or_else(|| Error::format("thunk adjustment negation overflows"))?
    } else {
        magnitude
    };
    Ok((number, &digits[length..]))
}

pub(super) fn validate_slot_semantics(slot: &ItaniumVtableSlotRecord) -> Result<()> {
    let expected = classify_slot(slot.target_symbol.as_deref(), &slot.pointer.target)?;
    if (
        slot.role,
        slot.this_adjustment.clone(),
        slot.return_adjustment.clone(),
    ) != expected
    {
        return Err(Error::format(
            "strict vtable slot role disagrees with its target symbol",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_itanium_thunk_adjustments_and_destructor_roles() {
        let local = StrictPointerTarget::Local { va: 1 };
        assert_eq!(
            classify_slot(Some("__ZThn16_N1A1fEv"), &local).unwrap().1,
            Some(ItaniumThunkAdjustment::NonVirtual { offset: -16 })
        );
        assert_eq!(
            classify_slot(Some("__ZTvn8_n24_N1A1fEv"), &local)
                .unwrap()
                .1,
            Some(ItaniumThunkAdjustment::Virtual {
                offset: -8,
                virtual_offset: -24
            })
        );
        let covariant = classify_slot(Some("__ZTchn8_h16_N1A1fEv"), &local).unwrap();
        assert_eq!(
            covariant.1,
            Some(ItaniumThunkAdjustment::NonVirtual { offset: -8 })
        );
        assert_eq!(
            covariant.2,
            Some(ItaniumThunkAdjustment::NonVirtual { offset: 16 })
        );
        assert_eq!(
            classify_slot(Some("__ZN1AD0Ev"), &local).unwrap().0,
            ItaniumVtableSlotRole::DeletingDestructor
        );
        assert_eq!(
            classify_slot(Some("___cxa_pure_virtual"), &local)
                .unwrap()
                .0,
            ItaniumVtableSlotRole::PureVirtual
        );
        assert_eq!(
            classify_slot(Some("___cxa_deleted_virtual"), &local)
                .unwrap()
                .0,
            ItaniumVtableSlotRole::DeletedVirtual
        );
    }
}
