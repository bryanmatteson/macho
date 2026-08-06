//! Emit deterministic whole-program recovery receipts for the macOS system gate.

#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use macho::analysis::control_flow::{
    ControlFlowContinuation, ControlFlowExitKind, FunctionControlFlowStatus,
};
#[cfg(target_os = "macos")]
use macho::analysis::exception_index::ExceptionIndexStatus;
#[cfg(target_os = "macos")]
use macho::analysis::functions::FunctionEntryCandidateDisposition;
#[cfg(target_os = "macos")]
use macho::analysis::program::{ProgramRecoveryLimits, ProgramRecoveryStatus, RecoveredProgram};
#[cfg(target_os = "macos")]
use macho::analysis::recovery::RecoveryQuestionKind;
#[cfg(target_os = "macos")]
use serde::Serialize;

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct CorpusReceipt {
    path: String,
    cpu_type: i32,
    cpu_subtype: i32,
    limits: ProgramRecoveryLimits,
    recovered_functions: usize,
    candidate_entries: usize,
    rejected_entries: usize,
    functions_with_uncertain_extents: usize,
    function_conflicts: usize,
    recovered_jump_table_observations: usize,
    recovered_jump_tables: usize,
    recovered_jump_table_entries: usize,
    range_bounded_jump_tables: usize,
    unresolved_range_jump_tables: usize,
    executable_bytes_observed: u64,
    executable_bytes_classified: u64,
    executable_bytes_unresolved: u64,
    recovery_questions: usize,
    byte_role_questions: usize,
    imported_non_returning_calls: usize,
    local_non_returning_calls: usize,
    control_flow_complete_functions: usize,
    control_flow_partial_functions: usize,
    jump_table_dispatches: usize,
    tail_dispatches: usize,
    unresolved_indirect_branches: usize,
    control_flow_observed_bytes: u64,
    control_flow_instruction_bytes: u64,
    control_flow_data_bytes: u64,
    control_flow_gap_bytes: u64,
    control_flow_omitted_bytes: u64,
    exception_status: ExceptionIndexStatus,
    exception_function_records: usize,
    exception_call_sites: usize,
    exception_actions: usize,
    exception_cfi_rows: usize,
    local_exceptional_transfers: usize,
    outward_exceptional_transfers: usize,
    indirect_value_flow_work: u64,
    indirect_value_flow_truncated: bool,
    indirect_value_flow_widened: bool,
    control_flow_continuation: Option<ControlFlowContinuation>,
    overall_status: ProgramRecoveryStatus,
    wall_ceiling_millis: u64,
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths = {
        let supplied = std::env::args().skip(1).collect::<Vec<_>>();
        if supplied.is_empty() {
            vec!["/bin/ls".to_owned(), "/usr/bin/file".to_owned()]
        } else {
            supplied
        }
    };
    let limits = ProgramRecoveryLimits::default();
    let mut receipts = Vec::new();
    for path in paths {
        let bytes = std::fs::read(&path)?;
        let container = macho::core::parse(&bytes)?;
        for macho in container.macho_files() {
            let started = Instant::now();
            let program = RecoveredProgram::recover_all(macho, limits)?;
            let elapsed = started.elapsed();
            if elapsed >= Duration::from_secs(10) {
                return Err(format!(
                    "recovery exceeded 10 seconds for {path} CPU {:#x}/{:#x}: {elapsed:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                )
                .into());
            }
            let functions = program.functions().expect("recover_all selects functions");
            let executable = program
                .executable_bytes()
                .expect("recover_all selects executable bytes")
                .completeness();
            let control_flow = program
                .control_flow()
                .expect("recover_all selects control flow");
            let indirect = program
                .indirect_calls()
                .expect("recover_all selects indirect calls")
                .completeness();
            let exceptions = program
                .exceptions()
                .expect("recover_all selects exception evidence");
            let jump_table_observations = control_flow
                .functions()
                .iter()
                .flat_map(|graph| graph.jump_tables.iter())
                .collect::<Vec<_>>();
            let mut jump_tables = BTreeMap::new();
            for table in &jump_table_observations {
                jump_tables
                    .entry((table.instruction_address, table.table_address))
                    .or_insert(*table);
            }
            if indirect.value_flow_truncated {
                return Err(format!(
                    "value flow exhausted {} work units for {path} CPU {:#x}/{:#x}",
                    indirect.value_flow_work,
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                )
                .into());
            }
            receipts.push(CorpusReceipt {
                path: path.clone(),
                cpu_type: macho.header().cpu_type().0,
                cpu_subtype: macho.header().cpu_subtype().0,
                limits,
                recovered_functions: functions.functions().len(),
                candidate_entries: functions.entry_candidates().len(),
                rejected_entries: functions
                    .entry_candidates()
                    .iter()
                    .filter(|candidate| {
                        matches!(
                            candidate.disposition,
                            FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
                                | FunctionEntryCandidateDisposition::RejectedByCaller
                                | FunctionEntryCandidateDisposition::RejectedRecoveredData
                                | FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
                        )
                    })
                    .count(),
                functions_with_uncertain_extents: functions
                    .functions()
                    .iter()
                    .filter(|function| !function.completeness.extent_is_authoritative)
                    .count(),
                function_conflicts: functions
                    .functions()
                    .iter()
                    .map(|function| function.conflicts.len())
                    .sum(),
                recovered_jump_table_observations: jump_table_observations.len(),
                recovered_jump_tables: jump_tables.len(),
                recovered_jump_table_entries: jump_tables
                    .values()
                    .map(|table| table.entries.len())
                    .sum(),
                range_bounded_jump_tables: jump_tables
                    .values()
                    .filter(|table| table.range.is_some())
                    .count(),
                unresolved_range_jump_tables: jump_tables
                    .values()
                    .filter(|table| table.range.is_none())
                    .count(),
                executable_bytes_observed: executable.observed_bytes,
                executable_bytes_classified: executable.classified_bytes,
                executable_bytes_unresolved: executable.unresolved_bytes,
                recovery_questions: program.questions().len(),
                byte_role_questions: program
                    .questions()
                    .iter()
                    .filter(|question| question.kind == RecoveryQuestionKind::ByteRole)
                    .count(),
                imported_non_returning_calls: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.calls.iter())
                    .filter(|call| call.non_returning_symbol.is_some())
                    .count(),
                local_non_returning_calls: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.calls.iter())
                    .filter(|call| call.non_returning_callee.is_some())
                    .count(),
                control_flow_complete_functions: control_flow
                    .functions()
                    .iter()
                    .filter(|graph| {
                        graph.completeness.status == FunctionControlFlowStatus::Complete
                    })
                    .count(),
                control_flow_partial_functions: control_flow
                    .functions()
                    .iter()
                    .filter(|graph| graph.completeness.status == FunctionControlFlowStatus::Partial)
                    .count(),
                jump_table_dispatches: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.exits.iter())
                    .filter(|exit| exit.kind == ControlFlowExitKind::JumpTableDispatch)
                    .count(),
                tail_dispatches: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.exits.iter())
                    .filter(|exit| exit.kind == ControlFlowExitKind::TailDispatch)
                    .count(),
                unresolved_indirect_branches: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.exits.iter())
                    .filter(|exit| exit.kind == ControlFlowExitKind::IndirectBranch)
                    .count(),
                control_flow_observed_bytes: control_flow
                    .functions()
                    .iter()
                    .map(|graph| graph.completeness.observed_bytes)
                    .sum(),
                control_flow_instruction_bytes: control_flow
                    .functions()
                    .iter()
                    .map(|graph| graph.completeness.instruction_bytes)
                    .sum(),
                control_flow_data_bytes: control_flow
                    .functions()
                    .iter()
                    .map(|graph| graph.completeness.data_bytes)
                    .sum(),
                control_flow_gap_bytes: control_flow
                    .functions()
                    .iter()
                    .map(|graph| graph.completeness.gap_bytes)
                    .sum(),
                control_flow_omitted_bytes: control_flow
                    .functions()
                    .iter()
                    .map(|graph| graph.completeness.omitted_bytes)
                    .sum(),
                exception_status: exceptions.status(),
                exception_function_records: exceptions.records().len(),
                exception_call_sites: exceptions.call_sites().len(),
                exception_actions: exceptions
                    .call_sites()
                    .iter()
                    .map(|record| record.actions.len())
                    .sum(),
                exception_cfi_rows: exceptions.cfi_rows().len(),
                local_exceptional_transfers: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.exceptional_transfers.iter())
                    .filter(|transfer| transfer.landing_pad.is_some())
                    .count(),
                outward_exceptional_transfers: control_flow
                    .functions()
                    .iter()
                    .flat_map(|graph| graph.exceptional_transfers.iter())
                    .filter(|transfer| transfer.landing_pad.is_none())
                    .count(),
                indirect_value_flow_work: indirect.value_flow_work,
                indirect_value_flow_truncated: indirect.value_flow_truncated,
                indirect_value_flow_widened: indirect.value_flow_widened,
                control_flow_continuation: control_flow.continuation().cloned(),
                overall_status: program.completeness().status,
                wall_ceiling_millis: 10_000,
            });
        }
    }
    receipts.sort_by(|left, right| {
        (&left.path, left.cpu_type, left.cpu_subtype).cmp(&(
            &right.path,
            right.cpu_type,
            right.cpu_subtype,
        ))
    });
    serde_json::to_writer_pretty(std::io::stdout().lock(), &receipts)?;
    println!();
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("system_corpus_receipt requires macOS system binaries");
}
