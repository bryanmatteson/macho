use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::num::NonZeroUsize;

use macho::analysis::disassembly::{
    DecodeMode, DisassemblyRequest, DisassemblySelection, SliceSelection, disassemble,
};
use macho::analysis::program::{ProgramRecoveryLimits, RecoveredProgram};
use macho::analysis::recovery::{RecoveryAddressRange, RecoveryGuide};
use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer};
use macho::core::{ParseLimits, ParseMode, ParseOptions};
use macho::insn::{
    Arch, X86EncodeFields, decode_one, encode_arm64_fixed, encode_x86_form, identify_encoding,
};
use macho::mutate::{PatchOp, PatchPlan, PatchTransaction};
use macho_test_support::{CPU_TYPE_ARM64, fat32, thin64_arm64};

fn fixtures() -> (Vec<u8>, Vec<u8>) {
    let thin = thin64_arm64(2);
    let fat = fat32(&[
        (CPU_TYPE_ARM64, 0, thin.clone()),
        (CPU_TYPE_ARM64, 2, thin.clone()),
    ]);
    (thin, fat)
}

fn parsing(c: &mut Criterion) {
    let (thin, fat) = fixtures();
    let mut group = c.benchmark_group("parse_and_validate");
    for (name, bytes) in [("thin", thin), ("fat", fat)] {
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::new("strict", name), &bytes, |b, bytes| {
            b.iter(|| macho::parse(std::hint::black_box(bytes)))
        });
        group.bench_with_input(BenchmarkId::new("forensic", name), &bytes, |b, bytes| {
            let options = ParseOptions {
                mode: ParseMode::Forensic,
                limits: ParseLimits::default(),
            };
            b.iter(|| macho::parse_with_options(std::hint::black_box(bytes), &options))
        });
    }
    group.finish();
}

fn selective_analysis(c: &mut Criterion) {
    let (thin, _) = fixtures();
    let container = macho::parse(&thin).expect("fixture parses");
    let selective = AnalysisPlan::new([AnalysisDomain::Header, AnalysisDomain::Segments]);
    let full = AnalysisPlan::all();
    let mut group = c.benchmark_group("analysis");
    group.bench_function("selective_snapshot", |b| {
        b.iter(|| Analyzer.run(std::hint::black_box(&container), &selective))
    });
    group.bench_function("full_snapshot", |b| {
        b.iter(|| Analyzer.run(std::hint::black_box(&container), &full))
    });
    group.bench_function("xref_construction", |b| {
        let plan = AnalysisPlan::new([AnalysisDomain::Xrefs]);
        b.iter(|| Analyzer.run(std::hint::black_box(&container), &plan))
    });
    group.finish();
}

fn reconstruction_and_diff(c: &mut Criterion) {
    let (thin, _) = fixtures();
    let container = macho::parse(&thin).expect("fixture parses");
    let plan = AnalysisPlan::new([
        AnalysisDomain::CSurface,
        AnalysisDomain::CppSurface,
        AnalysisDomain::Header,
    ]);
    let document = Analyzer.run(&container, &plan).expect("fixture analyzes");
    let mut group = c.benchmark_group("semantic");
    group.bench_function("c_cpp_reconstruction", |b| {
        b.iter(|| Analyzer.run(std::hint::black_box(&container), &plan))
    });
    group.bench_function("semantic_diff", |b| {
        b.iter(|| {
            macho::analysis::diff::diff_documents(
                std::hint::black_box(&document),
                &document,
                plan.domains(),
            )
        })
    });
    group.finish();
}

fn bounded_disassembly(c: &mut Criterion) {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho::parse(&bytes).expect("fixture parses");
    let request = DisassemblyRequest::new(
        SliceSelection::All,
        DisassemblySelection::ExecutableSections,
        DecodeMode::Recovering,
        false,
        NonZeroUsize::new(64).expect("non-zero"),
        NonZeroUsize::new(16).expect("non-zero"),
    )
    .expect("valid benchmark request");
    c.bench_function("bounded_disassembly", |b| {
        b.iter(|| disassemble(std::hint::black_box(&container), &request))
    });
}

fn incremental_control_flow(c: &mut Criterion) {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho::parse(&bytes).expect("fixture parses");
    let image = container.first_macho().expect("fixture has image");
    let base = RecoveredProgram::recover_all(image, ProgramRecoveryLimits::default())
        .expect("fixture recovers");
    let functions = base.functions().expect("full recovery selects functions");
    assert!(
        functions.functions().len() > 1,
        "fixture must contain multiple recovered functions"
    );
    let selected = functions
        .functions()
        .first()
        .expect("fixture has a recovered function");
    let extent = selected.extent.expect("fixture function has an extent");
    let guide = RecoveryGuide::builder(base.image().clone())
        .function_ranges(
            selected.entry,
            vec![
                RecoveryAddressRange::new(extent.start, extent.end_exclusive)
                    .expect("fixture extent is non-empty"),
            ],
        )
        .expect("fixture range is valid guidance")
        .build();
    let cold = RecoveredProgram::recover_with_guide(image, base.request().clone(), &guide)
        .expect("cold guided recovery");
    let warm = RecoveredProgram::refine(image, &base, &guide).expect("warm guided refinement");
    assert_eq!(warm, cold, "warm refinement must preserve cold truth");
    assert!(
        base.control_flow()
            .unwrap()
            .functions()
            .iter()
            .zip(warm.control_flow().unwrap().functions())
            .any(|(before, after)| before == after),
        "fixture must retain at least one unaffected function graph"
    );

    let mut group = c.benchmark_group("incremental_control_flow");
    group.bench_function("cold_recover_with_guide", |b| {
        b.iter(|| {
            RecoveredProgram::recover_with_guide(
                std::hint::black_box(image),
                base.request().clone(),
                std::hint::black_box(&guide),
            )
        })
    });
    group.bench_function("warm_refine_from_retained_base", |b| {
        b.iter(|| {
            RecoveredProgram::refine(
                std::hint::black_box(image),
                std::hint::black_box(&base),
                std::hint::black_box(&guide),
            )
        })
    });
    group.finish();
}

fn patch_preview(c: &mut Criterion) {
    let (thin, _) = fixtures();
    let container = macho::parse(&thin).expect("fixture parses");
    let image = container.first_macho().expect("fixture has image");
    let plan = PatchPlan::new(vec![PatchOp::PatchBytes {
        offset: 0,
        bytes: Vec::new(),
    }]);
    c.bench_function("structural_patch_preview", |b| {
        b.iter(|| {
            let mut transaction = PatchTransaction::new(std::hint::black_box(image));
            for operation in plan.operations() {
                transaction.add_op(operation.clone());
            }
            transaction.preview()
        })
    });
    c.bench_function("semantic_patch_preview", |b| {
        let analysis = AnalysisPlan::new([AnalysisDomain::Header]);
        b.iter(|| macho::workflow::execute(std::hint::black_box(&thin), &plan, &analysis, None))
    });
}

fn instruction_codecs(c: &mut Criterion) {
    let x86_nop = [0x90];
    let arm64_nop = 0xD503_201Fu32.to_le_bytes();
    let x86_form = identify_encoding(&x86_nop, Arch::X86_64)
        .expect("generated x86 NOP")
        .form_index
        .expect("x86 form index");
    let arm64_id = identify_encoding(&arm64_nop, Arch::Arm64)
        .expect("generated ARM64 NOP")
        .encoding_id;

    let mut group = c.benchmark_group("instruction_codecs");
    group.bench_function("x86_generated_identity", |b| {
        b.iter(|| identify_encoding(std::hint::black_box(&x86_nop), Arch::X86_64))
    });
    group.bench_function("x86_semantic_decode", |b| {
        b.iter(|| decode_one(std::hint::black_box(&x86_nop), 0x1000, Arch::X86_64))
    });
    group.bench_function("x86_generated_encode", |b| {
        b.iter(|| encode_x86_form(x86_form, std::hint::black_box(X86EncodeFields::default())))
    });
    group.bench_function("arm64_generated_identity", |b| {
        b.iter(|| identify_encoding(std::hint::black_box(&arm64_nop), Arch::Arm64))
    });
    group.bench_function("arm64_semantic_decode", |b| {
        b.iter(|| decode_one(std::hint::black_box(&arm64_nop), 0x1000, Arch::Arm64))
    });
    group.bench_function("arm64_generated_encode", |b| {
        b.iter(|| encode_arm64_fixed(std::hint::black_box(arm64_id)))
    });
    group.finish();
}

criterion_group!(
    benches,
    parsing,
    selective_analysis,
    reconstruction_and_diff,
    bounded_disassembly,
    incremental_control_flow,
    patch_preview,
    instruction_codecs
);
criterion_main!(benches);
