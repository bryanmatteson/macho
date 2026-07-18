use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::num::NonZeroUsize;

use macho::analysis::disassembly::{
    DecodeMode, DisassemblyRequest, DisassemblySelection, SliceSelection, disassemble,
};
use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer};
use macho::core::{ParseLimits, ParseMode, ParseOptions};
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

criterion_group!(
    benches,
    parsing,
    selective_analysis,
    reconstruction_and_diff,
    bounded_disassembly,
    patch_preview
);
criterion_main!(benches);
