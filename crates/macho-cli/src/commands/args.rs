//! Shared command-line argument authorities.

use std::path::PathBuf;

use clap::Args;
use macho::analysis::AnalysisLimits;

use super::OutputFormat;

/// One input file path shared by commands that inspect or mutate an image.
#[derive(Debug, Clone, Args)]
pub struct InputArgs {
    /// Path to the input file.
    pub path: PathBuf,
}

/// Optional positional input used only by commands that also expose nested actions.
#[derive(Debug, Clone, Default, Args)]
pub struct OptionalInputArgs {
    /// Optional path to the input file.
    pub path: Option<PathBuf>,
}

/// Optional architecture selection for thin/fat/file-set operations.
#[derive(Debug, Clone, Default, Args)]
pub struct ArchitectureArgs {
    /// Select one architecture name, such as `arm64`, `arm64e`, or `x86_64`.
    #[arg(long)]
    pub arch: Option<String>,
}

/// Global machine/human output selection.
#[derive(Debug, Clone, Copy, Args)]
pub struct FormatArgs {
    /// Select the output representation.
    #[arg(long, value_enum, global = true, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

/// Bounded collection/decode limits shared by selective-analysis commands.
#[derive(Debug, Clone, Args)]
pub struct AnalysisLimitArgs {
    /// Maximum strings retained per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_strings_per_slice)]
    pub max_strings: usize,
    /// Maximum cross-references retained per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_xrefs_per_slice)]
    pub max_xrefs: usize,
    /// Maximum address ranges retained per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_ranges_per_slice)]
    pub max_ranges: usize,
    /// Maximum virtual tables retained per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_vtables_per_slice)]
    pub max_vtables: usize,
    /// Maximum decoded bytes inspected per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_decoded_bytes_per_slice)]
    pub max_decoded_bytes: usize,
    /// Maximum issues retained for one domain.
    #[arg(long, default_value_t = AnalysisLimits::default().max_issues_per_domain)]
    pub max_issues: usize,
}

impl Default for AnalysisLimitArgs {
    fn default() -> Self {
        let limits = AnalysisLimits::default();
        Self {
            max_strings: limits.max_strings_per_slice,
            max_xrefs: limits.max_xrefs_per_slice,
            max_ranges: limits.max_ranges_per_slice,
            max_vtables: limits.max_vtables_per_slice,
            max_decoded_bytes: limits.max_decoded_bytes_per_slice,
            max_issues: limits.max_issues_per_domain,
        }
    }
}

impl From<&AnalysisLimitArgs> for AnalysisLimits {
    fn from(args: &AnalysisLimitArgs) -> Self {
        Self {
            max_strings_per_slice: args.max_strings,
            max_xrefs_per_slice: args.max_xrefs,
            max_ranges_per_slice: args.max_ranges,
            max_vtables_per_slice: args.max_vtables,
            max_decoded_bytes_per_slice: args.max_decoded_bytes,
            max_issues_per_domain: args.max_issues,
        }
    }
}
