include!("container.rs");
include!("structure.rs");
include!("symbols.rs");
include!("metadata.rs");
include!("semantic.rs");
include!("diagnostics.rs");
include!("report.rs");
mod document;

pub use document::diff_documents;

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::dyld::imports::ImportRecord;
use crate::analysis::snapshot::*;
