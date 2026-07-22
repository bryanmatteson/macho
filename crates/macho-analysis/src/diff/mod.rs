include!("container.rs");
include!("structure.rs");
include!("symbols.rs");
include!("metadata.rs");
include!("diagnostics.rs");
include!("report.rs");
mod document;

pub use document::diff_documents;

use std::collections::{BTreeMap, BTreeSet};

use crate::dyld::imports::ImportRecord;
use crate::snapshot::*;
