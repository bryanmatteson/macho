/// The graph module.
pub mod graph;
/// The render module.
pub mod render;

pub use graph::{
    AllMethods, ClassNode, MethodEntry, MethodKind, MethodOrigin, MethodResolution, ObjCGraph,
    PropertyEntry, ProtocolNode, ResolvedMethod, SelectorOwner,
};

use serde::Serialize;

use crate::analysis::Result;
use crate::analysis::core::MachoFile;

/// Explicit configuration for Objective-C header reconstruction.
#[derive(Debug, Clone, Default)]
pub struct ObjcReconstructionPlan {
    /// Optional exact class name; matching categories are retained with it.
    pub class_filter: Option<String>,
}

/// Typed output from Objective-C header reconstruction.
#[derive(Debug, Clone, Serialize)]
pub struct ObjcReconstructionReport {
    /// Rendered class, category, and protocol declarations.
    pub header: String,
    /// Number of rendered class declarations.
    pub classes: usize,
    /// Number of rendered category declarations.
    pub categories: usize,
    /// Number of rendered protocol declarations.
    pub protocols: usize,
}

/// Reconstruct Objective-C declarations according to an explicit plan.
pub fn reconstruct(
    macho: &MachoFile<'_>,
    plan: &ObjcReconstructionPlan,
) -> Result<ObjcReconstructionReport> {
    let metadata = crate::metadata::objc::parse_objc_metadata(macho)?;
    let classes = metadata
        .classes
        .iter()
        .filter(|class| {
            plan.class_filter
                .as_ref()
                .is_none_or(|filter| class.name == *filter)
        })
        .collect::<Vec<_>>();
    let categories = metadata
        .categories
        .iter()
        .filter(|category| {
            plan.class_filter
                .as_ref()
                .is_none_or(|filter| category.class_name == *filter)
        })
        .collect::<Vec<_>>();
    let protocols = if plan.class_filter.is_none() {
        metadata.protocols.iter().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut header = String::new();
    for class in &classes {
        header.push_str(&render::render_class_header(class));
        header.push('\n');
    }
    for protocol in &protocols {
        header.push_str(&render::render_protocol_header(protocol));
        header.push('\n');
    }
    for category in &categories {
        header.push_str(&render::render_category_header(category));
        header.push('\n');
    }
    Ok(ObjcReconstructionReport {
        header,
        classes: classes.len(),
        categories: categories.len(),
        protocols: protocols.len(),
    })
}
