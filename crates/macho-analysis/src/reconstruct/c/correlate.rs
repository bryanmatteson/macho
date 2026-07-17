/// One caller-supplied header source used for pure correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSource {
    /// The path field.
    pub path: String,
    /// The contents field.
    pub contents: String,
}

/// Pure correlation extension point; implementations receive and mutate only
/// owned analysis data.
pub trait HeaderCorrelator {
    /// Performs correlate.
    fn correlate(&self, analysis: &mut CAnalysis) -> Result<()>;
}

/// Deterministic correlator over caller-supplied source documents.
#[derive(Debug, Clone, Default)]
pub struct InMemoryHeaderCorrelator {
    sources: Vec<HeaderSource>,
}

impl InMemoryHeaderCorrelator {
    /// Performs new.
    pub fn new(mut sources: Vec<HeaderSource>) -> Self {
        sources.sort_by(|left, right| left.path.cmp(&right.path));
        Self { sources }
    }
}

impl HeaderCorrelator for InMemoryHeaderCorrelator {
    fn correlate(&self, analysis: &mut CAnalysis) -> Result<()> {
        let mut seen = BTreeSet::new();
        for header in &self.sources {
            correlate_named_items(
                &header.path,
                &header.contents,
                analysis
                    .functions
                    .iter_mut()
                    .map(|item| (&item.name, &mut item.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header.path,
                &header.contents,
                analysis
                    .globals
                    .iter_mut()
                    .map(|item| (&item.name, &mut item.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header.path,
                &header.contents,
                analysis
                    .typedefs
                    .iter_mut()
                    .map(|item| (&item.name, &mut item.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header.path,
                &header.contents,
                analysis
                    .records
                    .iter_mut()
                    .map(|item| (&item.name, &mut item.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
            correlate_named_items(
                &header.path,
                &header.contents,
                analysis
                    .enums
                    .iter_mut()
                    .map(|item| (&item.name, &mut item.evidence)),
                &mut analysis.correlated_headers,
                &mut seen,
            );
        }
        Ok(())
    }
}

fn correlate_named_items<'a, I>(
    header_path: &str,
    contents: &str,
    items: I,
    matches: &mut Vec<HeaderCorrelationMatch>,
    seen: &mut BTreeSet<(String, String)>,
) where
    I: IntoIterator<Item = (&'a String, &'a mut Vec<EvidenceFact>)>,
{
    for (name, evidence) in items {
        if !contains_identifier(contents, name) {
            continue;
        }
        let key = (header_path.to_owned(), name.clone());
        if !seen.insert(key) {
            continue;
        }
        evidence.push(EvidenceFact {
            kind: EvidenceKind::HeaderMatch,
            confidence: Confidence::Correlated,
            detail: format!("matched symbol name in header {header_path}"),
        });
        matches.push(HeaderCorrelationMatch {
            path: header_path.to_owned(),
            symbol: name.clone(),
            confidence: Confidence::Correlated,
        });
    }
}

fn contains_identifier(contents: &str, needle: &str) -> bool {
    contents.match_indices(needle).any(|(index, _)| {
        let before = contents[..index].chars().next_back();
        let after = contents[index + needle.len()..].chars().next();
        is_boundary(before) && is_boundary(after)
    })
}

fn is_boundary(character: Option<char>) -> bool {
    character.is_none_or(|character| !(character.is_ascii_alphanumeric() || character == '_'))
}
