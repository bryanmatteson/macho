use crate::codesign::parse_code_signature;
use crate::model::mach::MachFile;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ResignPlan {
    pub was_signed: bool,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub had_entitlements: bool,
    pub had_cms_signature: bool,
    pub hash_type: Option<String>,
    pub suggested_command: String,
}

impl ResignPlan {
    pub fn from_mach(mach: &MachFile<'_>) -> Self {
        let sig = parse_code_signature(mach).ok();

        let (was_signed, identifier, team_id, had_entitlements, had_cms_signature, hash_type) =
            if let Some(ref s) = sig {
                let cd = s.code_directories().first();
                (
                    true,
                    cd.and_then(|c| c.identifier.map(|s| s.to_string())),
                    cd.and_then(|c| c.team_id.map(|s| s.to_string())),
                    s.entitlements_xml().is_some(),
                    s.cms_signature_present(),
                    cd.map(|c| c.hash_type.name().to_string()),
                )
            } else {
                (false, None, None, false, false, None)
            };

        let suggested_command = build_resign_command(identifier.as_deref(), had_entitlements);

        Self {
            was_signed,
            identifier,
            team_id,
            had_entitlements,
            had_cms_signature,
            hash_type,
            suggested_command,
        }
    }
}

fn build_resign_command(identifier: Option<&str>, had_entitlements: bool) -> String {
    let mut cmd = "codesign -f -s <identity>".to_string();
    if let Some(id) = identifier {
        cmd.push_str(&format!(" --identifier {id}"));
    }
    if had_entitlements {
        cmd.push_str(" --entitlements <entitlements.plist>");
    }
    cmd.push_str(" <binary>");
    cmd
}

impl std::fmt::Display for ResignPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.was_signed {
            return write!(f, "Binary was not signed; no re-signing needed.");
        }
        writeln!(f, "Re-sign assistance:")?;
        if let Some(ref id) = self.identifier {
            writeln!(f, "  Identifier: {id}")?;
        }
        if let Some(ref team) = self.team_id {
            writeln!(f, "  Team ID:    {team}")?;
        }
        if self.had_entitlements {
            writeln!(f, "  Entitlements were present (extract before patching)")?;
        }
        if let Some(ref ht) = self.hash_type {
            writeln!(f, "  Hash type:  {ht}")?;
        }
        writeln!(f, "  Command:    {}", self.suggested_command)
    }
}
