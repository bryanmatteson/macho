use crate::codesign::parse_code_signature;
use crate::model::mach::MachFile;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ResignPlan {
    pub was_signed: bool,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub has_entitlements: bool,
    pub entitlements_xml: Option<String>,
    pub entitlements_der_present: bool,
    pub has_cms_signature: bool,
    pub hash_type: Option<String>,
    pub suggested_command: String,
}

impl ResignPlan {
    pub fn from_mach(mach: &MachFile<'_>) -> Self {
        let sig = parse_code_signature(mach).ok();

        let (
            was_signed,
            identifier,
            team_id,
            entitlements_xml,
            entitlements_der_present,
            has_cms_signature,
            hash_type,
        ) = if let Some(ref s) = sig {
            let cd = s.code_directories().first();
            (
                true,
                cd.and_then(|c| c.identifier.map(|s| s.to_string())),
                cd.and_then(|c| c.team_id.map(|s| s.to_string())),
                s.entitlements_xml().map(|s| s.to_string()),
                s.entitlements_der().is_some(),
                s.cms_signature_present(),
                cd.map(|c| c.hash_type.name().to_string()),
            )
        } else {
            (false, None, None, None, false, false, None)
        };

        let has_entitlements = entitlements_xml.is_some() || entitlements_der_present;
        let suggested_command = build_resign_command(identifier.as_deref(), has_entitlements);

        Self {
            was_signed,
            identifier,
            team_id,
            has_entitlements,
            entitlements_xml,
            entitlements_der_present,
            has_cms_signature,
            hash_type,
            suggested_command,
        }
    }
}

fn build_resign_command(identifier: Option<&str>, has_entitlements: bool) -> String {
    let mut cmd = "codesign -f -s <identity>".to_string();
    if let Some(id) = identifier {
        cmd.push_str(&format!(" --identifier {id}"));
    }
    if has_entitlements {
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
        if self.has_entitlements {
            if let Some(xml) = &self.entitlements_xml {
                writeln!(f, "  Entitlements: XML present ({} bytes)", xml.len())?;
            } else if self.entitlements_der_present {
                writeln!(f, "  Entitlements: DER present")?;
            } else {
                writeln!(f, "  Entitlements were present (extract before patching)")?;
            }
        }
        if let Some(ref ht) = self.hash_type {
            writeln!(f, "  Hash type:  {ht}")?;
        }
        if self.has_cms_signature {
            writeln!(f, "  CMS signature present")?;
        }
        writeln!(f, "  Command:    {}", self.suggested_command)
    }
}
