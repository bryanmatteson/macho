use crate::metadata::codesign::CodeSignature;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
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
    pub signature_parse_error: Option<String>,
    pub suggested_command: String,
    pub manual_steps: Vec<String>,
}

impl ResignPlan {
    pub fn from_mach(macho: &MachoFile<'_>) -> Self {
        let has_signature_load_command = macho
            .load_commands()
            .iter()
            .any(|lc| matches!(lc.kind, LoadCommand::CodeSignature(_)));
        let sig = macho.ext::<CodeSignature<'_>>();

        let (
            was_signed,
            identifier,
            team_id,
            entitlements_xml,
            entitlements_der_present,
            has_cms_signature,
            hash_type,
            signature_parse_error,
        ) = if let Ok(ref s) = sig {
            let cd = s.code_directories().first();
            (
                true,
                cd.and_then(|c| c.identifier.map(|s| s.to_string())),
                cd.and_then(|c| c.team_id.map(|s| s.to_string())),
                s.entitlements_xml().map(|s| s.to_string()),
                s.entitlements_der().is_some(),
                s.cms_signature_present(),
                cd.map(|c| c.hash_type.name().to_string()),
                None,
            )
        } else if has_signature_load_command {
            (
                true,
                None,
                None,
                None,
                false,
                false,
                None,
                sig.err().map(|err| err.to_string()),
            )
        } else {
            (false, None, None, None, false, false, None, None)
        };

        let has_entitlements = entitlements_xml.is_some() || entitlements_der_present;
        let suggested_command =
            build_resign_command(identifier.as_deref(), entitlements_xml.is_some());
        let manual_steps = build_manual_steps(
            entitlements_xml.is_some(),
            entitlements_der_present,
            signature_parse_error.as_deref(),
        );

        Self {
            was_signed,
            identifier,
            team_id,
            has_entitlements,
            entitlements_xml,
            entitlements_der_present,
            has_cms_signature,
            hash_type,
            signature_parse_error,
            suggested_command,
            manual_steps,
        }
    }
}

fn build_resign_command(identifier: Option<&str>, has_xml_entitlements: bool) -> String {
    let mut cmd = "codesign -f -s <identity>".to_string();
    if let Some(id) = identifier {
        cmd.push_str(&format!(" --identifier {id}"));
    }
    if has_xml_entitlements {
        cmd.push_str(" --entitlements <entitlements.plist>");
    }
    cmd.push_str(" <binary>");
    cmd
}

fn build_manual_steps(
    has_xml_entitlements: bool,
    has_der_entitlements: bool,
    signature_parse_error: Option<&str>,
) -> Vec<String> {
    let mut steps = Vec::new();

    if has_xml_entitlements {
        steps.push(
            "Extract the embedded XML entitlements into a plist before re-signing.".to_string(),
        );
    } else if has_der_entitlements {
        steps.push(
            "Original signature carries DER entitlements only; export or reconstruct a plist if entitlements must be preserved."
                .to_string(),
        );
    }

    if signature_parse_error.is_some() {
        steps.push(
            "Inspect the original LC_CODE_SIGNATURE before patching if identifier, entitlements, or CMS state must be preserved."
                .to_string(),
        );
    }

    steps
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
        if let Some(ref err) = self.signature_parse_error {
            writeln!(f, "  Signature parse error: {err}")?;
        }
        if self.has_cms_signature {
            writeln!(f, "  CMS signature present")?;
        }
        writeln!(f, "  Command:    {}", self.suggested_command)?;
        for step in &self.manual_steps {
            writeln!(f, "  Note:       {step}")?;
        }
        Ok(())
    }
}
