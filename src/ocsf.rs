use crate::graph::{Path, Summary};
use serde::{Deserialize, Serialize};

/// OCSF DetectionFindingEvent [2004]
/// Emitted when Zetra detects a behavioral attack pattern
#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionFindingEvent {
    pub class_uid: u32,
    pub activity_id: u32,
    pub severity_id: u32,
    pub finding_info: FindingInfo,
    pub metadata: Metadata,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingInfo {
    pub title: String,
    pub desc: String,
    pub uid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub product: Product,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Product {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

impl DetectionFindingEvent {
    /// Build a DetectionFindingEvent from a flagged path
    pub fn from_path(path: &Path, summary: &Summary) -> Self {
        let severity_id = if summary.bes > 0.5 { 3 } 
                         else if summary.bes > 0.2 { 2 } 
                         else { 1 };

        Self {
            class_uid: 2004,
            activity_id: 1,
            severity_id,
            finding_info: FindingInfo {
                title: "Behavioral attack pattern detected".to_string(),
                desc: format!(
                    "Path {} flagged: {} violations. BES score: {:.2}",
                    path.id,
                    path.flag_count,
                    summary.bes
                ),
                uid: format!("zetra-path-{}", path.id),
            },
            metadata: Metadata {
                product: Product {
                    name: "Zetra".to_string(),
                    vendor_name: "Zetra Security".to_string(),
                    version: "0.1.0".to_string(),
                },
            },
        }
    }

    /// Serialize to OCSF-compliant JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{}".to_string())
    }
}