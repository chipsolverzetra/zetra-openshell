use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A rule for detecting anomalous behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    pub name: String,
    pub description: String,
    pub max_allowed_calls: Option<u32>,
}

/// Built-in attack patterns based on real agent behavior
pub fn default_rules() -> HashMap<String, PatternRule> {
    let mut rules = HashMap::new();

    rules.insert(
        "loop_abuse".to_string(),
        PatternRule {
            name: "loop_abuse".to_string(),
            description: "Tool called more times than intended".to_string(),
            max_allowed_calls: Some(3),
        },
    );

    rules.insert(
        "tool_sequence_violation".to_string(),
        PatternRule {
            name: "tool_sequence_violation".to_string(),
            description: "Tools called in unexpected sequence".to_string(),
            max_allowed_calls: None,
        },
    );

    rules
}