use serde::{Deserialize, Serialize};

/// A node in the behavioral graph
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphNode {
    pub id: String,
}

/// An edge between two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub conditional: bool,
}

/// A flag raised when anomalous behavior is detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flag {
    pub rule: String,
    pub detail: String,
}

/// A single execution path through the agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Path {
    pub id: u32,
    pub intended_nodes: Vec<String>,
    pub actual_nodes: Vec<String>,
    pub tool_calls: Vec<String>,
    pub question: String,
    pub intended_tool_cycles: u32,
    pub actual_tool_call_count: u32,
    pub category: PathCategory,
    pub flags: Vec<Flag>,
    pub flag_count: u32,
    pub outlier: bool,
    pub outlier_score: f64,
    pub feature_vector: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PathCategory {
    Benign,
    Unintended,
    Malicious,
}

/// Summary of behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub total_paths: u32,
    pub benign: u32,
    pub unintended: u32,
    pub malicious: u32,
    pub bes: f64,
}

/// The behavioral graph for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<GraphEdge>,
}

impl BehavioralGraph {
    pub fn new(nodes: Vec<String>, edges: Vec<GraphEdge>) -> Self {
        Self { nodes, edges }
    }
}