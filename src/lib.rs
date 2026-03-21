//! zetra-openshell
//! Behavioral security layer for NVIDIA OpenShell
//!
//! OpenShell is the enforcement plane.
//! Zetra is the detection plane.
//! The OCSF stream is the interface between them.

pub mod graph;
pub mod patterns;
pub mod monitor;
pub mod enforce;
pub mod ocsf;