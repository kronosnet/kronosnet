//! # knetd-common
//!
//! Shared types and message definitions used by both the knetd daemon and knetctl CLI.
//!
//! This crate provides:
//! - Type-safe wrappers around primitive types (HostId, LinkId, etc.)
//! - RPC request/response message definitions for JSON-RPC 2.0
//! - Event types for async notifications from daemon to CLI

pub mod types;
pub mod rpc;
pub mod events;

// Re-export everything so consumers can use `use knetd_common::*`
pub use types::*;
pub use rpc::*;
pub use events::*;
