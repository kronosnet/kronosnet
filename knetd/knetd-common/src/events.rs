//! Event types for async notifications from daemon to CLI.
//!
//! These events are broadcast from the daemon to subscribed CLI clients
//! when significant state changes occur (links up/down, hosts reachable/unreachable, etc.)

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{InstanceName, HostId, LinkId};

/// Events that can be emitted by the daemon and subscribed to by CLI clients.
///
/// Uses tagged enum serialization so JSON consumers can discriminate on the "type" field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonEvent {
    /// A link's connection status changed (up/down).
    LinkStatusChange {
        instance: InstanceName,
        host_id: HostId,
        link_id: LinkId,
        /// True if link is connected (receiving heartbeats)
        connected: bool,
        /// True if this is a remote link (not locally configured)
        remote: bool,
        /// True if link was configured externally
        external: bool,
        timestamp: DateTime<Utc>,
    },
    /// A host's reachability status changed.
    HostStatusChange {
        instance: InstanceName,
        host_id: HostId,
        /// True if at least one link to this host is connected
        reachable: bool,
        /// True if connected via another host (multi-hop)
        remote: bool,
        /// True if host was configured externally
        external: bool,
        timestamp: DateTime<Utc>,
    },
    /// Path MTU Discovery detected a new MTU.
    PmtudNotify {
        instance: InstanceName,
        /// New MTU size in bytes
        mtu: u32,
        timestamp: DateTime<Utc>,
    },
    /// On-wire protocol version changed (version negotiation with peers).
    OnwireVerChange {
        instance: InstanceName,
        min_ver: u8,
        max_ver: u8,
        ver: u8,
        timestamp: DateTime<Utc>,
    },
    /// A log message from the libknet library.
    LogMessage {
        instance: InstanceName,
        level: String,
        subsystem: String,
        message: String,
        timestamp: DateTime<Utc>,
    },
}
