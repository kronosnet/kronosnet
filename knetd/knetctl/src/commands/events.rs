//! Event watching commands.
//!
//! Commands for subscribing to and monitoring real-time events from VPN instances.

use crate::client::RpcClient;
use anyhow::Result;
use clap::Subcommand;
use knetd_common::*;
use std::time::Duration;
use tokio::time::sleep;

/// Event subcommands.
#[derive(Subcommand)]
pub enum EventCommands {
    /// Watch events from a VPN instance in real-time
    #[command(override_usage = "knetctl events watch -i|--instance <INSTANCE> [-p|--poll-interval <POLL_INTERVAL>]")]
    Watch {
        /// VPN instance name
        #[arg(short = 'i', long)]
        instance: String,

        /// Poll interval in milliseconds
        #[arg(short = 'p', long, default_value = "500")]
        poll_interval: u64,
    },
}

/// Handle event commands.
pub async fn handle_command(client: &RpcClient, cmd: EventCommands) -> Result<()> {
    match cmd {
        EventCommands::Watch {
            instance,
            poll_interval,
        } => {
            println!("Watching events for instance '{}'...", instance);
            println!("Press Ctrl+C to stop\n");

            // Subscribe to events
            let req = SubscribeEventsRequest {
                instance: InstanceName::new(instance.clone()),
            };

            let response = client
                .call("events.subscribe", serde_json::to_value(req)?)
                .await?;
            let subscribe_resp: SubscribeEventsResponse = serde_json::from_value(response)?;

            let subscription_id = subscribe_resp.subscription_id;
            println!(
                "✓ Subscribed (subscription ID: {})\n",
                subscription_id
            );

            // Poll for events
            let poll_duration = Duration::from_millis(poll_interval);
            let mut event_count = 0;

            loop {
                let poll_req = PollEventsRequest {
                    subscription_id: subscription_id.clone(),
                    max_events: Some(100),
                };

                let response = client
                    .call("events.poll", serde_json::to_value(poll_req)?)
                    .await?;
                let poll_resp: PollEventsResponse = serde_json::from_value(response)?;

                for event in poll_resp.events {
                    event_count += 1;
                    print_event(event_count, &event);
                }

                sleep(poll_duration).await;
            }

            // Note: Unsubscribe happens automatically when the client disconnects
            // or we could add Ctrl+C handling to explicitly unsubscribe
        }
    }
}

/// Print a formatted event to the console.
fn print_event(count: usize, event: &DaemonEvent) {
    match event {
        DaemonEvent::LinkStatusChange {
            instance,
            host_id,
            link_id,
            connected,
            remote,
            external,
            timestamp,
        } => {
            let status = if *connected { "UP" } else { "DOWN" };
            let flags = format!(
                "{}{}",
                if *remote { " remote" } else { "" },
                if *external { " external" } else { "" }
            );
            println!(
                "[{}] {} Link {} to host {} is {} {}{}",
                count,
                timestamp.format("%H:%M:%S"),
                link_id.to_u8(),
                host_id.to_u16(),
                status,
                instance.as_str(),
                flags
            );
        }
        DaemonEvent::HostStatusChange {
            instance,
            host_id,
            reachable,
            remote,
            external,
            timestamp,
        } => {
            let status = if *reachable {
                "REACHABLE"
            } else {
                "UNREACHABLE"
            };
            let flags = format!(
                "{}{}",
                if *remote { " remote" } else { "" },
                if *external { " external" } else { "" }
            );
            println!(
                "[{}] {} Host {} is {} in {}{}",
                count,
                timestamp.format("%H:%M:%S"),
                host_id.to_u16(),
                status,
                instance.as_str(),
                flags
            );
        }
        DaemonEvent::PmtudNotify {
            instance,
            mtu,
            timestamp,
        } => {
            println!(
                "[{}] {} PMTUD detected MTU {} for instance '{}'",
                count,
                timestamp.format("%H:%M:%S"),
                mtu,
                instance.as_str()
            );
        }
        DaemonEvent::OnwireVerChange {
            instance,
            min_ver,
            max_ver,
            ver,
            timestamp,
        } => {
            println!(
                "[{}] {} On-wire version changed to {} (min={}, max={}) for instance '{}'",
                count,
                timestamp.format("%H:%M:%S"),
                ver,
                min_ver,
                max_ver,
                instance.as_str()
            );
        }
        DaemonEvent::LogMessage {
            instance: _,
            level,
            subsystem,
            message,
            timestamp,
        } => {
            println!(
                "[{}] {} [{}] {}: {}",
                count,
                timestamp.format("%H:%M:%S"),
                level,
                subsystem,
                message
            );
        }
    }
}
