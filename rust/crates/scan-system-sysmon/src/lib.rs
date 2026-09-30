//! CPU, network throughput and public sockets from the Windows host.
//!
//! Port of `list_public_connections`, `network_audit_snapshot` and the resource/
//! connection part of `collect_realtime_snapshot` in `scanner_windows.py`. The
//! persistence checks in the latter belong to the audit orchestration crate.
#![cfg(windows)]

use std::{collections::HashSet, io, thread, time::Duration};

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use scan_system_core::{format_rate, is_public_ipv4, looks_suspicious_text};
use serde::Serialize;
use sysinfo::{Networks, Pid, ProcessesToUpdate, System, MINIMUM_CPU_UPDATE_INTERVAL};

const HIGH_NETWORK_BPS: f64 = 5.0 * 1024.0 * 1024.0;
const MAX_CONNECTIONS: usize = 200;

/// The same keys as one item in Python's `list_public_connections()` output.
#[derive(Debug, Clone, Serialize)]
pub struct PublicConnection {
    pub pid: u32,
    pub process_name: String,
    pub local: String,
    pub remote: String,
    pub remote_ip: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_feed_match: Option<bool>,
}

/// The network portion of both Python snapshot dictionaries. Byte rates remain
/// floating point so the report and UI can format them at the point of display.
#[derive(Debug, Clone, Default, Serialize)]
pub struct NetworkSnapshot {
    pub cpu_percent: f32,
    pub download_bps: f64,
    pub upload_bps: f64,
    pub connections: Vec<PublicConnection>,
    pub anomalies: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct Counters {
    sent: u64,
    received: u64,
}

fn counters(networks: &Networks) -> Counters {
    Counters {
        sent: networks.values().map(|n| n.total_transmitted()).sum(),
        received: networks.values().map(|n| n.total_received()).sum(),
    }
}

fn rates(before: Counters, after: Counters, elapsed: Duration) -> (f64, f64) {
    let seconds = elapsed.as_secs_f64().max(1.0);
    (
        after.sent.saturating_sub(before.sent) as f64 / seconds,
        after.received.saturating_sub(before.received) as f64 / seconds,
    )
}

fn socket_status(state: netstat2::TcpState) -> String {
    // psutil uses these uppercase labels in saved reports and in the GUI.
    match state {
        netstat2::TcpState::SynSent => "SYN_SENT",
        netstat2::TcpState::SynReceived => "SYN_RECV",
        netstat2::TcpState::FinWait1 => "FIN_WAIT1",
        netstat2::TcpState::FinWait2 => "FIN_WAIT2",
        netstat2::TcpState::CloseWait => "CLOSE_WAIT",
        netstat2::TcpState::LastAck => "LAST_ACK",
        netstat2::TcpState::TimeWait => "TIME_WAIT",
        netstat2::TcpState::DeleteTcb => "DELETE_TCB",
        netstat2::TcpState::Established => "ESTABLISHED",
        netstat2::TcpState::Listen => "LISTEN",
        netstat2::TcpState::Closing => "CLOSING",
        netstat2::TcpState::Closed => "CLOSED",
        netstat2::TcpState::Unknown => "NONE",
    }
    .to_string()
}

/// Enumerates IPv4 TCP connections with a public remote address. UDP sockets
/// have no remote endpoint in `netstat2` and therefore cannot pass the same
/// `if not conn.raddr` guard as the Python implementation.
pub fn list_public_connections(system: &mut System) -> io::Result<Vec<PublicConnection>> {
    system.refresh_processes(ProcessesToUpdate::All, true);
    let sockets =
        get_sockets_info(AddressFamilyFlags::IPV4, ProtocolFlags::TCP).map_err(io::Error::other)?;
    let mut connections = Vec::new();

    for socket in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info else {
            continue;
        };
        let remote_ip = tcp.remote_addr.to_string();
        if !is_public_ipv4(&remote_ip) {
            continue;
        }
        let pid = socket.associated_pids.first().copied().unwrap_or(0);
        let process_name = system
            .process(Pid::from_u32(pid))
            .map(|process| process.name().to_string_lossy().into_owned())
            .unwrap_or_default();
        connections.push(PublicConnection {
            pid,
            process_name,
            local: format!("{}:{}", tcp.local_addr, tcp.local_port),
            remote: format!("{}:{}", tcp.remote_addr, tcp.remote_port),
            remote_ip,
            status: socket_status(tcp.state),
            threat_feed_match: None,
        });
    }

    connections.sort_by(|a, b| (&a.process_name, &a.remote).cmp(&(&b.process_name, &b.remote)));
    connections.truncate(MAX_CONNECTIONS);
    Ok(connections)
}

fn add_common_anomalies(snapshot: &mut NetworkSnapshot, cpu_threshold: f32) {
    if snapshot.cpu_percent >= cpu_threshold {
        snapshot
            .anomalies
            .push(format!("CPU eleve: {:.0}%", snapshot.cpu_percent));
    }
    let total = snapshot.upload_bps + snapshot.download_bps;
    if total >= HIGH_NETWORK_BPS {
        snapshot
            .anomalies
            .push(format!("Debit reseau eleve: {}", format_rate(total)));
    }
}

fn add_connection_anomalies(snapshot: &mut NetworkSnapshot, threat_feed_ips: &HashSet<String>) {
    for connection in &mut snapshot.connections {
        if threat_feed_ips.contains(&connection.remote_ip) {
            connection.threat_feed_match = Some(true);
            snapshot.anomalies.push(format!(
                "IP {} presente dans une liste de blocage menace (processus: {})",
                connection.remote_ip,
                if connection.process_name.is_empty() {
                    "inconnu"
                } else {
                    &connection.process_name
                }
            ));
        }
        if looks_suspicious_text(&format!(
            "{} {}",
            connection.process_name, connection.remote_ip
        )) {
            snapshot.anomalies.push(format!(
                "Connexion potentiellement suspecte: {} -> {}",
                if connection.process_name.is_empty() {
                    "inconnu"
                } else {
                    &connection.process_name
                },
                connection.remote_ip
            ));
        }
    }
}

/// Stateful sampler for GUI polling. The first call establishes CPU and network
/// baselines; subsequent calls compute rates from actual elapsed time. Persistence
/// checks are deliberately left for `scan-system-audit`.
pub struct RealtimeMonitor {
    system: System,
    networks: Networks,
    previous: std::time::Instant,
    previous_counters: Counters,
    cpu_high_streak: u32,
}

impl Default for RealtimeMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeMonitor {
    #[must_use]
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_cpu_usage();
        let networks = Networks::new_with_refreshed_list();
        let previous_counters = counters(&networks);
        Self {
            system,
            networks,
            previous: std::time::Instant::now(),
            previous_counters,
            cpu_high_streak: 0,
        }
    }

    /// Takes one GUI poll. A connection enumeration error is reported in
    /// `anomalies`, as Python does, so the rest of the sample is retained.
    #[must_use]
    pub fn snapshot(&mut self) -> NetworkSnapshot {
        self.system.refresh_cpu_usage();
        self.networks.refresh(true);
        let now = std::time::Instant::now();
        let current = counters(&self.networks);
        let (upload_bps, download_bps) =
            rates(self.previous_counters, current, now - self.previous);
        self.previous = now;
        self.previous_counters = current;

        let mut snapshot = NetworkSnapshot {
            cpu_percent: self.system.global_cpu_usage(),
            upload_bps,
            download_bps,
            ..NetworkSnapshot::default()
        };
        if snapshot.cpu_percent >= 95.0 {
            self.cpu_high_streak += 1;
        } else {
            self.cpu_high_streak = 0;
        }
        if self.cpu_high_streak >= 3 {
            snapshot
                .anomalies
                .push(format!("CPU eleve soutenu: {:.0}%", snapshot.cpu_percent));
        }
        let total = snapshot.upload_bps + snapshot.download_bps;
        if total >= HIGH_NETWORK_BPS {
            snapshot
                .anomalies
                .push(format!("Debit reseau eleve: {}", format_rate(total)));
        }
        match list_public_connections(&mut self.system) {
            Ok(connections) => snapshot.connections = connections,
            Err(error) => snapshot
                .anomalies
                .push(format!("Lecture connexions echouee: {error}")),
        }
        add_connection_anomalies(&mut snapshot, &HashSet::new());
        snapshot
    }
}

/// Standalone one-second audit sample, matching `network_audit_snapshot`.
/// The CPU sample needs two refreshes: the first one only establishes a baseline.
#[must_use]
pub fn network_audit_snapshot(threat_feed_ips: &HashSet<String>) -> NetworkSnapshot {
    let mut system = System::new();
    system.refresh_cpu_usage();
    let mut networks = Networks::new_with_refreshed_list();
    let before = counters(&networks);
    thread::sleep(Duration::from_secs(1).max(MINIMUM_CPU_UPDATE_INTERVAL));
    system.refresh_cpu_usage();
    networks.refresh(true);
    let after = counters(&networks);
    let (upload_bps, download_bps) = rates(before, after, Duration::from_secs(1));
    let mut snapshot = NetworkSnapshot {
        cpu_percent: system.global_cpu_usage(),
        upload_bps,
        download_bps,
        ..NetworkSnapshot::default()
    };
    add_common_anomalies(&mut snapshot, 85.0);
    match list_public_connections(&mut system) {
        Ok(connections) => snapshot.connections = connections,
        Err(error) => {
            snapshot
                .anomalies
                .push(format!("Lecture connexions echouee: {error}"));
            return snapshot;
        }
    }
    add_connection_anomalies(&mut snapshot, threat_feed_ips);
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_clamp_counter_reset_and_short_intervals() {
        let before = Counters {
            sent: 100,
            received: 200,
        };
        let after = Counters {
            sent: 50,
            received: 300,
        };
        assert_eq!(
            rates(before, after, Duration::from_millis(100)),
            (0.0, 100.0)
        );
    }

    #[test]
    fn threat_match_keeps_report_shape() {
        let mut snapshot = NetworkSnapshot {
            connections: vec![PublicConnection {
                pid: 42,
                process_name: "example.exe".into(),
                local: "127.0.0.1:1".into(),
                remote: "8.8.8.8:443".into(),
                remote_ip: "8.8.8.8".into(),
                status: "ESTABLISHED".into(),
                threat_feed_match: None,
            }],
            ..NetworkSnapshot::default()
        };
        add_connection_anomalies(&mut snapshot, &HashSet::from(["8.8.8.8".into()]));
        assert_eq!(snapshot.connections[0].threat_feed_match, Some(true));
        assert!(snapshot.anomalies[0].contains("liste de blocage"));
    }
}
