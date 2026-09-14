//! Ported from `scanner_windows.suspicious_score`.

/// The network-audit slice [`suspicious_score`] reads: how many observed connections
/// matched a known-bad IP from the threat feeds, and the raw anomaly messages
/// (`collect_realtime_snapshot`/`network_audit_snapshot`, `scan-system-audit`, phase 2).
#[derive(Debug, Clone, Default)]
pub struct NetworkAuditSummary {
    pub connection_threat_matches: usize,
    pub anomalies: Vec<String>,
}

/// Everything [`suspicious_score`] needs from a full audit report — just the counts and
/// the network anomaly text, not the full `Report` (phase 2) each of these actually
/// comes from.
#[derive(Debug, Clone, Default)]
pub struct ScoreInputs {
    pub defender_threats_count: usize,
    pub recent_installs_count: usize,
    pub recent_service_installs_count: usize,
    pub recent_task_registrations_count: usize,
    pub network_audit: NetworkAuditSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScoreResult {
    pub risk_score_100: u32,
    pub reasons: Vec<String>,
}

/// A coarse 0-100 risk score plus the human-readable reasons behind it. Per-signal caps
/// (Defender threats capped at 60, services at 15, network anomalies at 20) keep any
/// single noisy source from dominating the total before the final 0-100 clamp; the
/// threat-feed-match bonus is a flat +30 regardless of how many connections matched —
/// one confirmed hit already means "look at this machine now."
#[must_use]
pub fn suspicious_score(inputs: &ScoreInputs) -> ScoreResult {
    let mut score: i64 = 0;
    let mut reasons = Vec::new();

    let threats = inputs.defender_threats_count;
    if threats > 0 {
        score += (20 * threats as i64).min(60);
        reasons.push(format!("Menaces Defender detectees: {threats}"));
    }

    let installs = inputs.recent_installs_count;
    if installs >= 6 {
        score += 20;
        reasons.push(format!("Beaucoup d'installations recentes ({installs})"));
    } else if installs >= 3 {
        score += 10;
        reasons.push(format!("Plusieurs installations recentes ({installs})"));
    }

    let services = inputs.recent_service_installs_count;
    if services > 0 {
        score += ((services * 3) as i64).min(15);
        reasons.push(format!("Services installes recemment: {services}"));
    }

    let tasks = inputs.recent_task_registrations_count;
    if tasks >= 5 {
        score += 10;
        reasons.push(format!(
            "Taches planifiees nouvellement enregistrees: {tasks}"
        ));
    }

    let threat_matches = inputs.network_audit.connection_threat_matches;
    if threat_matches > 0 {
        score += 30;
        reasons.push(format!(
            "Connexion(s) vers une IP presente dans une liste de blocage menace: {threat_matches}"
        ));
    }

    let other_net_anomalies: Vec<&String> = inputs
        .network_audit
        .anomalies
        .iter()
        .filter(|a| !a.contains("liste de blocage"))
        .collect();
    if !other_net_anomalies.is_empty() {
        score += ((other_net_anomalies.len() * 5) as i64).min(20);
        reasons.push(format!(
            "Anomalies reseau detectees: {}",
            other_net_anomalies.len()
        ));
    }

    ScoreResult {
        risk_score_100: score.clamp(0, 100) as u32,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_counts(defender: usize, installs: usize, services: usize, tasks: usize) -> ScoreInputs {
        ScoreInputs {
            defender_threats_count: defender,
            recent_installs_count: installs,
            recent_service_installs_count: services,
            recent_task_registrations_count: tasks,
            network_audit: NetworkAuditSummary::default(),
        }
    }

    #[test]
    fn suspicious_score_empty_report_is_zero() {
        let result = suspicious_score(&ScoreInputs::default());
        assert_eq!(result.risk_score_100, 0);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn suspicious_score_defender_threats_capped_at_60() {
        let result = suspicious_score(&with_counts(5, 0, 0, 0));
        assert_eq!(result.risk_score_100, 60);
        assert!(result.reasons[0].contains("Menaces Defender detectees: 5"));
    }

    #[test]
    fn suspicious_score_defender_threats_uncapped() {
        let result = suspicious_score(&with_counts(2, 0, 0, 0));
        assert_eq!(result.risk_score_100, 40);
    }

    #[test]
    fn suspicious_score_installs_thresholds() {
        assert_eq!(suspicious_score(&with_counts(0, 2, 0, 0)).risk_score_100, 0);
        assert_eq!(
            suspicious_score(&with_counts(0, 3, 0, 0)).risk_score_100,
            10
        );
        assert_eq!(
            suspicious_score(&with_counts(0, 6, 0, 0)).risk_score_100,
            20
        );
    }

    #[test]
    fn suspicious_score_services_capped_at_15() {
        let result = suspicious_score(&with_counts(0, 0, 10, 0));
        assert_eq!(result.risk_score_100, 15);
    }

    #[test]
    fn suspicious_score_services_uncapped() {
        let result = suspicious_score(&with_counts(0, 0, 3, 0));
        assert_eq!(result.risk_score_100, 9);
    }

    #[test]
    fn suspicious_score_tasks_threshold() {
        assert_eq!(suspicious_score(&with_counts(0, 0, 0, 4)).risk_score_100, 0);
        assert_eq!(
            suspicious_score(&with_counts(0, 0, 0, 5)).risk_score_100,
            10
        );
    }

    #[test]
    fn suspicious_score_network_threat_feed_match_flat_30() {
        // +30 fixe, peu importe le nombre de connexions en match (pas +30 par connexion).
        let inputs = ScoreInputs {
            network_audit: NetworkAuditSummary {
                connection_threat_matches: 2,
                anomalies: vec![],
            },
            ..ScoreInputs::default()
        };
        assert_eq!(suspicious_score(&inputs).risk_score_100, 30);
    }

    #[test]
    fn suspicious_score_network_other_anomalies_excludes_threat_feed_wording() {
        // La ligne "liste de blocage" est deja comptee via connection_threat_matches
        // ailleurs -- ne doit pas aussi compter comme anomalie reseau generique, sinon
        // double comptage du meme signal.
        let inputs = ScoreInputs {
            network_audit: NetworkAuditSummary {
                connection_threat_matches: 0,
                anomalies: vec![
                    "IP 1.2.3.4 presente dans une liste de blocage menace (processus: x)".into(),
                    "CPU eleve: 90%".into(),
                ],
            },
            ..ScoreInputs::default()
        };
        let result = suspicious_score(&inputs);
        assert_eq!(result.risk_score_100, 5);
        assert!(result.reasons[0].contains("Anomalies reseau detectees: 1"));
    }

    #[test]
    fn suspicious_score_network_other_anomalies_capped_at_20() {
        let inputs = ScoreInputs {
            network_audit: NetworkAuditSummary {
                connection_threat_matches: 0,
                anomalies: (0..10).map(|i| format!("anomalie {i}")).collect(),
            },
            ..ScoreInputs::default()
        };
        assert_eq!(suspicious_score(&inputs).risk_score_100, 20);
    }

    #[test]
    fn suspicious_score_overall_capped_at_100() {
        // Somme brute = 60+20+15+10+30+20 = 155, doit etre ecretee a 100.
        let inputs = ScoreInputs {
            defender_threats_count: 5,          // 60
            recent_installs_count: 6,           // 20
            recent_service_installs_count: 10,  // 15
            recent_task_registrations_count: 5, // 10
            network_audit: NetworkAuditSummary {
                connection_threat_matches: 1,                          // 30
                anomalies: (0..10).map(|i| format!("a{i}")).collect(), // 20
            },
        };
        assert_eq!(suspicious_score(&inputs).risk_score_100, 100);
    }
}
