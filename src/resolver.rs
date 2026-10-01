//! The policy engine: compiles the config into fast lookup structures and
//! resolves `(client_ip, host) -> Decision` through the hierarchy.
//!
//! Resolution order, highest priority first:
//!   1. Individual (per-IP) rules
//!   2. Department rules (department chosen by CIDR longest-prefix match)
//!   3. Global rules
//!   4. Default action
//!
//! Within a single level, deny is checked before allow (fail-safe). The first
//! level to express an opinion wins; otherwise the default action applies.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::config::{Action, Config};
use crate::ipmap::IpMap;
use crate::policy::{normalize_host, Decision, Rules};

struct Department {
    name: String,
    rules: Rules,
}

/// Compiled, immutable policy engine. Cheap to share across tasks behind an
/// `Arc`; every field is read-only on the hot path.
pub struct Engine {
    default: Decision,
    global: Rules,
    departments: Vec<Department>,
    ipmap: IpMap,
    individuals: HashMap<IpAddr, Rules>,
}

/// The outcome of a policy evaluation, with context for logging.
pub struct Verdict {
    pub decision: Decision,
    /// Which level decided: "individual", a department name, "global", or "default".
    pub level: &'static str,
    /// Department name when the department level decided (else empty).
    pub department: Option<String>,
}

impl Engine {
    pub fn from_config(cfg: &Config) -> Self {
        let default = match cfg.server.default_action {
            Action::Allow => Decision::Allow,
            Action::Deny => Decision::Deny,
        };

        let global = Rules::from_raw(&cfg.global);

        let mut departments = Vec::with_capacity(cfg.departments.len());
        let mut ipmap = IpMap::new();
        for (idx, dept) in cfg.departments.iter().enumerate() {
            for net in &dept.cidrs {
                ipmap.insert(*net, idx);
            }
            departments.push(Department {
                name: dept.name.clone(),
                rules: Rules::from_raw(&dept.rules),
            });
        }
        ipmap.finalize();

        let mut individuals = HashMap::with_capacity(cfg.individuals.len());
        for ind in &cfg.individuals {
            individuals.insert(ind.ip, Rules::from_raw(&ind.rules));
        }

        Engine {
            default,
            global,
            departments,
            ipmap,
            individuals,
        }
    }

    /// Resolve a request. `raw_host` may include a port and/or trailing dot.
    pub fn evaluate(&self, client_ip: IpAddr, raw_host: &str) -> Verdict {
        let host = normalize_host(raw_host);

        // 1. Individual
        if let Some(rules) = self.individuals.get(&client_ip) {
            if let Some(decision) = rules.decide(&host) {
                return Verdict {
                    decision,
                    level: "individual",
                    department: None,
                };
            }
        }

        // 2. Department
        if let Some(idx) = self.ipmap.department(client_ip) {
            let dept = &self.departments[idx];
            if let Some(decision) = dept.rules.decide(&host) {
                return Verdict {
                    decision,
                    level: "department",
                    department: Some(dept.name.clone()),
                };
            }
        }

        // 3. Global
        if let Some(decision) = self.global.decide(&host) {
            return Verdict {
                decision,
                level: "global",
                department: None,
            };
        }

        // 4. Default
        Verdict {
            decision: self.default,
            level: "default",
            department: None,
        }
    }

    pub fn department_count(&self) -> usize {
        self.departments.len()
    }

    pub fn individual_count(&self) -> usize {
        self.individuals.len()
    }

    pub fn cidr_count(&self) -> usize {
        self.ipmap.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn engine(toml: &str) -> Engine {
        let cfg: Config = toml::from_str(toml).unwrap();
        Engine::from_config(&cfg)
    }

    #[test]
    fn hierarchy_precedence() {
        let e = engine(
            r#"
            [server]
            mode = "forward"
            listen = "0.0.0.0:8080"
            default_action = "deny"

            [global]
            allow = ["*"]
            deny = ["malware.test"]

            [[departments]]
            name = "sales"
            cidrs = ["192.168.10.0/24"]
            deny = ["youtube.com"]

            [[individuals]]
            ip = "192.168.10.55"
            allow = ["youtube.com"]
            "#,
        );

        let sales_ip: IpAddr = "192.168.10.9".parse().unwrap();
        let boss_ip: IpAddr = "192.168.10.55".parse().unwrap();
        let other_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Global deny applies to everyone.
        assert_eq!(e.evaluate(sales_ip, "malware.test").decision, Decision::Deny);
        // Department denies youtube for sales...
        assert_eq!(e.evaluate(sales_ip, "youtube.com").decision, Decision::Deny);
        // ...but the individual override allows it for the boss.
        assert_eq!(e.evaluate(boss_ip, "youtube.com").decision, Decision::Allow);
        // Global allow-all covers normal browsing.
        assert_eq!(e.evaluate(sales_ip, "example.com").decision, Decision::Allow);
        // An IP in no department still gets global rules.
        assert_eq!(e.evaluate(other_ip, "example.com").decision, Decision::Allow);
    }

    #[test]
    fn default_action_applies() {
        let e = engine(
            r#"
            [server]
            mode = "forward"
            listen = "0.0.0.0:8080"
            default_action = "deny"
            "#,
        );
        assert_eq!(
            e.evaluate("1.2.3.4".parse().unwrap(), "anything.test").decision,
            Decision::Deny
        );
    }
}
