//! Command catalog and fuzzy-matching for the auto-complete dropdown.
//!
//! Uses [`nucleo_matcher`] for scored fuzzy matching — the same algorithm
//! behind Helix editor's picker. Results are returned sorted by score
//! (best match first), with word-boundary bonuses, gap penalties, and
//! smart-case sensitivity.

use nucleo_matcher::pattern::{AtomKind, CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};

/// A known management command with its argument hint.
pub(crate) struct CommandEntry {
    /// The command name as typed (e.g. `"client-deny"`).
    pub name: &'static str,
    /// Short argument hint shown after the name (e.g. `"<cid> <kid> <reason>"`).
    pub args: &'static str,
}

/// All commands accepted by the `FromStr` impl on `OvpnCommand`, in logical
/// order. This mirrors the match arms in `command.rs`.
pub(crate) static CATALOG: &[CommandEntry] = &[
    // Informational
    CommandEntry {
        name: "version",
        args: "",
    },
    CommandEntry {
        name: "pid",
        args: "",
    },
    CommandEntry {
        name: "help",
        args: "",
    },
    CommandEntry {
        name: "net",
        args: "",
    },
    CommandEntry {
        name: "load-stats",
        args: "",
    },
    CommandEntry {
        name: "status",
        args: "[1|2|3]",
    },
    CommandEntry {
        name: "state",
        args: "[on|off|all|on all|N]",
    },
    CommandEntry {
        name: "log",
        args: "on|off|all|on all|N",
    },
    CommandEntry {
        name: "echo",
        args: "on|off|all|on all|N",
    },
    CommandEntry {
        name: "verb",
        args: "[0–15]",
    },
    CommandEntry {
        name: "mute",
        args: "[N]",
    },
    CommandEntry {
        name: "bytecount",
        args: "N",
    },
    // Connection control
    CommandEntry {
        name: "signal",
        args: "SIGHUP|SIGTERM|SIGUSR1|SIGUSR2",
    },
    CommandEntry {
        name: "kill",
        args: "<cn> | <proto:ip:port>",
    },
    CommandEntry {
        name: "hold",
        args: "[on|off|release]",
    },
    // Authentication
    CommandEntry {
        name: "username",
        args: "<auth-type> <value>",
    },
    CommandEntry {
        name: "password",
        args: "<auth-type> <value>",
    },
    CommandEntry {
        name: "auth-retry",
        args: "none|interact|nointeract",
    },
    CommandEntry {
        name: "forget-passwords",
        args: "",
    },
    // Interactive prompts
    CommandEntry {
        name: "needok",
        args: "<name> ok|cancel",
    },
    CommandEntry {
        name: "needstr",
        args: "<name> <value>",
    },
    // PKCS#11
    CommandEntry {
        name: "pkcs11-id-count",
        args: "",
    },
    CommandEntry {
        name: "pkcs11-id-get",
        args: "N",
    },
    // Client management (server mode)
    CommandEntry {
        name: "client-auth",
        args: "<cid> <kid> [config-lines]",
    },
    CommandEntry {
        name: "client-auth-nt",
        args: "<cid> <kid>",
    },
    CommandEntry {
        name: "client-deny",
        args: "<cid> <kid> <reason> [client-reason]",
    },
    CommandEntry {
        name: "client-kill",
        args: "<cid> [message]",
    },
    // Remote / proxy override
    CommandEntry {
        name: "remote",
        args: "accept|skip|mod <host> <port>",
    },
    CommandEntry {
        name: "proxy",
        args: "none|http <h> <p> [nct]|socks <h> <p>",
    },
    // Misc
    CommandEntry {
        name: "env-filter",
        args: "[level]",
    },
    CommandEntry {
        name: "remote-entry-count",
        args: "",
    },
    CommandEntry {
        name: "remote-entry-get",
        args: "i|all [j]",
    },
    CommandEntry {
        name: "push-update-broad",
        args: "<options>",
    },
    CommandEntry {
        name: "push-update-cid",
        args: "<cid> <options>",
    },
    CommandEntry {
        name: "raw-ml",
        args: "<command>",
    },
    // Lifecycle
    CommandEntry {
        name: "exit",
        args: "",
    },
    CommandEntry {
        name: "quit",
        args: "",
    },
];

/// Return catalog entries whose name fuzzy-matches `query`, sorted by
/// nucleo score (best match first).
///
/// An empty query returns every entry in catalog order.
pub(crate) fn fuzzy_match(query: &str) -> Vec<&'static CommandEntry> {
    if query.is_empty() {
        return CATALOG.iter().collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::new(
        query,
        CaseMatching::Smart,
        Normalization::Smart,
        AtomKind::Fuzzy,
    );

    let mut scored: Vec<_> = CATALOG
        .iter()
        .filter_map(|entry| {
            let mut buf = Vec::new();
            let haystack = Utf32Str::new(entry.name, &mut buf);
            let score = pattern.score(haystack, &mut matcher)?;
            Some((entry, score))
        })
        .collect();

    // Sort descending by score (highest = best match first).
    scored.sort_by_key(|&(_, score)| std::cmp::Reverse(score));

    scored.into_iter().map(|(entry, _)| entry).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_returns_all() {
        assert_eq!(fuzzy_match("").len(), CATALOG.len());
    }

    #[test]
    fn prefix_match() {
        let results = fuzzy_match("ver");
        assert!(results.first().is_some_and(|entry| entry.name == "version"));
    }

    #[test]
    fn fuzzy_across_hyphen() {
        let results = fuzzy_match("cd");
        assert!(results.iter().any(|entry| entry.name == "client-deny"));
    }

    #[test]
    fn word_boundary_bonus() {
        // "st" should rank "status" and "state" above "load-stats" because
        // the match starts at a word boundary.
        let results = fuzzy_match("st");
        let names: Vec<_> = results.iter().map(|entry| entry.name).collect();
        assert!(names.contains(&"status"));
        assert!(names.contains(&"state"));

        // status/state should appear before load-stats
        let status_pos = names.iter().position(|name| *name == "status").unwrap();
        let load_stats_pos = names.iter().position(|name| *name == "load-stats").unwrap();
        assert!(
            status_pos < load_stats_pos,
            "status ({status_pos}) should rank before load-stats ({load_stats_pos})"
        );
    }

    #[test]
    fn exact_match_ranks_first() {
        let results = fuzzy_match("help");
        assert_eq!(results.first().unwrap().name, "help");
    }

    #[test]
    fn no_match_returns_empty() {
        assert!(fuzzy_match("zzz").is_empty());
    }
}
