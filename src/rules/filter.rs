// -----------------------------------------------------------------------------
// File Name:      src/rules/filter.rs
// Description:    Domain matching and evasion filtering rules (allowlist, blocklist, wildcards).
// Author:         @tazihad
// Website:        https://zihad.com.bd
// License:        MIT License
// -----------------------------------------------------------------------------

// MIT License
//
// Copyright (c) 2024 @tazihad
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// -----------------------------------------------------------------------------

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use tracing::info;

/// Domain matching scope for determining whether to apply DPI circumvention.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EvasionScope {
    /// Apply circumvention to all domains (default).
    #[default]
    All,
    /// Apply circumvention only to domains that match the list.
    AllowList,
    /// Apply circumvention to all domains EXCEPT those that match the list.
    BlockList,
}

/// Rule filter engine for evaluating destination hosts.
#[derive(Debug, Clone)]
pub struct RuleFilter {
    scope: EvasionScope,
    patterns: Vec<String>,
}

impl Default for RuleFilter {
    fn default() -> Self {
        Self {
            scope: EvasionScope::All,
            patterns: Vec::new(),
        }
    }
}

impl RuleFilter {
    pub fn new(scope: EvasionScope, patterns: Vec<String>) -> Self {
        let cleaned = patterns
            .into_iter()
            .map(|p| p.trim().to_ascii_lowercase())
            .filter(|p| !p.is_empty() && !p.starts_with('#'))
            .collect();

        Self {
            scope,
            patterns: cleaned,
        }
    }

    /// Load patterns from a text file (one pattern per line, ignores comments and whitespace).
    pub fn from_file<P: AsRef<Path>>(scope: EvasionScope, path: P) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut patterns = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                patterns.push(trimmed.to_ascii_lowercase());
            }
        }

        info!(
            "Loaded {} domain filtering rules (Scope: {:?})",
            patterns.len(),
            scope
        );
        Ok(Self::new(scope, patterns))
    }

    /// Checks if circumvention tricks should be applied to a given destination host.
    pub fn should_evade(&self, host: &str) -> bool {
        match self.scope {
            EvasionScope::All => true,
            EvasionScope::AllowList => self.matches_any(host),
            EvasionScope::BlockList => !self.matches_any(host),
        }
    }

    fn matches_any(&self, host: &str) -> bool {
        let host_lower = host.to_ascii_lowercase();

        for pattern in &self.patterns {
            if pattern == &host_lower {
                return true;
            }

            // Suffix / Subdomain matching
            if pattern.starts_with('.') && host_lower.ends_with(pattern) {
                return true;
            }

            if pattern.starts_with("*.") {
                let suffix = &pattern[1..]; // ".example.com"
                if host_lower.ends_with(suffix) {
                    return true;
                }
            }

            // Simple wildcard contains
            if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
                let mid = &pattern[1..pattern.len() - 1];
                if host_lower.contains(mid) {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_filter_allowlist() {
        let rules = RuleFilter::new(
            EvasionScope::AllowList,
            vec![
                "youtube.com".to_string(),
                "*.googlevideo.com".to_string(),
                ".rutracker.org".to_string(),
            ],
        );

        assert!(rules.should_evade("youtube.com"));
        assert!(rules.should_evade("rr1.googlevideo.com"));
        assert!(rules.should_evade("sub.rutracker.org"));
        assert!(!rules.should_evade("google.com"));
        assert!(!rules.should_evade("wikipedia.org"));
    }

    #[test]
    fn test_rule_filter_blocklist() {
        let rules = RuleFilter::new(
            EvasionScope::BlockList,
            vec!["bank.com".to_string(), "*.internal".to_string()],
        );

        assert!(!rules.should_evade("bank.com"));
        assert!(!rules.should_evade("corp.internal"));
        assert!(rules.should_evade("blocked-site.com"));
    }
}
