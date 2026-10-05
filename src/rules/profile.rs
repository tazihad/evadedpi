// -----------------------------------------------------------------------------
// File Name:      src/rules/profile.rs
// Description:    Multi-profile domain routing for per-domain evasion strategies.
// Author:         @tazihad
// Website:        https://zihad.com.bd
// License:        MIT License
// -----------------------------------------------------------------------------

// MIT License
//
// Copyright (c) 2024-2026 @tazihad
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

use crate::core::strategy::EvasionStrategy;
use crate::rules::filter::{EvasionScope, RuleFilter};

/// A named profile linking a domain filter to a specific evasion strategy.
#[derive(Debug, Clone)]
pub struct DomainProfile {
    pub name: String,
    pub filter: RuleFilter,
    pub strategy: EvasionStrategy,
}

/// StrategyRouter manages strategy selection based on the requested target host.
#[derive(Debug, Clone)]
pub struct StrategyRouter {
    pub default_strategy: EvasionStrategy,
    pub profiles: Vec<DomainProfile>,
}

impl StrategyRouter {
    /// Create a new router with a default baseline strategy.
    pub fn new(default_strategy: EvasionStrategy) -> Self {
        Self {
            default_strategy,
            profiles: Vec::new(),
        }
    }

    /// Add a domain-specific profile.
    pub fn add_profile(&mut self, name: &str, hosts: Vec<String>, strategy: EvasionStrategy) {
        let filter = RuleFilter::new(EvasionScope::AllowList, hosts);
        self.profiles.push(DomainProfile {
            name: name.to_string(),
            filter,
            strategy,
        });
    }

    /// Retrieve the applicable strategy for a given destination host.
    pub fn get_strategy(&self, host: &str) -> &EvasionStrategy {
        for profile in &self.profiles {
            if profile.filter.should_evade(host) {
                return &profile.strategy;
            }
        }
        &self.default_strategy
    }

    /// Number of registered domain profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::strategy::SplitMode;

    #[test]
    fn test_strategy_router_matching() {
        let default_strat = EvasionStrategy {
            split_mode: SplitMode::FirstByte,
            ..Default::default()
        };
        let yt_strat = EvasionStrategy {
            split_mode: SplitMode::MultiSplit,
            ..Default::default()
        };

        let mut router = StrategyRouter::new(default_strat);
        router.add_profile("youtube", vec!["youtu.be".to_string(), "*.googlevideo.com".to_string()], yt_strat);

        assert_eq!(router.get_strategy("youtu.be").split_mode, SplitMode::MultiSplit);
        assert_eq!(router.get_strategy("rr1---sn-oxu-ixal.googlevideo.com").split_mode, SplitMode::MultiSplit);
        assert_eq!(router.get_strategy("example.com").split_mode, SplitMode::FirstByte);
    }
}
