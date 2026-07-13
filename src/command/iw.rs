use std::time::Duration;

use anyhow::Result;

use super::{CommandRequest, CommandRunner};
use crate::error::ErrorOperation;

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct Iw<'a> {
    runner: &'a dyn CommandRunner,
}

impl<'a> Iw<'a> {
    pub(crate) fn new(runner: &'a dyn CommandRunner) -> Self {
        Self { runner }
    }

    pub(crate) fn link_bitrates(
        &self,
        iface: &str,
        operation: ErrorOperation,
    ) -> Result<DirectionalBitrates> {
        let request =
            CommandRequest::new("iw", operation, QUERY_TIMEOUT).args(["dev", iface, "link"]);
        let output = self
            .runner
            .run(&request, None)
            .map_err(|failure| failure.into_domain())?;
        Ok(parse_link_bitrates(&output.stdout))
    }
}

#[derive(Default)]
pub(crate) struct DirectionalBitrates {
    pub(crate) tx_mbps: Option<f64>,
    pub(crate) rx_mbps: Option<f64>,
}

fn parse_link_bitrates(output: &str) -> DirectionalBitrates {
    let mut bitrates = DirectionalBitrates::default();
    for line in output.lines().map(str::trim) {
        if let Some(value) = parse_bitrate_line(line, "tx bitrate:") {
            bitrates.tx_mbps = Some(value);
        } else if let Some(value) = parse_bitrate_line(line, "rx bitrate:") {
            bitrates.rx_mbps = Some(value);
        }
    }
    bitrates
}

fn parse_bitrate_line(line: &str, prefix: &str) -> Option<f64> {
    let mut fields = line.strip_prefix(prefix)?.split_whitespace();
    let value = fields.next()?.parse::<f64>().ok()?;
    match fields.next()?.to_ascii_lowercase().as_str() {
        "kbit/s" => Some(value / 1000.0),
        "mbit/s" => Some(value),
        "gbit/s" => Some(value * 1000.0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_link_bitrates;

    #[test]
    fn parses_directional_iw_link_bitrates_in_mbps() {
        let parsed = parse_link_bitrates(
            "Connected to 00:11:22:33:44:55\n\ttx bitrate: 866.7 MBit/s\n\trx bitrate: 1.2 GBit/s\n",
        );
        assert_eq!(parsed.tx_mbps, Some(866.7));
        assert_eq!(parsed.rx_mbps, Some(1200.0));
    }
}
