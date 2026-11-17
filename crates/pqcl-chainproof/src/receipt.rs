//! Transaction receipts and their logs.
//!
//! A receipt's RLP body is `[status, cumulativeGasUsed, logsBloom, logs]`, and
//! each log is `[address, topics, data]`.
//!
//! ⚠️ **Typed receipts are not RLP at the outer level.** Since EIP-2718 a
//! receipt stored in the trie may be `TransactionType ‖ rlp(body)`, where the
//! type byte is *raw* and only the body is RLP. Besu with `londonBlock: 0`
//! produces type-2 receipts for the EIP-1559 transactions Foundry sends by
//! default, so this is the normal case for our chain rather than an edge case.
//! A decoder that hands the whole value to an RLP parser fails on every one of
//! them, and the error it gives points at RLP rather than at the type prefix.

use crate::{ProofError, rlp};

/// A decoded receipt, reduced to what an event proof needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// `None` for a legacy receipt, otherwise the EIP-2718 type byte.
    pub tx_type: Option<u8>,
    /// Whether the transaction succeeded.
    ///
    /// ⭐ Checked by callers before trusting any log. A reverted transaction
    /// still produces a receipt, and its logs are discarded by the EVM — but
    /// they are *absent*, not marked, so a caller reasoning about "did this
    /// event happen" must look at status rather than at the log list.
    pub success: bool,
    /// Cumulative gas used at this transaction's position in the block.
    pub cumulative_gas: u64,
    /// The logs this transaction emitted, in order.
    pub logs: Vec<Log>,
}

/// One emitted log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Log {
    /// The contract that emitted it.
    pub address: [u8; 20],
    /// Indexed topics. `topics[0]` is the event signature hash for a
    /// non-anonymous event.
    pub topics: Vec<[u8; 32]>,
    /// The ABI-encoded non-indexed arguments.
    pub data: Vec<u8>,
}

impl Receipt {
    /// Decode a receipt as stored in the receipt trie.
    ///
    /// # Errors
    ///
    /// [`ProofError::Receipt`] if the encoding is malformed.
    pub fn decode(raw: &[u8]) -> Result<Self, ProofError> {
        let &first = raw.first().ok_or(ProofError::Receipt("empty receipt"))?;

        // A legacy receipt is a bare RLP list, whose first byte is >= 0xc0.
        // Anything below that is an EIP-2718 type byte. Types are 0x00..=0x7f
        // by construction, precisely so they cannot collide with an RLP list
        // prefix.
        let (tx_type, body) = if first >= 0xc0 {
            (None, raw)
        } else if first <= 0x7f {
            (Some(first), &raw[1..])
        } else {
            return Err(ProofError::Receipt(
                "leading byte is neither an RLP list nor a valid EIP-2718 type",
            ));
        };

        let decoded = rlp::decode(body)?;
        let fields = decoded.list()?;
        if fields.len() != 4 {
            return Err(ProofError::Receipt(
                "a receipt body must have exactly four fields",
            ));
        }

        // Post-Byzantium the first field is a status flag: empty or 0x01.
        let status = fields[0].bytes()?;
        let success = match status {
            [] | [0] => false,
            [1] => true,
            _ => {
                return Err(ProofError::Receipt(
                    "status is neither 0 nor 1; this may be a pre-Byzantium state-root receipt",
                ));
            }
        };

        let cumulative_gas = if fields[1].bytes()?.is_empty() {
            0
        } else {
            fields[1].u64()?
        };

        // fields[2] is the logs bloom, which is redundant with the logs
        // themselves and is not consulted: it is a filter hint, not evidence.
        let log_items = fields[3].list()?;
        let mut logs = Vec::with_capacity(log_items.len());
        for item in log_items {
            logs.push(Log::from_rlp(item)?);
        }

        Ok(Self {
            tx_type,
            success,
            cumulative_gas,
            logs,
        })
    }
}

impl Log {
    fn from_rlp(item: &rlp::Rlp<'_>) -> Result<Self, ProofError> {
        let parts = item.list()?;
        if parts.len() != 3 {
            return Err(ProofError::Receipt("a log must have exactly three fields"));
        }

        let addr_bytes = parts[0].bytes()?;
        let address: [u8; 20] = addr_bytes
            .try_into()
            .map_err(|_| ProofError::Receipt("a log address must be 20 bytes"))?;

        let mut topics = Vec::new();
        for t in parts[1].list()? {
            let t: [u8; 32] = t
                .bytes()?
                .try_into()
                .map_err(|_| ProofError::Receipt("a log topic must be 32 bytes"))?;
            topics.push(t);
        }

        Ok(Self {
            address,
            topics,
            data: parts[2].bytes()?.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a receipt the way a client would, so the decoder is exercised
    /// against the same encoding a chain produces.
    fn encode_receipt(tx_type: Option<u8>, success: bool, gas: u64, logs: &[Log]) -> Vec<u8> {
        let log_items: Vec<Vec<u8>> = logs
            .iter()
            .map(|l| {
                let topics: Vec<Vec<u8>> = l.topics.iter().map(|t| rlp::encode_bytes(t)).collect();
                rlp::encode_list(&[
                    rlp::encode_bytes(&l.address),
                    rlp::encode_list(&topics),
                    rlp::encode_bytes(&l.data),
                ])
            })
            .collect();

        let body = rlp::encode_list(&[
            rlp::encode_bytes(if success { &[1] } else { &[] }),
            rlp::encode_u64(gas),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&log_items),
        ]);

        match tx_type {
            None => body,
            Some(t) => {
                let mut out = vec![t];
                out.extend_from_slice(&body);
                out
            }
        }
    }

    fn sample_log() -> Log {
        Log {
            address: [0x11; 20],
            topics: vec![[0xaa; 32], [0xbb; 32]],
            data: vec![0xcc; 32],
        }
    }

    #[test]
    fn a_legacy_receipt_decodes() {
        let raw = encode_receipt(None, true, 21_000, &[sample_log()]);
        let r = Receipt::decode(&raw).expect("decodes");
        assert_eq!(r.tx_type, None);
        assert!(r.success);
        assert_eq!(r.cumulative_gas, 21_000);
        assert_eq!(r.logs, vec![sample_log()]);
    }

    /// The case our own chain actually produces.
    #[test]
    fn a_type_two_receipt_decodes() {
        let raw = encode_receipt(Some(2), true, 55_000, &[sample_log()]);
        let r = Receipt::decode(&raw).expect("decodes");
        assert_eq!(r.tx_type, Some(2));
        assert!(r.success);
        assert_eq!(r.logs.len(), 1);
    }

    #[test]
    fn a_failed_receipt_reports_failure() {
        let raw = encode_receipt(Some(2), false, 21_000, &[]);
        let r = Receipt::decode(&raw).expect("decodes");
        assert!(
            !r.success,
            "a reverted transaction must not read as success"
        );
    }

    #[test]
    fn a_receipt_with_no_logs_decodes() {
        let raw = encode_receipt(Some(2), true, 21_000, &[]);
        assert!(Receipt::decode(&raw).expect("decodes").logs.is_empty());
    }

    #[test]
    fn a_malformed_receipt_is_rejected() {
        assert!(Receipt::decode(&[]).is_err());
        // 0x80 is a valid RLP byte string but not a list and not a type byte
        // followed by a list.
        assert!(Receipt::decode(&[0x80]).is_err());
        // A type byte with a truncated body.
        assert!(Receipt::decode(&[0x02, 0xc4, 0x01]).is_err());
    }

    #[test]
    fn a_wrong_sized_topic_is_rejected() {
        let bad_log = rlp::encode_list(&[
            rlp::encode_bytes(&[0x11; 20]),
            rlp::encode_list(&[rlp::encode_bytes(&[0xaa; 31])]),
            rlp::encode_bytes(&[]),
        ]);
        let body = rlp::encode_list(&[
            rlp::encode_bytes(&[1]),
            rlp::encode_u64(1),
            rlp::encode_bytes(&[0u8; 256]),
            rlp::encode_list(&[bad_log]),
        ]);
        let mut raw = vec![0x02];
        raw.extend_from_slice(&body);
        assert!(Receipt::decode(&raw).is_err());
    }
}
