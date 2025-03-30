// src/zkp/transactions.rs

use anyhow::{anyhow, Result};
use corepc_node::{tempfile::tempdir, Conf, Node};
use miniscript::bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    script::Builder,
    transaction::{Transaction, TxIn, TxOut, Version},
    Address, Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness,
};
use serde_json::Value;

/// Builds an OP_RETURN transaction embedding the provided data.
pub fn build_op_return_transaction(
    node: &Node,
    address: &Address,
    data: [u8; 32],
) -> Result<Transaction> {
    let utxos: Vec<Value> = node.client.call("listunspent", &[])?;
    let utxo = utxos
        .into_iter()
        .find(|u| u.get("address") == Some(&Value::String(address.to_string())))
        .ok_or_else(|| anyhow!("No UTXO found for address {}", address))?;

    let txid: Txid = utxo
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing txid"))?
        .parse()?;
    let vout = utxo
        .get("vout")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Missing vout"))? as u32;
    let amount_btc = utxo
        .get("amount")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow!("Missing amount"))?;
    let input_value = (amount_btc * 100_000_000.0) as u64;

    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&data)
        .into_script();
    let op_return_output = TxOut {
        value: Amount::from_sat(0),
        script_pubkey: op_return_script,
    };

    let fee = 1000;
    if input_value <= fee {
        return Err(anyhow!("Insufficient funds to cover fee"));
    }
    let change_value = input_value - fee;
    let change_address = node.client.new_address()?;
    let change_output = TxOut {
        value: Amount::from_sat(change_value),
        script_pubkey: change_address.script_pubkey(),
    };

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(0)?,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![op_return_output, change_output],
    })
}

/// Builds a P2TR transaction with 21 outputs of 546 sats each
pub fn build_p2tr_transaction(node: &Node, funding_address: &Address) -> Result<Transaction> {
    use miniscript::bitcoin::AddressType as BtcAddressType;

    let utxos: Vec<Value> = node.client.call("listunspent", &[])?;
    let utxo = utxos
        .into_iter()
        .find(|u| u.get("address") == Some(&Value::String(funding_address.to_string())))
        .ok_or_else(|| anyhow!("No UTXO found for address {}", funding_address))?;

    let txid: Txid = utxo
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing txid"))?
        .parse()?;
    let vout = utxo
        .get("vout")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("Missing vout"))? as u32;
    let input_value = (utxo
        .get("amount")
        .and_then(Value::as_f64)
        .ok_or_else(|| anyhow!("Missing amount"))?
        * 100_000_000.0) as u64;

    let dust_limit = 546;
    let num_outputs = 21;
    let mut outputs = Vec::with_capacity(num_outputs + 1);
    let mut total_output_value = 0;

    for _ in 0..num_outputs {
        // Keep retrying until we get a Taproot address
        let mut addr = node
            .client
            .new_address_with_type(corepc_node::AddressType::Bech32m)?;

        while addr.address_type() != Some(BtcAddressType::P2tr) {
            addr = node
                .client
                .new_address_with_type(corepc_node::AddressType::Bech32)?;
        }

        outputs.push(TxOut {
            value: Amount::from_sat(dust_limit),
            script_pubkey: addr.script_pubkey(),
        });
        total_output_value += dust_limit;
    }

    let fee_per_vb = 2;
    let est_vbytes = 10 + 41 + (31 * outputs.len());
    let est_fee = fee_per_vb * est_vbytes;

    let change_value = input_value.saturating_sub(total_output_value + est_fee as u64);
    let change_address = node.client.new_address()?;
    outputs.push(TxOut {
        value: Amount::from_sat(change_value),
        script_pubkey: change_address.script_pubkey(),
    });

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs,
    })
}

pub fn initialize_funded_node(bitcoind_path: &str) -> Result<(Node, Address)> {
    let tmpdir = tempdir()?;
    let mut conf = Conf::default();
    conf.args = vec!["-regtest", "-fallbackfee=0.0001"];
    conf.wallet = None;
    conf.tmpdir = Some(tmpdir.path().to_path_buf());

    let node = Node::with_conf(bitcoind_path, &conf)?;
    let wallet_name = "test_wallet";
    let _ = node.client.create_wallet(wallet_name);

    let address = node.client.new_address()?;
    println!("Generated Address: {:?}", &address);
    node.client.generate_to_address(101, &address)?;
    println!("Generated 101 blocks");

    Ok((node, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_time_zero() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert_eq!(tx.lock_time, LockTime::ZERO);
    }
}
