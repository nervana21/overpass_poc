// src/zkp/transactions.rs

use std::str::FromStr;

use anyhow::{anyhow, Result};
use bitcoin_rpc_codegen::{Client, RpcApi};
use bitcoincore_rpc::json::AddressType as RpcAddressType;
use corepc_node::tempfile::tempdir;
use corepc_node::{Conf, Node};
use miniscript::bitcoin::absolute::LockTime;
use miniscript::bitcoin::address::NetworkUnchecked;
use miniscript::bitcoin::opcodes::all::OP_RETURN;
use miniscript::bitcoin::script::Builder;
use miniscript::bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use miniscript::bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness};
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

    let txid: Txid =
        utxo.get("txid").and_then(Value::as_str).ok_or_else(|| anyhow!("Missing txid"))?.parse()?;
    let vout =
        utxo.get("vout").and_then(Value::as_u64).ok_or_else(|| anyhow!("Missing vout"))? as u32;
    let amount_btc =
        utxo.get("amount").and_then(Value::as_f64).ok_or_else(|| anyhow!("Missing amount"))?;
    let input_value = (amount_btc * 100_000_000.0) as u64;

    let op_return_script = Builder::new().push_opcode(OP_RETURN).push_slice(&data).into_script();
    let op_return_output = TxOut { value: Amount::from_sat(0), script_pubkey: op_return_script };

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

    let txid: Txid =
        utxo.get("txid").and_then(Value::as_str).ok_or_else(|| anyhow!("Missing txid"))?.parse()?;
    let vout =
        utxo.get("vout").and_then(Value::as_u64).ok_or_else(|| anyhow!("Missing vout"))? as u32;
    let input_value =
        (utxo.get("amount").and_then(Value::as_f64).ok_or_else(|| anyhow!("Missing amount"))?
            * 100_000_000.0) as u64;

    let dust_limit = 546;
    let num_outputs = 21;
    let mut outputs = Vec::with_capacity(num_outputs + 1);
    let mut total_output_value = 0;

    for _ in 0..num_outputs {
        // Keep retrying until we get a Taproot address
        let mut addr = node.client.new_address_with_type(corepc_node::AddressType::Bech32m)?;

        while addr.address_type() != Some(BtcAddressType::P2tr) {
            addr = node.client.new_address_with_type(corepc_node::AddressType::Bech32)?;
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

/// Build a simple Taproot OP_RETURN transaction:
/// - single UTXO input from `funding_address`
/// - one zero‑value OP_RETURN output carrying `data`
/// - one Taproot change output (all sats minus fee)
pub fn build_codegen_transaction(
    client: &Client,
    funding_address: &str,
    data: [u8; 32],
) -> Result<Transaction> {
    // Parse the funding address string once
    let target_address = Address::<NetworkUnchecked>::from_str(funding_address)?;

    // pull all utxos using the snake_case method
    let utxos = client.list_unspent(None, None, None, None, None)?;

    const FEE: u64 = 1_000;

    let mut chosen = None;
    for u in utxos {
        // Compare addresses directly (Option<Address<NetworkUnchecked>>)
        if u.address == Some(target_address.clone()) {
            let sats = u.amount.to_sat(); // Assuming amount is of type Amount
            if sats >= FEE {
                chosen = Some((u.clone(), sats));
                break;
            }
        }
    }
    let (utxo, input_value) = chosen
        .ok_or_else(|| anyhow!("No UTXO at {} with at least {} sats", funding_address, FEE,))?;

    // parse txid & vout directly from the struct fields
    let txid = utxo.txid; // Assuming field exists
    let vout = utxo.vout; // Assuming field exists

    // build OP_RETURN output
    let op_return_script = Builder::new()
        .push_opcode(miniscript::bitcoin::blockdata::opcodes::all::OP_RETURN)
        .push_slice(data)
        .into_script();
    let op_return_output = TxOut { value: Amount::from_sat(0), script_pubkey: op_return_script };

    // compute change
    let change_value = input_value
        .checked_sub(FEE)
        .ok_or_else(|| anyhow!("Insufficient funds: have {}, need {} sats", input_value, FEE))?;

    // fresh Taproot change address using the snake_case method
    let change_addr_unchecked = client.get_new_address(None, Some(RpcAddressType::Bech32m))?;
    let change_addr = change_addr_unchecked.assume_checked();

    let change_output =
        TxOut { value: Amount::from_sat(change_value), script_pubkey: change_addr.script_pubkey() };

    // assemble transaction
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(txid, vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![op_return_output, change_output],
    };

    Ok(tx)
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
