use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::json::WalletCreateFundedPsbtOptions;
use bitcoincore_rpc::{bitcoincore_rpc_json, Auth, Client, RpcApi};
use payjoin::bitcoin::consensus::encode::{deserialize, serialize_hex};
use payjoin::bitcoin::consensus::Encodable;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{
    Address, AddressType, Amount, Denomination, FeeRate, Network, OutPoint, Script, Transaction,
    TxOut, Txid,
};
use payjoin::receive::InputPair;

/// Implementation of PayjoinWallet for bitcoind
#[derive(Clone, Debug)]
pub struct BitcoindWallet {
    pub bitcoind: std::sync::Arc<Client>,
}

impl BitcoindWallet {
    pub fn new(config: &crate::app::config::BitcoindConfig) -> Result<Self> {
        let client = match &config.cookie {
            Some(cookie) if cookie.as_os_str().is_empty() =>
                return Err(anyhow!(
                    "Cookie authentication enabled but no cookie path provided in config.toml"
                )),
            Some(cookie) => Client::new(config.rpchost.as_str(), Auth::CookieFile(cookie.into())),
            None => Client::new(
                config.rpchost.as_str(),
                Auth::UserPass(config.rpcuser.clone(), config.rpcpassword.clone()),
            ),
        }?;
        Ok(Self { bitcoind: Arc::new(client) })
    }
}

impl BitcoindWallet {
    /// Create a PSBT with the given outputs and fee rate
    pub fn create_psbt(
        &self,
        outputs: HashMap<String, Amount>,
        fee_rate: FeeRate,
        lock_unspent: bool,
    ) -> Result<Psbt> {
        let fee_sat_per_kvb =
            fee_rate.to_sat_per_kwu().checked_mul(4).ok_or_else(|| anyhow!("Invalid fee rate"))?;
        let fee_per_kvb = Amount::from_sat(fee_sat_per_kvb);
        log::debug!("Fee rate sat/kvb: {}", fee_per_kvb.display_in(Denomination::Satoshi));

        let options = WalletCreateFundedPsbtOptions {
            lock_unspent: Some(lock_unspent),
            fee_rate: Some(fee_per_kvb),
            ..Default::default()
        };

        let psbt = self
            .bitcoind
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                None,
            )
            .context("Failed to create PSBT")?
            .psbt;

        let psbt = self
            .bitcoind
            .wallet_process_psbt(&psbt, None, None, None)
            .context("Failed to process PSBT")?
            .psbt;

        Psbt::from_str(&psbt).context("Failed to load PSBT from base64")
    }

    /// Process a PSBT, validating and signing inputs owned by this wallet
    ///
    /// Does not include bip32 derivations in the PSBT
    pub fn process_psbt(&self, psbt: &Psbt) -> Result<Psbt> {
        let psbt_str = psbt.to_string();
        let processed = self
            .bitcoind
            .wallet_process_psbt(&psbt_str, None, None, Some(false))
            .context("Failed to process PSBT")?
            .psbt;
        Psbt::from_str(&processed).context("Failed to parse processed PSBT")
    }

    /// Finalize a PSBT and extract the transaction
    pub fn finalize_psbt(&self, psbt: &Psbt) -> Result<Transaction> {
        let result = self
            .bitcoind
            .finalize_psbt(&psbt.to_string(), Some(true))
            .context("Failed to finalize PSBT")?;
        let tx = deserialize(&result.hex.ok_or_else(|| anyhow!("Incomplete PSBT"))?)?;
        Ok(tx)
    }

    pub fn can_broadcast(&self, tx: &Transaction) -> Result<bool> {
        let raw_tx = serialize_hex(&tx);
        let mempool_results = self.bitcoind.test_mempool_accept(&[raw_tx])?;
        match mempool_results.first() {
            Some(result) => Ok(result.allowed),
            None => Err(anyhow!("No mempool results returned on broadcast check",)),
        }
    }

    /// Broadcast a raw transaction
    pub fn broadcast_tx(&self, tx: &Transaction) -> Result<Txid> {
        let mut serialized_tx = Vec::new();
        tx.consensus_encode(&mut serialized_tx)?;
        self.bitcoind
            .send_raw_transaction(&serialized_tx)
            .context("Failed to broadcast transaction")
    }

    /// Check if a script belongs to this wallet
    pub fn is_mine(&self, script: &Script) -> Result<bool> {
        if let Ok(address) = Address::from_script(script, self.network()?) {
            self.bitcoind
                .get_address_info(&address)
                .map(|info| info.is_mine.unwrap_or(false))
                .context("Failed to get address info")
        } else {
            Ok(false)
        }
    }

    /// Get a new address from the wallet
    pub fn get_new_address(&self) -> Result<Address> {
        self.bitcoind
            .get_new_address(None, None)
            .context("Failed to get new address")?
            .require_network(self.network()?)
            .context("Invalid network for address")
    }

    /// List unspent UTXOs
    pub fn list_unspent(&self) -> Result<Vec<InputPair>> {
        let unspent = self
            .bitcoind
            .list_unspent(None, None, None, None, None)
            .context("Failed to list unspent")?;

        unspent
            .into_iter()
            .map(|utxo| {
                let tx = self.bitcoind.get_transaction(&utxo.txid, Some(true))?.transaction()?;
                input_pair_from_list_unspent(utxo, tx, self.network()?)
            })
            .collect::<Result<Vec<InputPair>, _>>()
            .context("Failed to convert list unspent entry to InputPair")
    }

    /// Get the network this wallet is operating on
    pub fn network(&self) -> Result<Network> {
        self.bitcoind
            .get_blockchain_info()
            .map_err(|_| anyhow!("Failed to get blockchain info"))
            .map(|info| info.chain)
    }
}

pub fn input_pair_from_list_unspent(
    utxo: bitcoincore_rpc_json::ListUnspentResultEntry,
    tx: Transaction,
    network: Network,
) -> Result<InputPair> {
    match Address::from_script(utxo.script_pub_key.as_script(), network)?.address_type().ok_or(
        anyhow!("Address is unknown, non-standard or related to the future witness version"),
    )? {
        AddressType::P2pkh => Ok(InputPair::new_p2pkh(
            Transaction {
                version: tx.version,
                lock_time: tx.lock_time,
                input: tx.input,
                output: tx.output,
            },
            OutPoint { txid: utxo.txid, vout: utxo.vout },
            None, // Default sequence
        )?),
        AddressType::P2sh => {
            let redeem_script = utxo.redeem_script.ok_or(anyhow!("Missing redeem script"))?;
            Ok(InputPair::new_p2sh(
                Transaction {
                    version: tx.version,
                    lock_time: tx.lock_time,
                    input: tx.input,
                    output: tx.output,
                },
                OutPoint { txid: utxo.txid, vout: utxo.vout },
                redeem_script,
                None, // Default sequence
            )?)
        }
        AddressType::P2wpkh => Ok(InputPair::new_p2wpkh(
            TxOut { value: utxo.amount, script_pubkey: utxo.script_pub_key },
            OutPoint { txid: utxo.txid, vout: utxo.vout },
            None,
        )?),
        AddressType::P2wsh => {
            let witness_script = utxo.witness_script.ok_or(anyhow!("Missing witness script"))?;
            Ok(InputPair::new_p2wsh(
                TxOut { value: utxo.amount, script_pubkey: utxo.script_pub_key },
                OutPoint { txid: utxo.txid, vout: utxo.vout },
                witness_script,
                None, // Default sequence
            )?)
        }
        AddressType::P2tr => Ok(InputPair::new_p2tr(
            TxOut { value: utxo.amount, script_pubkey: utxo.script_pub_key },
            OutPoint { txid: utxo.txid, vout: utxo.vout },
            None, // Default sequence
        )?),
        _ => Err(anyhow!("Unsupported AddressType")), // AddressType is non-exhaustive
    }
}
