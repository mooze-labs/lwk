use std::sync::Arc;

use elements::{hashes::Hash, AssetId, OutPoint, Transaction, TxOutSecrets, Txid};
use sqlx::{Executor, PgPool, QueryBuilder};
use tokio::sync::Mutex;

use crate::{
    ElementsNetwork, Error, PersistError, Persister, Update, WolletDescriptor,
};

/// Number of update blobs to keep when pruning.
const KEEP: i64 = 96;
/// Maximum number of parameters allowed in a single postgres statement.
const POSTGRES_BIND_LIMIT: usize = 65535;

/// Persister implementation using a PostgreSQL database.
#[cfg(feature = "postgres")]
pub struct PgPersister {
    wallet_id: i32,
    descriptor: WolletDescriptor,
    conn: PgPool,
    next: Mutex<u64>,
}

#[cfg(feature = "postgres")]
impl PgPersister {
    /// Create a new [`PgPersister`].
    pub async fn new(
        conn: &str,
        _network: ElementsNetwork,
        wallet_id: i32,
        descriptor: WolletDescriptor,
    ) -> Result<Arc<Self>, anyhow::Error> {
        let conn = PgPool::connect(conn).await?;
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS wollet_updates (
                wallet_id INTEGER NOT NULL,
                seq_id BIGINT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                blob BYTEA NOT NULL,
                PRIMARY KEY (wallet_id, seq_id)
            )
        "#,
        )
        .await
        .map_err(|e| PersistError::Other(format!("Could not create persister table: {}", e)))?;

        let last: Option<i64> = sqlx::query_scalar!(
            r#"
                SELECT seq_id FROM wollet_updates
                WHERE wallet_id = $1
                ORDER BY seq_id DESC
                LIMIT 1
            "#,
            wallet_id
        )
        .fetch_optional(&conn)
        .await
        .map_err(|_| PersistError::Other("Could not fetch last seq_id.".to_string()))?;

        let next = last.map(|s| s + 1).unwrap_or(0) as u64;

        Ok(Arc::new(Self {
            wallet_id,
            conn,
            descriptor,
            next: Mutex::new(next),
        }))
    }

    async fn last_seq(&self) -> Result<Option<i64>, PersistError> {
        let last_seq = sqlx::query_scalar!(
            r#"
                SELECT seq_id FROM wollet_updates
                WHERE wallet_id = $1
                ORDER BY seq_id DESC
                LIMIT 1
            "#,
            self.wallet_id
        )
        .fetch_optional(&self.conn)
        .await
        .map_err(|_| PersistError::Other("Could not fetch last seq_id.".to_string()))?;

        Ok(last_seq)
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Update, PersistError> {
        Update::deserialize_decrypted(blob, &self.descriptor)
            .map_err(|e| PersistError::Other(format!("Could not decrypt update: {}", e)))
    }
}

#[cfg(feature = "postgres")]
impl Persister for PgPersister {
    fn get(&self, index: usize) -> Result<Option<Update>, PersistError> {
        let blob_opt: Option<Vec<u8>> = futures::executor::block_on(async {
            sqlx::query_scalar!(
                r#"SELECT blob FROM wollet_updates WHERE wallet_id = $1 AND seq_id = $2"#,
                self.wallet_id,
                (index as i64)
            )
            .fetch_optional(&self.conn)
            .await
            .map_err(|_| PersistError::Other("Could not fetch update blob.".to_string()))
        })?;

        blob_opt
            .as_deref()
            .map(|slice| self.decrypt(slice))
            .transpose()
    }

    fn push(&self, mut update: Update) -> Result<(), PersistError> {
        futures::executor::block_on(async {
            let mut tx = self
                .conn
                .begin()
                .await
                .map_err(|_| PersistError::Other("Could not begin transaction.".to_string()))?;

            let last_seq = self.last_seq().await?;
            let mut overwrite_seq: Option<i64> = None;

            if update.only_tip() {
                if let Some(seq) = last_seq {
                    let prev_blob: Vec<u8> = sqlx::query_scalar!(
                        r#"SELECT blob FROM wollet_updates WHERE wallet_id = $1 AND seq_id = $2"#,
                        self.wallet_id,
                        seq
                    )
                    .fetch_optional(&self.conn)
                    .await
                    .map_err(|e| {
                        PersistError::Other(format!("Could not fetch previous update blob: {}", e))
                    })?
                    .expect("No previous sequence.");

                    let prev_update = self.decrypt(&prev_blob)?;
                    if prev_update.only_tip() {
                        update.wollet_status = prev_update.wollet_status;
                        overwrite_seq = Some(seq);
                    }
                }
            }

            let cipher = update
                .serialize_encrypted(&self.descriptor)
                .map_err(|e| PersistError::Other(format!("Could not serialize update: {}", e)))?;

            match overwrite_seq {
                Some(seq) => {
                    sqlx::query!(
                        r#"
                        UPDATE wollet_updates
                           SET blob = $3, created_at=NOW()
                        WHERE wallet_id=$1 AND seq_id=$2
                        "#,
                        self.wallet_id,
                        seq,
                        cipher
                    )
                    .execute(&self.conn)
                    .await
                    .map_err(|e| {
                        PersistError::Other(format!("Could not update update blob: {}", e))
                    })?;
                }
                None => {
                    let next_seq = last_seq.map(|s| s + 1).unwrap_or(0);
                    sqlx::query!(
                        r#"INSERT INTO wollet_updates (wallet_id, seq_id, blob) VALUES ($1, $2, $3)"#,
                        self.wallet_id,
                        next_seq,
                        cipher
                    )
                    .execute(&self.conn)
                    .await
                    .map_err(|e| PersistError::Other(format!("Could not insert update blob: {}", e)))?;
                }
            }

            if let Some(seq) = last_seq {
                sqlx::query!(
                    "DELETE FROM wollet_updates WHERE wallet_id=$1 AND seq_id < $2",
                    self.wallet_id,
                    seq - KEEP
                )
                .execute(&self.conn)
                .await
                .map_err(|e| PersistError::Other(format!("Could not prune old rows: {}", e)))?;
            }

            tx.commit()
                .await
                .map_err(|e| PersistError::Other(format!("Could not commit transaction: {}", e)))?;

            Ok(())
        })
    }
}

/// UTXO store backed by PostgreSQL.
#[cfg(feature = "postgres")]
pub struct PostgresUtxoStore {
    conn: PgPool,
    wallet_id: i32,
}

#[cfg(feature = "postgres")]
impl PostgresUtxoStore {
    async fn bulk_insert_new_utxos(
        &self,
        utxos: &[(OutPoint, TxOutSecrets)],
    ) -> Result<(), anyhow::Error> {
        struct Utxo(i32, [u8; 32], u32, [u8; 32], u64);

        let mut query_builder =
            QueryBuilder::new("INSERT INTO utxos (wallet_id, txid, vout, asset, amount)");

        let db_utxos = utxos
            .iter()
            .map(|(outpoint, secrets)| {
                Utxo(
                    self.wallet_id,
                    outpoint.txid.as_raw_hash().to_byte_array(),
                    outpoint.vout,
                    secrets.asset.into_inner().to_byte_array(),
                    secrets.value,
                )
            })
            .collect::<Vec<_>>();

        query_builder
            .push_values(
                db_utxos.iter().take(POSTGRES_BIND_LIMIT / 5),
                |mut b, utxo| {
                    b.push_bind(utxo.0)
                        .push_bind(utxo.1)
                        .push_bind(utxo.2 as i32)
                        .push_bind(utxo.3)
                        .push_bind(utxo.4 as i64);
                },
            )
            .push("ON CONFLICT (wallet_id, txid, vout) DO NOTHING");

        let mut tx = self
            .conn
            .begin()
            .await
            .map_err(|e| anyhow::anyhow!("Could not begin transaction: {}", e))?;
        query_builder
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("Could not bulk insert new utxos: {}", e))?;
        tx.commit()
            .await
            .map_err(|e| anyhow::anyhow!("Could not commit transaction: {}", e))?;

        Ok(())
    }

    async fn bulk_update_transactions(
        &self,
        txs: &[(Txid, Transaction)],
    ) -> Result<(), anyhow::Error> {
        struct SpendRecord(i32, [u8; 32], u32);

        let spends = txs
            .iter()
            .flat_map(|(_txid, transaction)| {
                transaction.input.iter().map(|input| {
                    SpendRecord(
                        self.wallet_id,
                        input.previous_output.txid.as_raw_hash().to_byte_array(),
                        input.previous_output.vout,
                    )
                })
            })
            .collect::<Vec<_>>();

        if spends.is_empty() {
            return Ok(());
        }

        let mut query_builder = QueryBuilder::new(
            "UPDATE utxos SET spent = TRUE, reserved = FALSE WHERE (wallet_id, txid, vout) IN",
        );

        query_builder.push_tuples(
            spends.iter().take(POSTGRES_BIND_LIMIT / 3),
            |mut b, spend| {
                b.push_bind(spend.0)
                    .push_bind(spend.1)
                    .push_bind(spend.2 as i32);
            },
        );

        let mut tx = self
            .conn
            .begin()
            .await
            .map_err(|e| anyhow::anyhow!("Could not begin transaction: {}", e))?;
        query_builder
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("Could not bulk update transactions: {}", e))?;
        tx.commit()
            .await
            .map_err(|e| anyhow::anyhow!("Could not commit transaction: {}", e))?;

        Ok(())
    }

    async fn bulk_delete_transactions(&self, txs: &[Txid]) -> Result<(), anyhow::Error> {
        let mut query_builder =
            QueryBuilder::new("DELETE FROM utxos WHERE wallet_id = $1 AND txid IN");

        query_builder.push_tuples(txs.iter().take(POSTGRES_BIND_LIMIT), |mut b, txid| {
            b.push_bind(self.wallet_id)
                .push_bind(txid.as_raw_hash().to_byte_array());
        });

        let mut tx = self
            .conn
            .begin()
            .await
            .map_err(|e| anyhow::anyhow!("Could not begin transaction: {}", e))?;
        query_builder
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("Could not bulk delete transactions: {}", e))?;
        tx.commit()
            .await
            .map_err(|e| anyhow::anyhow!("Could not commit transaction: {}", e))?;

        Ok(())
    }

    /// Reserve specific utxos.
    pub async fn reserve_utxo(&self, utxos: &[OutPoint]) -> Result<(), anyhow::Error> {
        let mut query_builder =
            QueryBuilder::new("UPDATE utxos SET reserved = TRUE WHERE (wallet_id, txid, vout) IN");

        query_builder.push_tuples(utxos.iter().take(POSTGRES_BIND_LIMIT), |mut b, utxo| {
            b.push_bind(self.wallet_id)
                .push_bind(utxo.txid.as_raw_hash().to_byte_array())
                .push_bind(utxo.vout as i32);
        });

        query_builder
            .build()
            .execute(&self.conn)
            .await
            .map_err(|e| anyhow::anyhow!("Could not reserve utxos: {}", e))?;

        Ok(())
    }
}

/// Trait defining operations required from a UTXO store.
#[cfg(feature = "postgres")]
#[async_trait::async_trait]
pub trait UtxoStore {
    async fn apply_update(&self, update: &Update) -> Result<(), anyhow::Error>;
    async fn select_utxos(
        &self,
        amount: u64,
        asset: [u8; 32],
    ) -> Result<Vec<OutPoint>, Error>;
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl UtxoStore for PostgresUtxoStore {
    async fn apply_update(&self, update: &Update) -> Result<(), anyhow::Error> {
        if update.only_tip() {
            return Ok(());
        }

        self.bulk_insert_new_utxos(&update.new_txs.unblinds).await?;
        self.bulk_update_transactions(&update.new_txs.txs).await?;
        self.bulk_delete_transactions(&update.txid_height_delete)
            .await?;

        Ok(())
    }

    async fn select_utxos(
        &self,
        amount: u64,
        asset: [u8; 32],
    ) -> Result<Vec<OutPoint>, Error> {
        let result = sqlx::query!(
            r#"
                SELECT txid, vout, asset, amount FROM utxos
                WHERE wallet_id = $1
                AND asset = $2
                AND spent = false
                AND reserved = false
                ORDER BY height NULLS LAST, amount ASC
            "#,
            self.wallet_id,
            &asset
        )
        .fetch_all(&self.conn)
        .await
        .map_err(|e| Error::Generic(format!(
            "Failed to select UTXOs from database: {}",
            e
        )))?;

        let utxos: Vec<(OutPoint, u64)> = result
            .into_iter()
            .filter_map(|row| match Hash::from_slice(&row.txid) {
                Ok(hash) => {
                    let outpoint = OutPoint {
                        txid: Txid::from_raw_hash(hash),
                        vout: row.vout as u32,
                    };
                    Some((outpoint, row.amount as u64))
                }
                Err(e) => {
                    log::error!("Failed to parse txid {}: {}", hex::encode(&row.txid), e);
                    None
                }
            })
            .collect();

        let total: u64 = utxos.iter().map(|(_, v)| *v).sum();
        let asset_id = AssetId::from_slice(&asset)?;
        if total < amount {
            return Err(Error::InsufficientFunds {
                missing_sats: amount - total,
                asset_id,
                is_token: false,
            });
        }

        let selected = branch_and_bound_with_fallback(&utxos, amount);

        self
            .reserve_utxo(&selected)
            .await
            .map_err(|e| Error::Generic(format!("Failed to reserve UTXOs: {}", e)))?;

        Ok(selected)
    }
}

/// Maximum recursion depth for the BnB algorithm.
#[cfg(feature = "postgres")]
const MAX_BNB_DEPTH: usize = 18;
/// Number of attempts for the knapsack heuristic.
#[cfg(feature = "postgres")]
const KNAPSACK_ATTEMPTS: usize = 100;

/// Select UTXOs using a branch and bound algorithm with knapsack and greedy
/// fallbacks. The algorithm will first try BnB, then knapsack and finally a
/// simple greedy selection if the previous strategies fail.
#[cfg(feature = "postgres")]
pub fn branch_and_bound_with_fallback(utxos: &[(OutPoint, u64)], target: u64) -> Vec<OutPoint> {
    if let Some(r) = branch_and_bound(utxos, target, MAX_BNB_DEPTH) {
        return r.into_iter().map(|(outpoint, _)| outpoint).collect();
    }

    if let Some(r) = knapsack(utxos, target, KNAPSACK_ATTEMPTS) {
        return r.into_iter().map(|(outpoint, _)| outpoint).collect();
    }

    // Greedy fallback
    let mut selected = vec![];
    let mut remaining = target;
    for (outpoint, amount) in utxos.iter() {
        if remaining == 0 {
            break;
        }
        if *amount <= remaining {
            selected.push(*outpoint);
            remaining -= *amount;
        }
    }
    selected
}

#[cfg(feature = "postgres")]
fn branch_and_bound(
    utxos: &[(OutPoint, u64)],
    target: u64,
    max_depth: usize,
) -> Option<Vec<(OutPoint, u64)>> {
    let mut utxos = utxos.to_vec();
    utxos.sort_by(|a, b| b.1.cmp(&a.1));

    let mut cum_sum = vec![0; utxos.len() + 1];
    for i in (0..utxos.len()).rev() {
        cum_sum[i] = cum_sum[i + 1] + utxos[i].1;
    }

    let mut selection = vec![];
    bnb_recursive(&utxos, &cum_sum, target, 0, &mut selection, 0, 0, max_depth)
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
fn bnb_recursive(
    utxos: &[(OutPoint, u64)],
    cum_sums: &[u64],
    target: u64,
    current_sum: u64,
    current_selection: &mut Vec<(OutPoint, u64)>,
    index: usize,
    depth: usize,
    max_depth: usize,
) -> Option<Vec<(OutPoint, u64)>> {
    if current_sum == target {
        return Some(current_selection.clone());
    }

    if current_sum > target || index >= utxos.len() || depth >= max_depth {
        return None;
    }

    if current_sum + cum_sums[index] < target {
        return None;
    }

    let exclude = bnb_recursive(
        utxos,
        cum_sums,
        target,
        current_sum,
        current_selection,
        index + 1,
        depth + 1,
        max_depth,
    );

    if exclude.is_some() {
        return exclude;
    }

    current_selection.push(utxos[index].clone());
    let include = bnb_recursive(
        utxos,
        cum_sums,
        target,
        current_sum + utxos[index].1,
        current_selection,
        index + 1,
        depth + 1,
        max_depth,
    );
    current_selection.pop();

    if include.is_some() {
        return include;
    }

    None
}

#[cfg(feature = "postgres")]
fn knapsack(
    utxos: &[(OutPoint, u64)],
    target: u64,
    attempts: usize,
) -> Option<Vec<(OutPoint, u64)>> {
    use rand::{seq::SliceRandom, Rng};

    let mut rng = rand::thread_rng();
    let mut best: Option<(u64, Vec<(OutPoint, u64)>)> = None;

    for _ in 0..attempts {
        let mut sum = 0u64;
        let mut selection: Vec<(OutPoint, u64)> = Vec::new();

        let mut shuffled = utxos.to_vec();
        shuffled.shuffle(&mut rng);

        for (outpoint, value) in shuffled.iter() {
            if sum >= target {
                break;
            }
            if rng.gen::<bool>() || sum + *value <= target {
                selection.push((*outpoint, *value));
                sum += *value;
            }
        }

        if sum >= target {
            let diff = sum - target;
            if best
                .as_ref()
                .map(|(best_diff, _)| diff < *best_diff)
                .unwrap_or(true)
            {
                best = Some((diff, selection.clone()));
                if diff == 0 {
                    break;
                }
            }
        }
    }

    best.map(|(_, sel)| sel)
}
