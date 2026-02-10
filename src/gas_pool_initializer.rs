// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use crate::config::CoinInitConfig;
use crate::storage::Storage;
use crate::mys_client::MysClient;
use crate::tx_signer::TxSigner;
use crate::types::GasCoin;
use parking_lot::Mutex;
use std::cmp::min;
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use myso_json_rpc_types::MySoTransactionBlockEffectsAPI;
use myso_types::base_types::MySoAddress;
use myso_types::coin::{PAY_MODULE_NAME, PAY_SPLIT_N_FUNC_NAME};
use myso_types::gas_coin::GAS;
use myso_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use myso_types::transaction::{Argument, Transaction, TransactionData};
use myso_types::MYSO_FRAMEWORK_PACKAGE_ID;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tracing::{debug, error, info, trace};

/// Any coin owned by the sponsor address with balance above target_init_coin_balance * NEW_COIN_BALANCE_FACTOR_THRESHOLD
/// is considered a new coin, and we will try to split it into smaller coins with balance close to target_init_coin_balance.
const NEW_COIN_BALANCE_FACTOR_THRESHOLD: u64 = 200;

/// Assume that initializing the gas pool (i.e. splitting coins) will take at most 12 hours.
const MAX_INIT_DURATION_SEC: u64 = 60 * 60 * 12;

/// Maximum number of coins to process in one initialization cycle to prevent KMS rate limiting
const MAX_COINS_PER_INIT_CYCLE: usize = 1000;

#[derive(Clone)]
struct CoinSplitEnv {
    target_init_coin_balance: u64,
    gas_cost_per_object: u64,
    signer: Arc<dyn TxSigner>,
    sponsor_address: MySoAddress,
    mys_client: MysClient,
    task_queue: Arc<Mutex<VecDeque<JoinHandle<Vec<GasCoin>>>>>,
    total_coin_count: Arc<AtomicUsize>,
    rgp: u64,
}

impl CoinSplitEnv {
    fn enqueue_task(&self, coin: GasCoin) -> Option<GasCoin> {
        if coin.balance <= (self.gas_cost_per_object + self.target_init_coin_balance) * 2 {
            trace!(
                "Skip splitting coin {:?} because it has small balance",
                coin
            );
            return Some(coin);
        }
        let env = self.clone();
        let task = tokio::task::spawn(async move { env.split_one_gas_coin(coin).await });
        self.task_queue.lock().push_back(task);
        None
    }

    fn increment_total_coin_count_by(&self, delta: usize) {
        info!(
            "Number of coins got so far: {}",
            self.total_coin_count
                .fetch_add(delta, std::sync::atomic::Ordering::Relaxed)
                + delta
        );
    }

    async fn split_one_gas_coin(self, mut coin: GasCoin) -> Vec<GasCoin> {
        let rgp = self.rgp;
        let split_count = min(
            // Max number of object mutations per transaction is 2048.
            2000,
            coin.balance / (self.gas_cost_per_object + self.target_init_coin_balance),
        );
        trace!(
            "Evenly splitting coin {:?} into {} coins",
            coin, split_count
        );
        let budget = self.gas_cost_per_object * split_count;
        let effects = loop {
            let mut pt_builder = ProgrammableTransactionBuilder::new();
            let pure_arg = pt_builder.pure(split_count).unwrap();
            pt_builder.programmable_move_call(
                MYSO_FRAMEWORK_PACKAGE_ID,
                PAY_MODULE_NAME.into(),
                PAY_SPLIT_N_FUNC_NAME.into(),
                vec![GAS::type_tag()],
                vec![Argument::GasCoin, pure_arg],
            );
            let pt = pt_builder.finish();
            let tx_data = TransactionData::new_programmable(
                self.sponsor_address,
                vec![coin.object_ref],
                pt,
                budget,
                rgp,
            );
            // Use exponential backoff with jitter to reduce rate limiting issues
            // Start at 100ms, max at 5 seconds, with jitter
            let retry_strategy = ExponentialBackoff::from_millis(100)
                .max_delay(Duration::from_secs(5))
                .map(jitter);

            let sig = match tokio_retry::Retry::spawn(retry_strategy.clone(), || async {
                self.signer
                    .sign_transaction(&tx_data)
                    .await
            }).await {
                Ok(sig) => sig,
                Err(err) => {
                    // Only log final failure, not individual retry attempts
                    debug!("All signing attempts failed for coin splitting, skipping this coin. Error: {:?}", err);
                    // Return empty vector to indicate this coin couldn't be split
                    return vec![];
                }
            };
            let tx = Transaction::from_generic_sig_data(tx_data, vec![sig]);
            debug!(
                "Sending transaction for execution. Tx digest: {:?}",
                tx.digest()
            );
            let result = self.mys_client.execute_transaction(tx.clone(), 10).await;
            match result {
                Ok(effects) => {
                    assert!(
                        effects.status().is_ok(),
                        "Transaction failed. This should never happen. Tx: {:?}, effects: {:?}",
                        tx,
                        effects
                    );
                    break effects;
                }
                Err(e) => {
                    error!("Failed to execute transaction: {:?}", e);
                    // Try to get the updated coin object, but don't crash if this fails
                    let latest_objects = self.mys_client.get_latest_gas_objects([coin.object_ref.0]).await;
                    if let Some((_, Some(updated_coin))) = latest_objects.into_iter().next() {
                        coin = updated_coin;
                        continue;
                    }
                    error!("Failed to get updated coin object after transaction failure. Skipping this coin.");
                    // Skip this coin instead of crashing - return empty result for this coin
                    return vec![];
                }
            }
        };
        let mut result = vec![];
        let new_coin_balance = (coin.balance - budget) / split_count;
        for created in effects.created() {
            result.extend(self.enqueue_task(GasCoin {
                object_ref: created.reference.to_object_ref(),
                balance: new_coin_balance,
            }));
        }
        let remaining_coin_balance = (coin.balance - new_coin_balance * (split_count - 1)) as i64
            - effects.gas_cost_summary().net_gas_usage();
        result.extend(self.enqueue_task(GasCoin {
            object_ref: effects.gas_object().reference.to_object_ref(),
            balance: remaining_coin_balance as u64,
        }));
        self.increment_total_coin_count_by(result.len() - 1);
        result
    }
}

enum RunMode {
    Init,
    Refresh,
}

pub struct GasPoolInitializer {
    _task_handle: JoinHandle<()>,
    // This is always Some. It is None only after the drop method is called.
    cancel_sender: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for GasPoolInitializer {
    fn drop(&mut self) {
        self.cancel_sender.take().unwrap().send(()).unwrap();
    }
}

impl GasPoolInitializer {
    pub async fn start(
        mys_client: MysClient,
        storage: Arc<dyn Storage>,
        coin_init_config: CoinInitConfig,
        signer: Arc<dyn TxSigner>,
    ) -> Self {
        let should_run_init = match storage.is_initialized().await {
            Ok(is_initialized) => !is_initialized,
            Err(err) => {
                error!("Failed to check if storage is initialized: {:?}", err);
                // Assume it needs initialization if we can't check
                true
            }
        };

        // Conditionally flush Redis if we need to start fresh and FORCE_FRESH_START is set
        if should_run_init && std::env::var("FORCE_FRESH_START").is_ok() {
            info!("FORCE_FRESH_START is set and pool needs initialization. Flushing Redis database to start fresh.");
            storage.flush_db().await;
        }

        if should_run_init {
            // If the pool has never been initialized, always run once at the beginning to make sure we have enough coins.
            Self::run_once(
                mys_client.clone(),
                &storage,
                RunMode::Init,
                coin_init_config.target_init_balance,
                &signer,
            )
            .await;
        }
        let (cancel_sender, cancel_receiver) = tokio::sync::oneshot::channel();
        let _task_handle = tokio::spawn(Self::run(
            mys_client,
            storage,
            coin_init_config,
            signer,
            cancel_receiver,
        ));
        Self {
            _task_handle,
            cancel_sender: Some(cancel_sender),
        }
    }

    async fn run(
        mys_client: MysClient,
        storage: Arc<dyn Storage>,
        coin_init_config: CoinInitConfig,
        signer: Arc<dyn TxSigner>,
        mut cancel_receiver: tokio::sync::oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(coin_init_config.refresh_interval_sec)) => {}
                _ = &mut cancel_receiver => {
                    info!("Coin init task is cancelled");
                    break;
                }
            }
            info!("Coin init task waking up and looking for new coins to initialize");
            Self::run_once(
                mys_client.clone(),
                &storage,
                RunMode::Refresh,
                coin_init_config.target_init_balance,
                &signer,
            )
            .await;
        }
    }

    async fn run_once(
        mys_client: MysClient,
        storage: &Arc<dyn Storage>,
        mode: RunMode,
        target_init_coin_balance: u64,
        signer: &Arc<dyn TxSigner>,
    ) {
        let sponsor_address = signer.get_address();
        let acquired_lock = match storage.acquire_init_lock(MAX_INIT_DURATION_SEC).await {
            Ok(acquired) => acquired,
            Err(err) => {
                error!("Failed to acquire initialization lock: {:?}", err);
                // If we can't check the lock, assume we should proceed with caution
                true
            }
        };

        if acquired_lock {
            info!("Acquired init lock. Starting new coin initialization");
        } else {
            info!("Another task is already initializing the pool. Skipping this round");
            return;
        }
        let start = Instant::now();
        let balance_threshold = if matches!(mode, RunMode::Init) {
            info!("The pool has never been initialized. Initializing it for the first time");
            0
        } else {
            target_init_coin_balance * NEW_COIN_BALANCE_FACTOR_THRESHOLD
        };
        let mut all_coins = mys_client
            .get_all_owned_mys_coins_above_balance_threshold(sponsor_address, balance_threshold)
            .await;

        if all_coins.is_empty() {
            info!(
                "No coins with balance above {} found. Skipping new coin initialization",
                balance_threshold
            );
            if let Err(err) = storage.release_init_lock().await {
                error!("Failed to release initialization lock: {:?}", err);
            }
            return;
        }

        // Limit coins per cycle to prevent KMS rate limiting and resource exhaustion
        let coins_to_process = if all_coins.len() > MAX_COINS_PER_INIT_CYCLE {
            info!(
                "Found {} coins above threshold, limiting to {} coins per initialization cycle to prevent KMS rate limiting",
                all_coins.len(),
                MAX_COINS_PER_INIT_CYCLE
            );
            all_coins.truncate(MAX_COINS_PER_INIT_CYCLE);
            all_coins
        } else {
            info!("Processing {} coins in this initialization cycle", all_coins.len());
            all_coins
        };
        let total_coin_count = Arc::new(AtomicUsize::new(coins_to_process.len()));
        let rgp = mys_client.get_reference_gas_price().await;
        let gas_cost_per_object = mys_client
            .calibrate_gas_cost_per_object(sponsor_address, &coins_to_process[0])
            .await;
        info!("Calibrated gas cost per object: {:?}", gas_cost_per_object);
        let result = Self::split_gas_coins(
            coins_to_process,
            CoinSplitEnv {
                target_init_coin_balance,
                gas_cost_per_object,
                signer: signer.clone(),
                sponsor_address,
                mys_client,
                task_queue: Default::default(),
                total_coin_count,
                rgp,
            },
        )
        .await;
        for chunk in result.chunks(5000) {
            if let Err(err) = storage.add_new_coins(chunk.to_vec()).await {
                error!("Failed to add new coins to storage: {:?}", err);
                // Continue trying to add other chunks, but don't crash
            }
        }
        if let Err(err) = storage.release_init_lock().await {
            error!("Failed to release initialization lock: {:?}", err);
            // Don't crash, but this could cause issues with future initialization attempts
        }
        info!(
            "New coin initialization took {:?}s",
            start.elapsed().as_secs()
        );
    }

    async fn split_gas_coins(coins: Vec<GasCoin>, env: CoinSplitEnv) -> Vec<GasCoin> {
        let total_balance: u64 = coins.iter().map(|c| c.balance).sum();
        info!(
            "Splitting {} coins with total balance of {} into smaller coins with target balance of {}. This will result in close to {} coins",
            coins.len(),
            total_balance,
            env.target_init_coin_balance,
            total_balance / env.target_init_coin_balance,
        );

        // Process coins in parallel for maximum speed
        // KMS sidecar can handle concurrent requests with caching and retries
        let mut result = vec![];
        for coin in coins {
            result.extend(env.enqueue_task(coin));
        }
        loop {
            let Some(task) = env.task_queue.lock().pop_front() else {
                break;
            };
            match task.await {
                Ok(split_result) => result.extend(split_result),
                Err(err) => {
                    error!("Coin splitting task failed: {:?}", err);
                }
            }
        }
        let new_total_balance: u64 = result.iter().map(|c| c.balance).sum();
        info!(
            "Splitting finished. Got {} coins. New total balance: {}. Spent {} gas in total",
            result.len(),
            new_total_balance,
            total_balance - new_total_balance
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::config::CoinInitConfig;
    use crate::gas_pool_initializer::{GasPoolInitializer, NEW_COIN_BALANCE_FACTOR_THRESHOLD};
    use crate::storage::connect_storage_for_testing;
    use crate::mys_client::MysClient;
    use crate::test_env::start_mys_cluster;
    use myso_types::gas_coin::MIST_PER_MYSO;

    // TODO: Add more accurate tests.

    #[tokio::test]
    async fn test_basic_init_flow() {
        telemetry_subscribers::init_for_testing();
        let (cluster, signer) = start_mys_cluster(vec![1000 * MIST_PER_MYSO]).await;
        let fullnode_url = cluster.fullnode_handle.rpc_url;
        let storage = connect_storage_for_testing(signer.get_address()).await;
        let mys_client = MysClient::new(&fullnode_url, None).await;
        let _ = GasPoolInitializer::start(
            mys_client,
            storage.clone(),
            CoinInitConfig {
                target_init_balance: MIST_PER_MYSO,
                refresh_interval_sec: 200,
            },
            signer,
        )
        .await;
        assert!(storage.get_available_coin_count().await.unwrap() > 900);
    }

    #[tokio::test]
    async fn test_init_non_even_split() {
        telemetry_subscribers::init_for_testing();
        let (cluster, signer) = start_mys_cluster(vec![10000000 * MIST_PER_MYSO]).await;
        let fullnode_url = cluster.fullnode_handle.rpc_url;
        let storage = connect_storage_for_testing(signer.get_address()).await;
        let target_init_balance = 12345 * MIST_PER_MYSO;
        let mys_client = MysClient::new(&fullnode_url, None).await;
        let _ = GasPoolInitializer::start(
            mys_client,
            storage.clone(),
            CoinInitConfig {
                target_init_balance,
                refresh_interval_sec: 200,
            },
            signer,
        )
        .await;
        assert!(storage.get_available_coin_count().await.unwrap() > 800);
    }

    #[tokio::test]
    async fn test_add_new_funds_to_pool() {
        telemetry_subscribers::init_for_testing();
        let (cluster, signer) = start_mys_cluster(vec![1000 * MIST_PER_MYSO]).await;
        let sponsor = signer.get_address();
        let fullnode_url = cluster.fullnode_handle.rpc_url.clone();
        let storage = connect_storage_for_testing(signer.get_address()).await;
        let mys_client = MysClient::new(&fullnode_url, None).await;
        let _init_task = GasPoolInitializer::start(
            mys_client,
            storage.clone(),
            CoinInitConfig {
                target_init_balance: MIST_PER_MYSO,
                refresh_interval_sec: 1,
            },
            signer,
        )
        .await;
        assert!(storage.is_initialized().await.unwrap());
        let available_coin_count = storage.get_available_coin_count().await.unwrap();
        tracing::debug!("Available coin count: {}", available_coin_count);

        // Transfer some new MySo into the sponsor account.
        let new_addr = *cluster
            .get_addresses()
            .iter()
            .find(|addr| **addr != sponsor)
            .unwrap();
        let tx_data = cluster
            .test_transaction_builder_with_sender(new_addr)
            .await
            .transfer_mys(
                Some(NEW_COIN_BALANCE_FACTOR_THRESHOLD * MIST_PER_MYSO),
                sponsor,
            )
            .build();
        let response = cluster.sign_and_execute_transaction(&tx_data).await;
        tracing::debug!("New transfer effects: {:?}", response.effects.unwrap());

        // Give it some time for the task to pick up the new coin and split it.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let new_available_coin_count = storage.get_available_coin_count().await.unwrap();
        assert!(
            // In an ideal world we should have NEW_COIN_BALANCE_FACTOR_THRESHOLD more coins
            // since we just send a new coin with balance NEW_COIN_BALANCE_FACTOR_THRESHOLD and split
            // into target balance of 1 MySo each. However due to gas cost in splitting in practice
            // we are getting less, depending on gas cost which could change from time to time.
            // Subtract 5 which is an arbitrary small number just to be safe.
            new_available_coin_count
                > available_coin_count + NEW_COIN_BALANCE_FACTOR_THRESHOLD as usize - 5,
            "new_available_coin_count: {}, available_coin_count: {}",
            new_available_coin_count,
            available_coin_count
        );
    }
}
