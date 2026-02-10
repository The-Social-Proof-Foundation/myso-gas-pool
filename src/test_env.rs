// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use crate::config::{CoinInitConfig, DEFAULT_DAILY_GAS_USAGE_CAP};
use crate::gas_pool::gas_pool_core::GasPoolContainer;
use crate::gas_pool_initializer::GasPoolInitializer;
use crate::metrics::{GasPoolCoreMetrics, GasPoolRpcMetrics};
use crate::rpc::GasPoolServer;
use crate::storage::connect_storage_for_testing;
use crate::mys_client::MysClient;
use crate::tx_signer::{TestTxSigner, TxSigner};
use crate::AUTH_ENV_NAME;
use std::sync::Arc;
use myso_config::local_ip_utils::{get_available_port, localhost_for_testing};
use myso_swarm_config::genesis_config::AccountConfig;
use myso_types::base_types::{ObjectRef, MySoAddress};
use myso_types::crypto::get_account_key_pair;
use myso_types::gas_coin::MIST_PER_MYSO;
use myso_types::signature::GenericSignature;
use myso_types::transaction::{TransactionData, TransactionDataAPI};
use test_cluster::{TestCluster, TestClusterBuilder};
use tracing::debug;

pub async fn start_mys_cluster(init_gas_amounts: Vec<u64>) -> (TestCluster, Arc<dyn TxSigner>) {
    let (sponsor, keypair) = get_account_key_pair();
    let cluster = TestClusterBuilder::new()
        .with_accounts(vec![
            AccountConfig {
                address: Some(sponsor),
                gas_amounts: init_gas_amounts,
            },
            // Besides sponsor, also initialize another account with 1000 MYSO.
            AccountConfig {
                address: None,
                gas_amounts: vec![1000 * MIST_PER_MYSO],
            },
        ])
        .build()
        .await;
    (cluster, TestTxSigner::new(keypair.into()))
}

pub async fn start_gas_station(
    init_gas_amounts: Vec<u64>,
    target_init_coin_balance: u64,
) -> (TestCluster, GasPoolContainer) {
    debug!("Starting MySo cluster..");
    let (test_cluster, signer) = start_mys_cluster(init_gas_amounts).await;
    let fullnode_url = test_cluster.fullnode_handle.rpc_url.clone();
    let sponsor_address = signer.get_address();
    debug!("Starting storage. Sponsor address: {:?}", sponsor_address);
    let storage = connect_storage_for_testing(sponsor_address).await;
    let mys_client = MysClient::new(&fullnode_url, None).await;
    GasPoolInitializer::start(
        mys_client.clone(),
        storage.clone(),
        CoinInitConfig {
            target_init_balance: target_init_coin_balance,
            ..Default::default()
        },
        signer.clone(),
    )
    .await;
    let station = GasPoolContainer::new(
        signer,
        storage,
        mys_client,
        DEFAULT_DAILY_GAS_USAGE_CAP,
        GasPoolCoreMetrics::new_for_testing(),
    )
    .await;
    (test_cluster, station)
}

pub async fn start_rpc_server_for_testing(
    init_gas_amounts: Vec<u64>,
    target_init_balance: u64,
) -> (TestCluster, GasPoolContainer, GasPoolServer) {
    let (test_cluster, container) = start_gas_station(init_gas_amounts, target_init_balance).await;
    let localhost = localhost_for_testing();
    std::env::set_var(AUTH_ENV_NAME, "some secret");
    let server = GasPoolServer::new(
        container.get_gas_pool_arc(),
        localhost.parse().unwrap(),
        get_available_port(&localhost),
        GasPoolRpcMetrics::new_for_testing(),
    )
    .await;
    (test_cluster, container, server)
}

pub async fn create_test_transaction(
    test_cluster: &TestCluster,
    sponsor: MySoAddress,
    gas_coins: Vec<ObjectRef>,
) -> (TransactionData, GenericSignature) {
    let user = test_cluster
        .get_addresses()
        .into_iter()
        .find(|a| *a != sponsor)
        .unwrap();
    let object = test_cluster
        .wallet
        .get_one_gas_object_owned_by_address(user)
        .await
        .unwrap()
        .unwrap();
    let mut tx_data = test_cluster
        .test_transaction_builder_with_gas_object(user, gas_coins[0])
        .await
        .transfer(object, user)
        .build();
    // TODO: Add proper sponsored transaction support to test tx builder.
    tx_data.gas_data_mut().payment = gas_coins;
    tx_data.gas_data_mut().owner = sponsor;
    let user_sig = test_cluster
        .sign_transaction(&tx_data)
        .into_data()
        .tx_signatures_mut_for_testing()
        .pop()
        .unwrap();
    (tx_data, user_sig)
}
