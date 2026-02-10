// Copyright (c) Mysten Labs, Inc.
// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use fastcrypto::encoding::{Base64, Encoding};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{self, json};
use shared_crypto::intent::{Intent, IntentMessage};
use std::str::FromStr;
use std::sync::Arc;
use myso_types::base_types::MySoAddress;
use myso_types::crypto::{Signature, MySoKeyPair};
use myso_types::signature::GenericSignature;
use myso_types::transaction::TransactionData;

#[async_trait::async_trait]
pub trait TxSigner: Send + Sync {
    async fn sign_transaction(&self, tx_data: &TransactionData)
        -> anyhow::Result<GenericSignature>;
    fn get_address(&self) -> MySoAddress;
    fn is_valid_address(&self, address: &MySoAddress) -> bool {
        self.get_address() == *address
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureResponse {
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MySoAddressResponse {
    #[serde(rename = "mysPubkeyAddress")]
    mys_pubkey_address: MySoAddress,
}

pub struct SidecarTxSigner {
    sidecar_url: String,
    client: Client,
    mys_address: MySoAddress,
}

impl SidecarTxSigner {
    pub async fn new(sidecar_url: String) -> Arc<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        let url = format!("{}/{}", sidecar_url, "get-pubkey-address");
        println!("Requesting KMS sidecar address from: {}", url);

        let resp = client
            .get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .unwrap_or_else(|err| panic!("Failed to get pubkey address from {}: {}", url, err));
            
        let status = resp.status();
        if !status.is_success() {
            let error_text = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            panic!("KMS sidecar returned error status {}: {}", status, error_text);
        }
        
        let response_text = resp.text().await
            .unwrap_or_else(|err| panic!("Failed to read response body from {}: {}", url, err));
        println!("KMS sidecar response: {}", response_text);
        
        let mys_address: MySoAddressResponse = serde_json::from_str(&response_text)
            .unwrap_or_else(|err| panic!("Failed to parse address response from {}: {}. Response was: {}", url, err, response_text));
            
        Arc::new(Self {
            sidecar_url,
            client,
            mys_address: mys_address.mys_pubkey_address,
        })
    }
}

#[async_trait::async_trait]
impl TxSigner for SidecarTxSigner {
    async fn sign_transaction(
        &self,
        tx_data: &TransactionData,
    ) -> anyhow::Result<GenericSignature> {
        let bytes = Base64::encode(bcs::to_bytes(&tx_data)?);
        let resp = self
            .client
            .post(format!("{}/{}", self.sidecar_url, "sign-transaction"))
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(20))
            .json(&json!({"txBytes": bytes}))
            .send()
            .await?;

        // Check if the response is successful
        let status = resp.status();
        if !status.is_success() {
            let error_text = resp.text().await?;
            return Err(anyhow!("KMS sidecar returned error status {}: {}", status, error_text));
        }

        // Get the response text to check its structure
        let response_text = resp.text().await?;

        // Try to parse as error response first
        if let Ok(error_resp) = serde_json::from_str::<ErrorResponse>(&response_text) {
            return Err(anyhow!("KMS sidecar error: {}", error_resp.error));
        }

        // Try to parse as success response
        let sig_bytes: SignatureResponse = serde_json::from_str(&response_text)
            .map_err(|_| anyhow!("Failed to parse KMS sidecar response: {}", response_text))?;

        let sig = GenericSignature::from_str(&sig_bytes.signature)
            .map_err(|err| anyhow!(err.to_string()))?;
        Ok(sig)
    }

    fn get_address(&self) -> MySoAddress {
        self.mys_address
    }
}

pub struct TestTxSigner {
    keypair: MySoKeyPair,
}

impl TestTxSigner {
    pub fn new(keypair: MySoKeyPair) -> Arc<Self> {
        Arc::new(Self { keypair })
    }
}

#[async_trait::async_trait]
impl TxSigner for TestTxSigner {
    async fn sign_transaction(
        &self,
        tx_data: &TransactionData,
    ) -> anyhow::Result<GenericSignature> {
        let intent_msg = IntentMessage::new(Intent::myso_transaction(), tx_data);
        let sponsor_sig = Signature::new_secure(&intent_msg, &self.keypair).into();
        Ok(sponsor_sig)
    }

    fn get_address(&self) -> MySoAddress {
        (&self.keypair.public()).into()
    }
}
