
use anyhow::{Result, anyhow};
use prism_client::SignatureBundle;
use prism_keys::SigningKey;
pub use prism_common::{
    account::Account,
    api::{PrismApi, PendingTransaction}
};
use prism_client::PrismHttpClient;
use std::sync::Arc;

use tokio::sync::{oneshot, mpsc};
use tracing::info;

pub async fn run_prism_client(addr: &str, mut rx: mpsc::Receiver<(PrismClientRequest,
    oneshot::Sender<PrismClientResponse>)>, signing_key: &'static SigningKey) -> Result<()> {


    let prism_client = Box::leak(Box::new(PrismHttpClient::new(addr)
        .map_err(|_| anyhow!("Connection to prism web-server has failed")).unwrap()));
    info!("Connected to Prism client at {}", addr);

    loop {
        if let Some((request_type, syn)) = rx.recv().await {
            info!("Channel length: {}", rx.len());
            match request_type {
                PrismClientRequest::RegisterService(service_id) => {
                    let result = prism_client.register_service(service_id.to_string(), signing_key.verifying_key(), &*signing_key)
                        .await
                        .map_err(|_| anyhow!("Could not register the service"))?;
                    let boxed_ptx: Box<dyn PendingTransaction<Timer = <PrismHttpClient as PrismApi>::Timer> + Send + Sync> = Box::new(result);

                    let client_response = PrismClientResponse::PendingTransaction {
                        pending_transaction: boxed_ptx,
                    };
                    let _ = syn.send(client_response);
                },
                PrismClientRequest::CreateAccount{account_id, service_id}=> {
                    let result = prism_client.create_account(account_id, service_id, &signing_key, &signing_key).await.unwrap();
                    let boxed_ptx: Box<dyn PendingTransaction<Timer = <PrismHttpClient as PrismApi>::Timer> + Send + Sync> = Box::new(result);

                    let client_response = PrismClientResponse::PendingTransaction {
                        pending_transaction: boxed_ptx,
                    };
                    let _ = syn.send(client_response);
                },
                PrismClientRequest::SetData{account, data}=> {
                    let sb = SignatureBundle {
                        signature: signing_key.sign(&data),
                        verifying_key: signing_key.verifying_key()
                    };
                    let result = prism_client.set_data(&account, data, sb, &signing_key).await;
                    let _account_resp = result.unwrap().wait_with_interval(tokio::time::Duration::from_secs(2)).await;
                    info!("Account {} updated successfully.", account.id());
                    let _ = syn.send(PrismClientResponse::PendingDataAddition);
                },
            }
        }
    }
}

#[derive(Debug)]
pub enum PrismClientRequest {
    RegisterService(String),
    CreateAccount {
        account_id: String,
        service_id: String
    },
    SetData{
        account: Box<Account>,
        data: Vec<u8>,
    }
}

pub enum PrismClientResponse {
    PendingTransaction{
        pending_transaction:Box<dyn PendingTransaction<Timer = <PrismHttpClient as PrismApi>::Timer> + Send + Sync>,
    },
    PendingDataAddition,
    Account(Account)
}
