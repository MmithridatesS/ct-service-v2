mod key_manager;
use anyhow::{Result, anyhow};
use prism_client::SignatureBundle;
use prism_keys::SigningKey;
pub use prism_common::{
    account::Account,
    api::{PrismApi, PendingTransaction}
};
use prism_client::PrismHttpClient;

use tokio::sync::{oneshot, mpsc};
use tracing::{info, warn};

pub async fn run_prism_client(addr: &str, mut rx: mpsc::Receiver<(PrismClientRequest,
    oneshot::Sender<PrismClientResponse>)>, signing_key: &'static SigningKey) -> Result<()> {

    let mut key_manager = key_manager::KeyManager::new();

    let prism_client = Box::leak(Box::new(PrismHttpClient::new(addr)
        .map_err(|_| anyhow!("Connection to prism web-server has failed"))?));
    info!("Connected to Prism client at {}", addr);

    loop {
        if let Some((request_type, syn)) = rx.recv().await {
            info!("Channel length: {}", rx.len());
            match request_type {
                PrismClientRequest::RegisterService(service_id) => {
                    let result = prism_client.register_service(service_id.to_string(), signing_key.verifying_key(), signing_key)
                        .await
                        .map_err(|_| anyhow!("Could not register the service"))?;


                    let boxed_ptx: Box<dyn PendingTransaction<Timer = <PrismHttpClient as PrismApi>::Timer> + Send + Sync> = Box::new(result);

                    let client_response = PrismClientResponse::PendingTransaction {
                        pending_transaction: boxed_ptx,
                    };
                    let _ = syn.send(client_response);
                },
                PrismClientRequest::CreateAccount{account_id, service_id}=> {
                    if key_manager.get_key(account_id.clone()).is_some() {
                        warn!("Tried to create account with id {} although a signing key for it already exists", &account_id);
                        continue;
                    }
                    let user_signing_key = SigningKey::new_ed25519();
                    let _ = &key_manager.add_key(account_id.clone(), user_signing_key.clone());

                    let result = prism_client.create_account(account_id, service_id, signing_key, &user_signing_key).await
                        .unwrap()
                        .wait_with_interval(tokio::time::Duration::from_secs(1))
                        .await;
                    let _ = syn.send(PrismClientResponse::Account(result.ok()));
                },

                PrismClientRequest::SetData{account, data}=> {
                    let user_signing_key = key_manager.get_key(account.id().to_string());
                    let sb = SignatureBundle {
                        signature: signing_key.sign(&data),
                        verifying_key: signing_key.verifying_key()
                    };
                    let result = prism_client.set_data(&account, data, sb, user_signing_key.unwrap()).await;
                    let _account_resp = result.unwrap().wait_with_interval(tokio::time::Duration::from_secs(1)).await;
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
    Account(Option<Account>)
}
