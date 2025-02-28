mod log_list;
mod scheduler;
mod prism_client;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures::future::join_all;
use ctclient::{CTClient, SthResult};
use anyhow::{Result, anyhow};
use prism_client::Account;
use keystore_rs::{KeyChain, KeyStore};
use tokio::sync::{mpsc, oneshot};
use prism_keys::SigningKey::Ed25519;
use tracing::{warn, debug, error, info};
use tracing_subscriber::FmtSubscriber;
use std::sync::Arc;

const SERVICE_ID: &str = "PrivaCT";
#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter("info")
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set subscriber");

    let key = KeyChain.get_or_create_signing_key(SERVICE_ID).unwrap();
    let signing_key = Box::leak(Box::new(Ed25519(Box::new(key))));
    let (tx, rx) = mpsc::channel(1024);

    let scheduler = Arc::new(scheduler::Scheduler::new(60, 15 * 60));
    // running the client_handler
    let prism_client_runner = tokio::spawn(prism_client::run_prism_client("http://127.0.0.1:50524", rx, signing_key));

    //registering the service on the start-up
    let _ = register_service(SERVICE_ID, tx.clone()).await;

    let cached_logs = log_list::service::CachingLogListService::new(std::time::Duration::from_secs(60 * 60 * 24));

    let log_monitor = tokio::spawn(monitor_all_ops(cached_logs, tx.clone(), scheduler));

    tokio::select! {
        res_client = prism_client_runner => {
            match res_client.unwrap() {
                Ok(()) => {
                    info!("Exited prism http client.")
                }, 
                Err(e) => {
                    warn!("Prism client failed with the following error: {}", e)
                }
            }
        },
        log_monitor = log_monitor => {
            match log_monitor.unwrap() {
                Ok(()) => {
                    info!("Exited prism http client.")
                }, 
                Err(e) => {
                    warn!("Prism client failed with the following error: {}", e)
                }
            }
        }
    }
}


async fn monitor_all_ops(cached_logs: log_list::service::CachingLogListService, tx: mpsc::Sender<(prism_client::PrismClientRequest, oneshot::Sender<prism_client::PrismClientResponse>)>, scheduler: Arc<scheduler::Scheduler>) -> Result<()> {
    let operator_list = cached_logs.get_all_operator_names().await.map_err(|_| anyhow!("Could not fetch the operator names"))?;
    let mut jh = vec![];
    for operator in operator_list {
        let scheduler = Arc::clone(&scheduler);
        info!("Updating Logs for operator {} started.", operator);
        let logs = cached_logs.get_all_by_operator(&operator).await.unwrap();
        jh.push(tokio::spawn(monitor_logs(logs, tx.clone(), scheduler)));
    }
    join_all(jh).await;
    Ok(())
}

async fn monitor_logs(logs: Vec<log_list::Log>, tx: mpsc::Sender<(prism_client::PrismClientRequest, oneshot::Sender<prism_client::PrismClientResponse>)>, scheduler: Arc<scheduler::Scheduler>) -> Result<()> {
    let potentially_usable_logs = logs.iter()
        .filter(|log| matches!(log.state, Some(log_list::LogState::Usable { .. })) || 
                      matches!(log.state, Some(log_list::LogState::Readonly { .. })) || 
                      matches!(log.state, Some(log_list::LogState::Retired { .. }))).collect::<Vec<_>>();

    let mut join_handles = vec![];
    if potentially_usable_logs.is_empty() {
        return Ok(());
    }
    info!("found {} potentially usable logs", potentially_usable_logs.len());
    for log in potentially_usable_logs.iter() {
        tokio::time::sleep(scheduler.get_offset()).await;
        let account_create_request = prism_client::PrismClientRequest::CreateAccount{account_id: log.log_id.clone(), service_id: SERVICE_ID.to_string()};
        let (otx, orx) = oneshot::channel();
        let _ = tx.send((account_create_request, otx)).await;
        match orx.await {
            Ok(prism_client::PrismClientResponse::PendingTransaction { pending_transaction }) => {
                let account_res = pending_transaction.wait().await;
                if account_res.is_ok() {
                    info!("Account with ID: {} is created.", account_res.clone().unwrap().id())
                }
                join_handles.push(tokio::spawn(monitor_log(log.clone().clone(),
                    account_res.unwrap(),
                    scheduler.get_interval(),
                    tx.clone())))
            },
            _ => {warn!("Did not get the required response")}

        }
    }
    let _ = join_all(join_handles).await;
    Ok(())
}

async fn monitor_log(log: log_list::Log, account: Account, interval: tokio::time::Duration, tx: mpsc::Sender<(prism_client::PrismClientRequest, oneshot::Sender<prism_client::PrismClientResponse>)>) -> Result<()> {
    info!("Starting to update logs for {}", account.id());
    let mut client = CTClient::new_from_latest_th(&log.url, &log.key).map_err(|e| {
        anyhow!(
            "Error initializing client for log {}: {}",
            log.description,
            e
        )
    })?;

    let mut last_tree_head = [0u8; 32];

    loop {
        let update_result = client.light_update();
        match update_result {
            SthResult::Ok(head) => {
                info!("requesting to add data for {}", &account.id());
                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;

                    let data = log_list::SignedTreeHead::from_ctclient_sth(head.clone());
                    let bytes = data.serialize_json();

                    let request = prism_client::PrismClientRequest::SetData {
                        account: Box::new(account.clone()),
                        data: bytes,
                    };

                    let (otx, orx) = oneshot::channel();
                    let _ = tx.send((request, otx)).await;
                    match orx.await{
                        Ok(prism_client::PrismClientResponse::PendingDataAddition) => {},
                        _ => warn!("unexpected res")
                    }

                }
            }
            SthResult::Err(e) => {
                error!("Error in log {}: {}", log.description, e);
            }
            SthResult::ErrWithSth(e, head) => {
                error!("Error with sth in log {}: {}", log.description, e);

                if !head.root_hash.eq(&last_tree_head) {
                    last_tree_head = head.root_hash;
                    debug!("{}: {}", log.description, BASE64.encode(head.root_hash));
                }
            }
        }

        tokio::time::sleep(interval).await;
    }
}

async fn register_service(service_id: &str, tx: mpsc::Sender<(prism_client::PrismClientRequest, oneshot::Sender<prism_client::PrismClientResponse>)>) -> Result<()> {
    let request = prism_client::PrismClientRequest::RegisterService(service_id.to_string());
    let (otx, orx) = oneshot::channel();
    let send_res = tx.send((request, otx)).await;
    warn!("{:?}", send_res);
    match orx.await {
        Ok(prism_client::PrismClientResponse::PendingTransaction { pending_transaction }) => {
            let account_res = pending_transaction.wait().await;
            if account_res.is_ok() {
                info!("Service with ID: {} is created.", account_res.unwrap().id())
            }
        },
        _ => {warn!("Did not get the required response")}
    }
    Ok(())
}
