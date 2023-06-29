use dotenv::dotenv;
use eyre::Result;
use log::{error, info};
use janus_rpc;
use couch_rs::prelude::*;
use std::convert::Infallible;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    colog::init();
    let (addr, server_handle) = run_server().await.unwrap();
    let url = format!("http://{}", addr);
    println!("Server started, listening on {url}");

    server_handle.stopped().await;

    let mut app = janus_rpc::JanusRpc::new();

    // Register the RPC methods
    app.add_rpc_method("verify_solidity", Box::new(verify_solidity));

    // Start the server
    app.listen("127.0.0.1:8000", |req| async move {
        match req.method() {
            "POST" => {
                let body = req.into_body().data().await.unwrap();
                let result = app.handle_rpc_request(&body).await;
                Ok::<_, Infallible>(Response::builder()
                    .status(200)
                    .header("Content-Type", "application/json")
                    .body(Body::from(result))
                    .unwrap())
            }
            _ => Ok::<_, Infallible>(Response::builder()
                .status(405)
                .body(Body::from("Method Not Allowed"))
                .unwrap()),
        }
    })
    .await
    .unwrap();

    Ok(())
}