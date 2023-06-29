use halo2curves::bn256::Fr;
use jsonrpsee::{
    core::{async_trait, RpcResult as Result, __reexports::serde_json},
    proc_macros::rpc,
    tracing::info,
};

use crate::request::request;
use core::panic;
use ezkl::{
    commands::{Cli, Commands},
    execute::ExecutionError,
    pfsys::{prepare_data, prepare_model_circuit_and_public_input},
};
use ezkl::{
    commands::{RunArgs, StrategyType, TranscriptType},
    execute::run,
};
use halo2_proofs::{dev::MockProver, poly::commitment::ParamsProver};
use serde_json::Value;
use std::collections::HashMap;
use std::{env, error::Error, fs::File, sync::Arc};
use std::{io::prelude::*, path::PathBuf};

use jsonrpsee::tracing::Value;

pub struct JanusRpc {
    auth_log: HashMap<String, Vec<u64>>,
}

#[rpc(server, client)]
trait JanusApi {
    #[method(name = "forward")]
    async fn forward(&self, input_data: Value) -> Result<Value>;
    #[method(name = "mock")]
    async fn mock(&self, input_data: Value, target_output_data: Value) -> Result<bool>;
    #[method(name = "submit_proof")]
    async fn submit_proof(
        &self,
        input_data: Value,
        target_output_data: Value,
        user_address: String,
    ) -> Result<bool>;
    #[method(name = "verify_aggr_proof")]
    async fn verify_aggr_proof(&self, input_data: Value, target_output_data: Value)
        -> Result<bool>;
    #[method(name = "verify_solidity")]
    async fn verify_solidity(&self) -> Result<bool>;
}

const SERVER_ARGS: RunArgs = RunArgs {
    tolerance: 0_usize,
    scale: 4_i32,
    bits: 10_usize,
    logrows: 12_u32,
    public_inputs: false,
    public_outputs: true,
    public_params: false,
    max_rotations: 512_usize,
};

impl JanusRpc {
    pub fn new() -> Self {
        JanusRpc {
            auth_log: HashMap::new(),
        }
    }

    fn add_entry(&mut self, key: String, value: u64) {
        let entry = self.auth_log.entry(key).or_insert_with(Vec::new);
        entry.push(value);
    }

    fn get_entry(&self, key: &str) -> Option<&Vec<u64>> {
        self.auth_log.get(key)
    }

    fn remove_entry(&mut self, key: &str) {
        self.auth_log.remove(key);
    }

    // Here, we forward our MobileNetV2 model to ezkl
    async fn forward(&self, input_data: Value) -> Result<Value> {
        let cli = Cli {
            command: Commands::Forward {
                data: "./data/MobileNetV2/input.json".to_string(),
                model: "./data/MobileNetV2/network.onnx".to_string(),
                output: "output.json".to_string(),
            },
            args: SERVER_ARGS,
        };
        env::set_var("EZKLCONF", "./data/forward.json");
        let input_data_str = serde_json::to_string(&input_data)?;
        store_json_data(&input_data_str, "./data/MobileNetV2/input.json").unwrap();
        run(cli).await.unwrap();
        let output = retrieve_json_data("output.json").unwrap();
        Ok(output)
    }

    async fn mock(
        &self,
        input_data: Value,
        target_output_data: Value,
        hunt_id: String,
    ) -> (Result<bool>) {
        env::set_var("EZKLCONF", "./data/mock.json");

        let cli = Cli {
            command: Commands::Mock {
                data: "./data/MobileNetV2/input.json".to_string(),
                model: "./data/MobileNetV2/network.onnx".to_string(),
            },
            args: SERVER_ARGS,
        };
        let input_data_str = serde_json::to_string(&input_data)?;
        store_json_data(&input_data_str, "./data/MobileNetV2/input.json")?;
        let output_data = input_data["output_data"].clone();
        // TODO: compare target_output_data and auth_log entry
        let target_output_data = target_output_data["target_output_data"].clone();
        let output_data_vec: Vec<Vec<f64>> = serde_json::from_value(output_data)?;
        let target_output_data_vec: Vec<Vec<f64>> = serde_json::from_value(target_output_data)?;
        let distance = euclidean_distance(&output_data_vec[0], &target_output_data_vec[0]);
        let res = run(cli).await;
        print!("res: {:?}", res);
        match res {
            Ok(_) => {
                info!("mock success");
                if distance < 0.1 {
                    self.submit_proof(input_data, target_output_data, hunt_id)
                        .await;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => Ok(false),
        }
    }

    async fn submit_proof(
        &self,
        input_data: Value,
        target_output_data: Value,
        hunt_id: String,
    ) -> (Result<bool>, String) {
        let cli = Cli {
            command: Commands::Prove {
                data: "./data/MobileNetV2/input.json".to_string(),
                model: PathBuf::from("./data/MobileNetV2/network.onnx"),
                vk_path: PathBuf::from("MobileNetV2.vk"),
                proof_path: PathBuf::from("MobileNetV2.pf"),
                params_path: PathBuf::from("kzg.params"),
                transcript: TranscriptType::EVM,
                strategy: StrategyType::Single,
            },
            args: SERVER_ARGS,
        };
        env::set_var("EZKLCONF", "./data/submit_proof.json");
        let input_data_str = serde_json::to_string(&input_data)?;
        store_json_data(&input_data_str, "./data/MobileNetV2/input.json")?;
        // TODO: compare target_output_data and auth_log entry
        let output_data = input_data["output_data"].clone();
        let target_output_data = target_output_data["target_output_data"].clone();
        let output_data_vec: Vec<Vec<f64>> = serde_json::from_value(output_data)?;
        let target_output_data_vec: Vec<Vec<f64>> = serde_json::from_value(target_output_data)?;
        let distance = euclidean_distance(&output_data_vec[0], &target_output_data_vec[0]);

        let res = run(cli).await;
        print!("res: {:?}", res);
        match res {
            Ok(_) => {
                info!("mock success");
                if distance < 0.1 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => Ok(false),
        }
    }

    async fn verify_aggr_proof(
        &self,
        input_data: Value,
        target_output_data: Value,
    ) -> Result<bool> {
        env::set_var("EZKLCONF", "./data/submit_proof.json");
        let cli = Cli {
            command: Commands::VerifyAggr {
                proof_path: PathBuf::from("MobileNetV2.pf"),
                vk_path: PathBuf::from("MobileNetV2.vk"),
                params_path: PathBuf::from("kzg.params"),
                transcript: TranscriptType::EVM,
            },
            args: SERVER_ARGS,
        };
        let input_data_str = serde_json::to_string(&input_data)?;
        store_json_data(&input_data_str, "./data/MobileNetV2/input.json").unwrap();
        let output_data = input_data["output_data"].clone();
        let target_output_data = target_output_data["target_output_data"].clone();
        let output_data_vec: Vec<Vec<f64>> = serde_json::from_value(output_data).unwrap();
        let target_output_data_vec: Vec<Vec<f64>> =
            serde_json::from_value(target_output_data).unwrap();
        let distance = euclidean_distance(&output_data_vec[0], &target_output_data_vec[0]);
        let res = run(cli).await;
        match res {
            Ok(_) => {
                info!("Verify success");
                if distance < 0.1 {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(e) => {
                info!("Verify failed");
                Ok(false)
            }
        }
    }

    // TODO: finish verify with Solidity contract (ethers.rs)
    async fn verify_solidity(&self, user_address: String, photo_preimage: Value) -> Result<bool> {
        // send data and generate proof
        let cli: Cli {
            command: Commands::Prove {
                data: "./data/MobileNetV2/input.json".to_string(),
                model: PathBuf::from("./data/MobileNetV2/network.onnx"),
                vk_path: PathBuf::from("MobileNetV2.vk"),
                proof_path: PathBuf::from("MobileNetV2.pf"),
                params_path: PathBuf::from("kzg.params"),
                transcript: TranscriptType::EVM,
                strategy: StrategyType::Single,
            },
            args: SERVER_ARGS,
        };
        }
        }
        // send proof to verifier contract with verify_caller.rs
        // calculate euclidian distance and return true if < 0.1
        // is this address in the auth log? if so, compare to target. If not, set target to address
        if self.auth_log.contains_key(user_address) {
            
        }
    }
}

fn store_json_data(json_str: &str, path: &str) -> std::io::Result<()> {
    // Open the file for writing
    let mut file = File::create(path)?;

    // Write the Json data to the file
    file.write_all(json_str.as_bytes())?;

    Ok(())
}

fn retrieve_json_data(path: &str) -> std::io::Result<Value> {
    // Open the file for reading
    let mut file = File::open(path)?;

    // Read the file contents into a string
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse the JSON string into a JSON object
    let json_data: Value = serde_json::from_str(&contents)?;

    Ok(json_data)
}

// Finding the Euclidian distance between the two output tensors of our machine learning model
fn euclidean_distance(a: &Vec<f64>, b: &Vec<f64>) -> f64 {
    // check to make sure that a and b are the same length since the tensors should be the same
    assert_eq!(
        a.len(),
        b.len(),
        "The lengths of a and b are {} and {}. They should be the same length.",
        a.len(),
        b.len()
    );

    a.iter()
        .zip(b)
        .map(|(&x, &y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_euclidean_distance() {
        let a: &Vec<f64> = &vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let b: &Vec<f64> = &vec![10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0];
        assert_eq!(euclidean_distance(&a, &b), 18.16590212458495);
    }

    #[test]
    #[should_panic(
        expected = "The lengths of a and b are 10 and 9. They should be the same length."
    )]
    fn test_euclidean_distance_different_lengths() {
        let a: &Vec<f64> = &vec![1.0, 2.0, 3.8, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 110.8];
        let b: &Vec<f64> = &vec![10.0, 9.0, 84.0, 7.0, 6.4, 51.0, 4.0, 3.8, 2.0];
        euclidean_distance(&a, &b);
    }
}
