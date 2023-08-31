use serde::Deserialize;

use crate::broadcaster;
use crate::evm::{deserialize_evm_chain_configs, EvmChainConfig};
use crate::tofnd::Config as TofndConfig;
use crate::url::Url;

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    pub tm_jsonrpc: Url,
    pub tm_grpc: Url,
    pub broadcast: broadcaster::Config,
    #[serde(deserialize_with = "deserialize_evm_chain_configs")]
    pub evm_chains: Vec<EvmChainConfig>,
    pub tofnd_config: TofndConfig,
    pub event_buffer_cap: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tm_jsonrpc: "http://localhost:26657".parse().unwrap(),
            tm_grpc: "tcp://localhost:9090".parse().unwrap(),
            broadcast: broadcaster::Config::default(),
            evm_chains: vec![],
            tofnd_config: TofndConfig::default(),
            event_buffer_cap: 100000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use crate::{broadcaster::key::ECDSASigningKey, evm::ChainName};

    #[test]
    fn deserialize_evm_configs() {
        let rpc_url = "http://localhost:7545/";
        let voting_verifier = ECDSASigningKey::random().address();

        let config_str = format!(
            "
            [[evm_chains]]
            name = 'Ethereum'
            rpc_url = '{rpc_url}'
            voting_verifier = '{voting_verifier}'

            [[evm_chains]]
            name = 'Polygon'
            rpc_url = '{rpc_url}'
            voting_verifier = '{voting_verifier}'

            [[evm_chains]]
            name = 'Optimism'
            rpc_url = '{rpc_url}'
            voting_verifier = '{voting_verifier}'
            l1_chain_name = 'Ethereum'
            ",
        );
        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();
        assert_eq!(cfg.evm_chains.len(), 3);

        let actual = cfg.evm_chains.get(0).unwrap();
        assert_eq!(actual.name, ChainName::Ethereum);
        assert_eq!(actual.rpc_url.as_str(), rpc_url);
        assert_eq!(actual.l1_chain_name, None);
        assert_eq!(actual.voting_verifier, voting_verifier);

        let actual = cfg.evm_chains.get(1).unwrap();
        assert_eq!(actual.name, ChainName::Other("Polygon".into()));
        assert_eq!(actual.rpc_url.as_str(), rpc_url);
        assert_eq!(actual.l1_chain_name, None);
        assert_eq!(actual.voting_verifier, voting_verifier);

        let actual = cfg.evm_chains.get(2).unwrap();
        assert_eq!(actual.name, ChainName::Other("Optimism".into()));
        assert_eq!(actual.rpc_url.as_str(), rpc_url);
        assert_eq!(actual.l1_chain_name, Some(ChainName::Ethereum));
        assert_eq!(actual.voting_verifier, voting_verifier);
    }

    #[test]
    fn deserialize_url() {
        let expected_url = "tcp://localhost:26657";
        let cfg: Config =
            toml::from_str(format!("tm_jsonrpc = '{expected_url}'").as_str()).unwrap();
        assert_eq!(cfg.tm_jsonrpc.as_str(), expected_url);

        let expected_url = "tcp://localhost:9090";
        let cfg: Config = toml::from_str(format!("tm_grpc = '{expected_url}'").as_str()).unwrap();
        assert_eq!(cfg.tm_grpc.as_str(), expected_url);
    }

    #[test]
    fn fail_deserialization() {
        assert!(toml::from_str::<Config>("tm_jsonrpc = 'some other string'").is_err());
        assert!(toml::from_str::<Config>("tm_jsonrpc = 5").is_err());
    }

    #[test]
    fn deserialize_tofnd_config() {
        let url = "http://localhost:50051/";
        let party_uid = "party_uid";
        let key_uid = "key_uid";

        let config_str = format!(
            "
            [tofnd_config]
            url = '{url}'
            party_uid = '{party_uid}'
            key_uid = '{key_uid}'
            ",
        );

        let cfg: Config = toml::from_str(config_str.as_str()).unwrap();

        assert_eq!(cfg.tofnd_config.url.as_str(), url);
        assert_eq!(cfg.tofnd_config.party_uid.as_str(), party_uid);
        assert_eq!(cfg.tofnd_config.key_uid.as_str(), key_uid);
    }
}