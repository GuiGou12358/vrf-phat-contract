#![cfg_attr(not(feature = "std"), no_std, no_main)]

extern crate alloc;
extern crate core;

#[ink::contract(env = pink_extension::PinkEnvironment)]
mod vrf_oracle {
    use alloc::{string::String, vec::Vec};
    use phat_offchain_rollup::clients::ink::{Action, ContractId, InkRollupClient};
    use pink_extension::chain_extension::signing;
    use pink_extension::vrf;
    use pink_extension::{error, info, ResultExt};
    use scale::{Decode, Encode};

    /// Type of response when the offchain rollup communicates with this contract
    const TYPE_ERROR: u8 = 0;
    const TYPE_RESPONSE: u8 = 10;

    /// Message to request the random value
    /// message pushed in the queue by the Ink! smart contract and read by the offchain rollup
    #[derive(Eq, PartialEq, Clone, scale::Encode, scale::Decode)]
    struct RandomValueRequestMessage {
        /// id of the requestor
        requestor_id: AccountId,
        /// nonce of the requestor
        requestor_nonce: u128,
        /// minimum value requested
        min: u64,
        /// maximum value requested
        max: u64,
    }
    /// Message sent to provide a random value
    /// response pushed in the queue by the offchain rollup and read by the Ink! smart contract
    #[derive(Encode, Decode)]
    struct RandomValueResponseMessage {
        /// Type of response
        resp_type: u8,
        /// initial request
        request: RandomValueRequestMessage,
        /// random_value
        random_value: Option<u64>,
        /// when an error occurs
        error: Option<Vec<u8>>,
    }

    #[ink(storage)]
    pub struct Vrf {
        owner: AccountId,
        /// config to send the data to the ink! smart contract
        config: Option<Config>,
        /// Key for signing the rollup tx.
        attest_key: [u8; 32],
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout)
    )]
    struct Config {
        /// The RPC endpoint of the target blockchain
        rpc: String,
        pallet_id: u8,
        call_id: u8,
        /// The rollup anchor address on the target blockchain
        contract_id: ContractId,
        /// Key for sending out the rollup meta-tx. None to fallback to the wallet based auth.
        sender_key: Option<[u8; 32]>,
    }

    #[derive(Encode, Decode, Debug)]
    #[repr(u8)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ContractError {
        BadOrigin,
        ClientNotConfigured,
        InvalidKeyLength,
        InvalidAddressLength,
        NoRequestInQueue,
        FailedToCreateClient,
        FailedToCommitTx,
        FailedToFetchPrice,

        FailedToGetStorage,
        FailedToCreateTransaction,
        FailedToSendTransaction,
        FailedToGetBlockHash,
        FailedToDecode,
        InvalidRequest,
        FailedToCallRollup,

        MinGreaterThanMax,
        DivByZero,
        MulOverFlow,
        AddOverFlow,
        SubOverFlow,
    }

    type Result<T> = core::result::Result<T, ContractError>;

    impl From<phat_offchain_rollup::Error> for ContractError {
        fn from(error: phat_offchain_rollup::Error) -> Self {
            error!("error in the rollup: {:?}", error);
            ContractError::FailedToCallRollup
        }
    }

    impl Vrf {
        #[ink(constructor)]
        pub fn default() -> Self {
            const NONCE: &[u8] = b"attest_key";
            let private_key = signing::derive_sr25519_key(NONCE);

            Self {
                owner: Self::env().caller(),
                attest_key: private_key[..32].try_into().expect("Invalid Key Length"),
                config: None,
            }
        }

        /// Gets the owner of the contract
        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        /// Gets the attestor address used by this rollup
        #[ink(message)]
        pub fn get_attest_address(&self) -> Vec<u8> {
            signing::get_public_key(&self.attest_key, signing::SigType::Sr25519)
        }

        /// Gets the ecdsa address used by this rollup in the meta transaction
        #[ink(message)]
        pub fn get_attest_ecdsa_address(&self) -> Vec<u8> {
            use ink::env::hash;
            let input = signing::get_public_key(&self.attest_key, signing::SigType::Ecdsa);
            let mut output = <hash::Blake2x256 as hash::HashOutput>::Type::default();
            ink::env::hash_bytes::<hash::Blake2x256>(&input, &mut output);
            output.to_vec()
        }

        /// Set attestor key.
        ///
        /// For dev purpose. (admin only)
        #[ink(message)]
        pub fn set_attest_key(&mut self, attest_key: Option<Vec<u8>>) -> Result<()> {
            self.ensure_owner()?;
            self.attest_key = match attest_key {
                Some(key) => key.try_into().or(Err(ContractError::InvalidKeyLength))?,
                None => {
                    const NONCE: &[u8] = b"attest_key";
                    let private_key = signing::derive_sr25519_key(NONCE);
                    private_key[..32]
                        .try_into()
                        .or(Err(ContractError::InvalidKeyLength))?
                }
            };
            Ok(())
        }

        /// Gets the sender address used by this rollup (in case of meta-transaction)
        #[ink(message)]
        pub fn get_sender_address(&self) -> Option<Vec<u8>> {
            if let Some(Some(sender_key)) = self.config.as_ref().map(|c| c.sender_key.as_ref()) {
                let sender_key = signing::get_public_key(sender_key, signing::SigType::Sr25519);
                Some(sender_key)
            } else {
                None
            }
        }

        /// Gets the config of the target consumer contract
        #[ink(message)]
        pub fn get_target_contract(&self) -> Option<(String, u8, u8, ContractId)> {
            self.config
                .as_ref()
                .map(|c| (c.rpc.clone(), c.pallet_id, c.call_id, c.contract_id))
        }

        /// Configures the target consumer contract (admin only)
        #[ink(message)]
        pub fn config_target_contract(
            &mut self,
            rpc: String,
            pallet_id: u8,
            call_id: u8,
            contract_id: Vec<u8>,
            sender_key: Option<Vec<u8>>,
        ) -> Result<()> {
            self.ensure_owner()?;
            self.config = Some(Config {
                rpc,
                pallet_id,
                call_id,
                contract_id: contract_id
                    .try_into()
                    .or(Err(ContractError::InvalidAddressLength))?,
                sender_key: match sender_key {
                    Some(key) => Some(key.try_into().or(Err(ContractError::InvalidKeyLength))?),
                    None => None,
                },
            });
            Ok(())
        }

        /// Transfers the ownership of the contract (admin only)
        #[ink(message)]
        pub fn transfer_ownership(&mut self, new_owner: AccountId) -> Result<()> {
            self.ensure_owner()?;
            self.owner = new_owner;
            Ok(())
        }

        /// Processes a request by a rollup transaction
        #[ink(message)]
        pub fn answer_request(&self) -> Result<Option<Vec<u8>>> {
            let config = self.ensure_client_configured()?;
            let mut client = connect(config)?;

            // Get a request if presents
            let request: RandomValueRequestMessage = client
                .pop()
                .log_err("answer_request: failed to read queue")?
                .ok_or(ContractError::NoRequestInQueue)?;

            let response = self.handle_request(request)?;
            // Attach an action to the tx by:
            client.action(Action::Reply(response.encode()));

            maybe_submit_tx(client, &self.attest_key, config.sender_key.as_ref())
        }

        fn handle_request(
            &self,
            request: RandomValueRequestMessage,
        ) -> Result<RandomValueResponseMessage> {
            let requestor_id = request.requestor_id;
            let requestor_nonce = request.requestor_nonce;
            let min = request.min;
            let max = request.max;

            info!(
                "Request received from {requestor_id:?}/{requestor_nonce} - random value between {min} and {max}"
            );

            if min > max {
                let response = RandomValueResponseMessage {
                    resp_type: TYPE_ERROR,
                    request,
                    random_value: None,
                    error: Some(ContractError::MinGreaterThanMax.encode()),
                };
                return Ok(response);
            }

            let response = match self.inner_get_random(min, max, requestor_id, requestor_nonce) {
                Ok(random_value) => RandomValueResponseMessage {
                    resp_type: TYPE_RESPONSE,
                    request,
                    random_value: Some(random_value),
                    error: None,
                },
                Err(e) => RandomValueResponseMessage {
                    resp_type: TYPE_ERROR,
                    request,
                    random_value: None,
                    error: Some(e.encode()),
                },
            };
            Ok(response)
        }

        /// Simulate and return a random number (admin only - for dev purpose)
        #[ink(message)]
        pub fn get_random(
            &self,
            min: u64,
            max: u64,
            requestor_id: AccountId,
            requestor_nonce: u128,
        ) -> Result<u64> {
            self.ensure_owner()?;
            self.inner_get_random(min, max, requestor_id, requestor_nonce)
        }

        fn inner_get_random(
            &self,
            min: u64,
            max: u64,
            requestor_id: AccountId,
            requestor_nonce: u128,
        ) -> Result<u64> {
            let mut salt: Vec<u8> = Vec::new();
            salt.extend_from_slice(requestor_id.as_ref());
            salt.extend_from_slice(&requestor_nonce.to_be_bytes());

            let output = vrf(&salt);

            // a is between 0 and 255
            let a = output[0] as u128;

            // a * (max - min + 1) / (u8::MAX) + min
            let result = (max as u128)
                .checked_sub(min as u128)
                .ok_or(ContractError::SubOverFlow)?
                .checked_add(1)
                .ok_or(ContractError::AddOverFlow)?
                .checked_mul(a)
                .ok_or(ContractError::MulOverFlow)?
                .checked_div(u8::MAX as u128)
                .ok_or(ContractError::DivByZero)?
                .checked_add(min as u128)
                .ok_or(ContractError::AddOverFlow)? as u64;

            Ok(result)
        }

        /// Returns BadOrigin error if the caller is not the owner
        fn ensure_owner(&self) -> Result<()> {
            if self.env().caller() == self.owner {
                Ok(())
            } else {
                Err(ContractError::BadOrigin)
            }
        }

        /// Returns the config reference or raise the error `ClientNotConfigured`
        fn ensure_client_configured(&self) -> Result<&Config> {
            self.config
                .as_ref()
                .ok_or(ContractError::ClientNotConfigured)
        }
    }

    fn connect(config: &Config) -> Result<InkRollupClient> {
        let result = InkRollupClient::new(
            &config.rpc,
            config.pallet_id,
            config.call_id,
            &config.contract_id,
        )
        .log_err("failed to create rollup client");

        match result {
            Ok(client) => Ok(client),
            Err(e) => {
                error!("Error : {:?}", e);
                Err(ContractError::FailedToCreateClient)
            }
        }
    }

    fn maybe_submit_tx(
        client: InkRollupClient,
        attest_key: &[u8; 32],
        sender_key: Option<&[u8; 32]>,
    ) -> Result<Option<Vec<u8>>> {
        let maybe_submittable = client
            .commit()
            .log_err("failed to commit")
            .map_err(|_| ContractError::FailedToCommitTx)?;

        if let Some(submittable) = maybe_submittable {
            let tx_id = if let Some(sender_key) = sender_key {
                // Prefer to meta-tx
                submittable
                    .submit_meta_tx(attest_key, sender_key)
                    .log_err("failed to submit rollup meta-tx")?
            } else {
                // Fallback to account-based authentication
                submittable
                    .submit(attest_key)
                    .log_err("failed to submit rollup tx")?
            };
            return Ok(Some(tx_id));
        }
        Ok(None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink::env::debug_println;
        use ink::primitives::AccountId;

        struct EnvVars {
            /// The RPC endpoint of the target blockchain
            rpc: String,
            pallet_id: u8,
            call_id: u8,
            /// The rollup anchor address on the target blockchain
            contract_id: ContractId,
            /// When we want to manually set the attestor key for signing the message (only dev purpose)
            attest_key: Vec<u8>,
            /// When we want to use meta tx
            sender_key: Option<Vec<u8>>,
        }

        fn get_env(key: &str) -> String {
            std::env::var(key).expect("env not found")
        }

        fn config() -> EnvVars {
            dotenvy::dotenv().ok();
            let rpc = get_env("RPC");
            let pallet_id: u8 = get_env("PALLET_ID").parse().expect("u8 expected");
            let call_id: u8 = get_env("CALL_ID").parse().expect("u8 expected");
            let contract_id: ContractId = hex::decode(get_env("CONTRACT_ID"))
                .expect("hex decode failed")
                .try_into()
                .expect("incorrect length");
            let attest_key = hex::decode(get_env("ATTEST_KEY")).expect("hex decode failed");
            let sender_key = std::env::var("SENDER_KEY")
                .map(|s| hex::decode(s).expect("hex decode failed"))
                .ok();

            EnvVars {
                rpc: rpc.to_string(),
                pallet_id,
                call_id,
                contract_id: contract_id.into(),
                attest_key,
                sender_key,
            }
        }

        #[ink::test]
        fn test_update_attestor_key() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let mut vrf = Vrf::default();

            // Secret key and address of Alice in localhost
            let sk_alice: [u8; 32] = [0x01; 32];
            let address_alice = hex_literal::hex!(
                "189dac29296d31814dc8c56cf3d36a0543372bba7538fa322a4aebfebc39e056"
            );

            let initial_attestor_address = vrf.get_attest_address();
            assert_ne!(address_alice, initial_attestor_address.as_slice());

            vrf.set_attest_key(Some(sk_alice.into())).unwrap();

            let attestor_address = vrf.get_attest_address();
            assert_eq!(address_alice, attestor_address.as_slice());

            vrf.set_attest_key(None).unwrap();

            let attestor_address = vrf.get_attest_address();
            assert_eq!(initial_attestor_address, attestor_address);
        }

        fn init_contract() -> Vrf {
            let EnvVars {
                rpc,
                pallet_id,
                call_id,
                contract_id,
                attest_key,
                sender_key,
            } = config();

            let mut vrf = Vrf::default();
            vrf.config_target_contract(rpc, pallet_id, call_id, contract_id.into(), sender_key)
                .unwrap();
            vrf.set_attest_key(Some(attest_key)).unwrap();

            vrf
        }

        #[ink::test]
        fn test_random() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let vrf = init_contract();

            let account = AccountId::try_from(*&[1u8; 32]).unwrap();

            let min = 1;
            let max = 10;
            let result = vrf.get_random(min, max, account, 1).unwrap();
            assert!(result >= min);
            assert!(result <= max);
            debug_println!("random number: {result:?}");

            let min = 0;
            let max = u64::MAX;
            let result = vrf.get_random(min, max, account, 2).unwrap();
            assert!(result >= min);
            assert!(result <= max);
            debug_println!("random number: {result:?}");

            assert_eq!(101, vrf.get_random(101, 101, account, 2).unwrap());
            assert_eq!(0, vrf.get_random(0, 0, account, 3).unwrap());
            assert_eq!(
                u64::MAX,
                vrf.get_random(u64::MAX, u64::MAX, account, 3).unwrap()
            );
        }

        #[ink::test]
        #[ignore = "The target contract must be deployed on the Substrate node and a random number request must be submitted"]
        fn answer_request() {
            let _ = env_logger::try_init();
            pink_extension_runtime::mock_ext::mock_all_ext();

            let vrf = init_contract();

            let r = vrf.answer_request().expect("failed to answer request");
            debug_println!("answer request: {r:?}");
        }
    }
}
