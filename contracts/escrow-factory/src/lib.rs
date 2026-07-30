#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, xdr::ToXdr, Address, BytesN, Env};

/// Imports the compiled `EscrowInstance` WASM (built by `build.rs`), giving
/// us a typed `Client` for cross-contract calls and a `WASM` byte constant
/// for uploading/testing, without linking the instance's contract code
/// directly into this crate's own WASM output.
mod escrow_instance_contract {
    soroban_sdk::contractimport!(
        file = "../../target/escrow-instance-wasm/wasm32v1-none/release/escrow_instance.wasm"
    );
}

#[contracttype]
pub enum DataKey {
    Admin,
    WasmHash,
    /// Next nonce to allocate for a given depositor.
    Nonce(Address),
    /// Index of deployed escrow addresses, keyed by (depositor, nonce).
    EscrowAddress(Address, u64),
}

/// Deploys and tracks individual `EscrowInstance` sub-contracts, one per
/// escrow, so each escrow has its own storage and independent lifecycle
/// instead of sharing a single contract's state.
#[contract]
pub struct EscrowFactory;

#[contractimpl]
impl EscrowFactory {
    /// Initialize the factory with an admin (used as the refund authority
    /// on every deployed instance) and the WASM hash of `EscrowInstance`
    /// that must already be uploaded to the ledger.
    pub fn initialize(env: Env, admin: Address, escrow_wasm_hash: BytesN<32>) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::WasmHash, &escrow_wasm_hash);
    }

    /// Deploy a new `EscrowInstance` for `depositor`, initialize it with the
    /// given terms, and return its address. The deployed address is
    /// deterministic — see `predict_escrow_address`.
    pub fn create_escrow(
        env: Env,
        depositor: Address,
        beneficiary: Address,
        token: Address,
        amount: i128,
        release_time: u64,
    ) -> Address {
        depositor.require_auth();
        assert!(amount > 0, "Amount must be greater than zero");

        let nonce = Self::get_next_nonce(env.clone(), depositor.clone());
        let salt = Self::compute_salt(&env, &depositor, &beneficiary, nonce);

        let wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::WasmHash)
            .expect("Factory not initialized");
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Factory not initialized");

        let escrow_address = env
            .deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, ());

        escrow_instance_contract::Client::new(&env, &escrow_address).initialize(
            &admin,
            &depositor,
            &beneficiary,
            &token,
            &amount,
            &release_time,
        );

        env.storage().persistent().set(
            &DataKey::EscrowAddress(depositor.clone(), nonce),
            &escrow_address,
        );
        env.storage()
            .persistent()
            .set(&DataKey::Nonce(depositor), &(nonce + 1));

        escrow_address
    }

    /// Compute the address an escrow for (depositor, beneficiary, nonce)
    /// would be deployed to, without deploying it.
    pub fn predict_escrow_address(
        env: Env,
        depositor: Address,
        beneficiary: Address,
        nonce: u64,
    ) -> Address {
        let salt = Self::compute_salt(&env, &depositor, &beneficiary, nonce);
        env.deployer()
            .with_current_contract(salt)
            .deployed_address()
    }

    /// Look up the deployed escrow address for a given depositor/nonce pair.
    pub fn get_escrow_address(env: Env, depositor: Address, nonce: u64) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::EscrowAddress(depositor, nonce))
            .expect("Escrow not found for depositor/nonce")
    }

    /// The nonce that will be used the next time `create_escrow` is called
    /// for this depositor.
    pub fn get_next_nonce(env: Env, depositor: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Nonce(depositor))
            .unwrap_or(0)
    }

    /// Derive a deployment salt from (depositor, beneficiary, nonce) so the
    /// resulting contract address is deterministic and predictable ahead of
    /// deployment.
    fn compute_salt(
        env: &Env,
        depositor: &Address,
        beneficiary: &Address,
        nonce: u64,
    ) -> BytesN<32> {
        let data = (depositor.clone(), beneficiary.clone(), nonce).to_xdr(env);
        env.crypto().sha256(&data).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, token::StellarAssetClient, Address, Env};

    /// Deploy and initialize a factory, returning (factory_client, admin).
    fn setup_factory(env: &Env) -> (EscrowFactoryClient<'_>, Address) {
        let admin = Address::generate(env);
        let wasm_hash = env
            .deployer()
            .upload_contract_wasm(escrow_instance_contract::WASM);
        let factory_id = env.register(EscrowFactory, ());
        let client = EscrowFactoryClient::new(env, &factory_id);
        client.initialize(&admin, &wasm_hash);
        (client, admin)
    }

    fn setup_token(env: &Env, depositor: &Address) -> Address {
        let asset_admin = Address::generate(env);
        let token_contract = env.register_stellar_asset_contract_v2(asset_admin);
        let token = token_contract.address();
        StellarAssetClient::new(env, &token).mint(depositor, &10_000);
        token
    }

    #[test]
    fn test_predicted_address_matches_deployed_address() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup_factory(&env);

        let depositor = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        let token = setup_token(&env, &depositor);

        let predicted = client.predict_escrow_address(&depositor, &beneficiary, &0u64);
        let deployed = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);

        assert_eq!(predicted, deployed);
        assert_eq!(client.get_escrow_address(&depositor, &0u64), deployed);
    }

    #[test]
    fn test_two_escrows_have_different_addresses() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup_factory(&env);

        let depositor = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        let token = setup_token(&env, &depositor);

        let first = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let second = client.create_escrow(&depositor, &beneficiary, &token, &50, &0u64);

        assert_ne!(first, second);
        assert_eq!(client.get_escrow_address(&depositor, &0u64), first);
        assert_eq!(client.get_escrow_address(&depositor, &1u64), second);
    }

    #[test]
    fn test_deployed_escrow_is_initialized_with_correct_terms() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, _admin) = setup_factory(&env);

        let depositor = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        let token = setup_token(&env, &depositor);

        let deployed = client.create_escrow(&depositor, &beneficiary, &token, &250, &1000u64);

        let instance_client = escrow_instance_contract::Client::new(&env, &deployed);
        let escrow = instance_client.get_escrow();
        assert_eq!(escrow.amount, 250);
        assert_eq!(escrow.depositor, depositor);
        assert_eq!(escrow.beneficiary, beneficiary);
    }

    #[test]
    fn test_instance_initialize_cannot_be_called_twice_via_factory() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, admin) = setup_factory(&env);

        let depositor = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        let token = setup_token(&env, &depositor);

        let deployed = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);

        let instance_client = escrow_instance_contract::Client::new(&env, &deployed);
        let result =
            instance_client.try_initialize(&admin, &depositor, &beneficiary, &token, &50, &0u64);
        assert!(result.is_err());
    }
}
