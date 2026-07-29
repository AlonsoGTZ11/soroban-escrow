#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, token, Address, Env,
    Symbol,
};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowStatus {
    Active,
    Released,
    Refunded,
    Disputed,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct EscrowData {
    pub depositor: Address,
    pub beneficiary: Address,
    pub token: Address,
    pub amount: i128,
    pub status: EscrowStatus,
    pub release_time: u64,
}

#[contracttype]
pub enum DataKey {
    Escrow,
    Admin,
}

/// Typed contract errors. Plain `panic!`/`assert!` string messages are
/// stripped from optimized release WASM and surface only as a generic VM
/// trap across a real cross-contract call, so lifecycle checks use
/// `panic_with_error!` instead — the error code always propagates intact
/// regardless of optimization or whether the caller is native or WASM.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum EscrowInstanceError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidAmount = 3,
    NotActive = 4,
    ReleaseTimeNotReached = 5,
    CannotRefund = 6,
}

/// Holds the state for a single escrow. Deployed per-instance by
/// `EscrowFactory` so each escrow has its own independent contract,
/// storage, and lifecycle.
#[contract]
pub struct EscrowInstance;

#[contractimpl]
impl EscrowInstance {
    /// Initialize this instance with escrow terms. Can only be called once —
    /// this guards against re-initialization after a factory deployment.
    pub fn initialize(
        env: Env,
        admin: Address,
        depositor: Address,
        beneficiary: Address,
        token: Address,
        amount: i128,
        release_time: u64,
    ) {
        if env.storage().instance().has(&DataKey::Escrow) {
            panic_with_error!(&env, EscrowInstanceError::AlreadyInitialized);
        }
        if amount <= 0 {
            panic_with_error!(&env, EscrowInstanceError::InvalidAmount);
        }
        depositor.require_auth();

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&depositor, &env.current_contract_address(), &amount);

        let escrow = EscrowData {
            depositor,
            beneficiary,
            token,
            amount,
            status: EscrowStatus::Active,
            release_time,
        };
        env.storage().instance().set(&DataKey::Escrow, &escrow);
        env.storage().instance().set(&DataKey::Admin, &admin);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "instance_initialized"),), ());
    }

    /// Release funds to the beneficiary.
    pub fn release(env: Env) {
        let mut escrow = Self::load(&env);
        escrow.depositor.require_auth();
        if escrow.status != EscrowStatus::Active {
            panic_with_error!(&env, EscrowInstanceError::NotActive);
        }
        if env.ledger().timestamp() < escrow.release_time {
            panic_with_error!(&env, EscrowInstanceError::ReleaseTimeNotReached);
        }

        let token_client = token::Client::new(&env, &escrow.token);
        token_client.transfer(
            &env.current_contract_address(),
            &escrow.beneficiary,
            &escrow.amount,
        );

        escrow.status = EscrowStatus::Released;
        env.storage().instance().set(&DataKey::Escrow, &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_released"),), ());
    }

    /// Refund to depositor — admin only, works on Active or Disputed escrows.
    pub fn refund(env: Env) {
        let mut escrow = Self::load(&env);
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, EscrowInstanceError::NotInitialized));
        admin.require_auth();

        if escrow.status != EscrowStatus::Active && escrow.status != EscrowStatus::Disputed {
            panic_with_error!(&env, EscrowInstanceError::CannotRefund);
        }

        let token_client = token::Client::new(&env, &escrow.token);
        token_client.transfer(
            &env.current_contract_address(),
            &escrow.depositor,
            &escrow.amount,
        );

        escrow.status = EscrowStatus::Refunded;
        env.storage().instance().set(&DataKey::Escrow, &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_refunded"),), ());
    }

    /// Raise a dispute — beneficiary only.
    pub fn dispute(env: Env) {
        let mut escrow = Self::load(&env);
        escrow.beneficiary.require_auth();
        if escrow.status != EscrowStatus::Active {
            panic_with_error!(&env, EscrowInstanceError::NotActive);
        }

        escrow.status = EscrowStatus::Disputed;
        env.storage().instance().set(&DataKey::Escrow, &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_disputed"),), ());
    }

    /// Get this instance's escrow details.
    pub fn get_escrow(env: Env) -> EscrowData {
        Self::load(&env)
    }

    fn load(env: &Env) -> EscrowData {
        env.storage()
            .instance()
            .get(&DataKey::Escrow)
            .unwrap_or_else(|| panic_with_error!(env, EscrowInstanceError::NotInitialized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        token::StellarAssetClient,
        Address, Env,
    };

    /// Convenience: register instance, mint tokens, return
    /// (admin, depositor, beneficiary, token, contract_id).
    fn setup(env: &Env) -> (Address, Address, Address, Address, Address) {
        let admin = Address::generate(env);
        let depositor = Address::generate(env);
        let beneficiary = Address::generate(env);
        let asset_admin = Address::generate(env);
        let token_contract = env.register_stellar_asset_contract_v2(asset_admin);
        let token = token_contract.address();
        StellarAssetClient::new(env, &token).mint(&depositor, &10_000);
        let contract_id = env.register(EscrowInstance, ());
        (admin, depositor, beneficiary, token, contract_id)
    }

    #[test]
    fn test_initialize_and_get_escrow() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowInstanceClient::new(&env, &contract_id);

        client.initialize(&admin, &depositor, &beneficiary, &token, &100, &0u64);

        let escrow = client.get_escrow();
        assert_eq!(escrow.status, EscrowStatus::Active);
        assert_eq!(escrow.amount, 100);
        assert_eq!(escrow.depositor, depositor);
        assert_eq!(escrow.beneficiary, beneficiary);
    }

    #[test]
    fn test_initialize_cannot_be_called_twice() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowInstanceClient::new(&env, &contract_id);

        client.initialize(&admin, &depositor, &beneficiary, &token, &100, &0u64);
        let result = client.try_initialize(&admin, &depositor, &beneficiary, &token, &50, &0u64);
        assert!(result.is_err());
    }

    #[test]
    fn test_release() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowInstanceClient::new(&env, &contract_id);

        client.initialize(&admin, &depositor, &beneficiary, &token, &100, &0u64);
        client.release();
        assert_eq!(client.get_escrow().status, EscrowStatus::Released);
    }

    #[test]
    fn test_release_time_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(500);
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowInstanceClient::new(&env, &contract_id);

        client.initialize(&admin, &depositor, &beneficiary, &token, &100, &1000u64);
        let result = client.try_release();
        assert!(result.is_err());
    }

    #[test]
    fn test_dispute_then_refund() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowInstanceClient::new(&env, &contract_id);

        client.initialize(&admin, &depositor, &beneficiary, &token, &100, &0u64);
        client.dispute();
        assert_eq!(client.get_escrow().status, EscrowStatus::Disputed);
        client.refund();
        assert_eq!(client.get_escrow().status, EscrowStatus::Refunded);
    }

    #[test]
    fn test_zero_amount_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowInstanceClient::new(&env, &contract_id);
        let result = client.try_initialize(&admin, &depositor, &beneficiary, &token, &0, &0u64);
        assert!(result.is_err());
    }
}
