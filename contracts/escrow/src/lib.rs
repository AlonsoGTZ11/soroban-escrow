#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, vec, Address, Env, Symbol, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EscrowStatus {
    Active,
    Released,
    Refunded,
    Disputed,
}

/// Encodes the optional parent-status gate.
/// `None` means "no parent requirement" (a root escrow or unconstrained child).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParentStatusRequirement {
    None,
    Status(EscrowStatus),
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Escrow {
    pub depositor: Address,
    pub beneficiary: Address,
    pub token: Address,
    pub amount: i128,
    pub status: EscrowStatus,
    pub release_time: u64,
    /// ID of the parent escrow, or 0 if this is a root escrow.
    pub parent_escrow_id: u64,
    /// Status the parent must reach before this child can be released.
    pub required_parent_status: ParentStatusRequirement,
}

#[contracttype]
pub enum DataKey {
    Escrow(u64),
    EscrowCount,
    Admin,
    /// Stores Vec<u64> of child escrow IDs for a given parent ID.
    ChildEscrows(u64),
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    /// Initialize the contract with an admin address.
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::EscrowCount, &0u64);
    }

    /// Create a new root escrow (no parent dependency).
    #[allow(deprecated)]
    pub fn create_escrow(
        env: Env,
        depositor: Address,
        beneficiary: Address,
        token: Address,
        amount: i128,
        release_time: u64,
    ) -> u64 {
        depositor.require_auth();
        assert!(amount > 0, "Amount must be greater than zero");

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&depositor, &env.current_contract_address(), &amount);

        let escrow_id = Self::next_id(&env);

        let escrow = Escrow {
            depositor,
            beneficiary,
            token,
            amount,
            status: EscrowStatus::Active,
            release_time,
            parent_escrow_id: 0,
            required_parent_status: ParentStatusRequirement::None,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_created"),), (escrow_id,));

        escrow_id
    }

    /// Create a child escrow that is gated on a parent reaching `required_status`.
    #[allow(deprecated)]
    pub fn create_child_escrow(
        env: Env,
        depositor: Address,
        beneficiary: Address,
        token: Address,
        amount: i128,
        release_time: u64,
        parent_id: u64,
        required_status: EscrowStatus,
    ) -> u64 {
        depositor.require_auth();
        assert!(amount > 0, "Amount must be greater than zero");

        // Validate parent exists
        let _parent: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(parent_id))
            .expect("Parent escrow not found");

        // Allocate the new ID first so we can run the cycle check against it.
        let escrow_id = Self::next_id(&env);

        // Circular dependency check: walk up from parent_id; if we reach
        // escrow_id the new escrow would form a cycle.
        assert!(
            !Self::is_ancestor(&env, parent_id, escrow_id),
            "Circular dependency detected"
        );

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&depositor, &env.current_contract_address(), &amount);

        let escrow = Escrow {
            depositor,
            beneficiary,
            token,
            amount,
            status: EscrowStatus::Active,
            release_time,
            parent_escrow_id: parent_id,
            required_parent_status: ParentStatusRequirement::Status(required_status),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(escrow_id), &escrow);

        // Register this child under its parent.
        let mut children: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::ChildEscrows(parent_id))
            .unwrap_or_else(|| vec![&env]);
        children.push_back(escrow_id);
        env.storage()
            .persistent()
            .set(&DataKey::ChildEscrows(parent_id), &children);

        #[allow(deprecated)]
        env.events().publish(
            (Symbol::new(&env, "child_escrow_created"),),
            (escrow_id, parent_id),
        );

        escrow_id
    }

    /// Release funds to beneficiary.
    /// For child escrows, validates parent has reached the required status first.
    #[allow(deprecated)]
    pub fn release(env: Env, escrow_id: u64) {
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .expect("Escrow not found");

        escrow.depositor.require_auth();
        assert!(
            escrow.status == EscrowStatus::Active,
            "Escrow is not active"
        );

        let current_time = env.ledger().timestamp();
        assert!(
            current_time >= escrow.release_time,
            "Release time has not been reached"
        );

        // If this escrow has a parent requirement, verify it.
        if let ParentStatusRequirement::Status(ref required) = escrow.required_parent_status {
            let parent: Escrow = env
                .storage()
                .persistent()
                .get(&DataKey::Escrow(escrow.parent_escrow_id))
                .expect("Parent escrow not found");
            assert!(
                &parent.status == required,
                "Parent escrow has not reached the required status"
            );
        }

        let token_client = token::Client::new(&env, &escrow.token);
        token_client.transfer(
            &env.current_contract_address(),
            &escrow.beneficiary,
            &escrow.amount,
        );

        escrow.status = EscrowStatus::Released;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_released"),), (escrow_id,));

        // Auto-trigger eligible children.
        Self::trigger_children(env, escrow_id);
    }

    /// Refund to depositor — admin only, works on Active or Disputed escrows.
    /// After refund, triggers any children that require Refunded parent status.
    #[allow(deprecated)]
    pub fn refund(env: Env, escrow_id: u64) {
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .expect("Escrow not found");

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not set");
        admin.require_auth();

        assert!(
            escrow.status == EscrowStatus::Active || escrow.status == EscrowStatus::Disputed,
            "Escrow cannot be refunded in current status"
        );

        let token_client = token::Client::new(&env, &escrow.token);
        token_client.transfer(
            &env.current_contract_address(),
            &escrow.depositor,
            &escrow.amount,
        );

        escrow.status = EscrowStatus::Refunded;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_refunded"),), (escrow_id,));

        // Auto-trigger eligible children waiting for Refunded parent status.
        Self::trigger_children(env, escrow_id);
    }

    /// Raise a dispute — beneficiary only.
    #[allow(deprecated)]
    pub fn dispute(env: Env, escrow_id: u64) {
        let mut escrow: Escrow = env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .expect("Escrow not found");

        escrow.beneficiary.require_auth();
        assert!(
            escrow.status == EscrowStatus::Active,
            "Escrow is not active"
        );

        escrow.status = EscrowStatus::Disputed;
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events()
            .publish((Symbol::new(&env, "escrow_disputed"),), (escrow_id,));
    }

    /// Get escrow details.
    pub fn get_escrow(env: Env, escrow_id: u64) -> Escrow {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .expect("Escrow not found")
    }

    /// Get total escrow count.
    pub fn get_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::EscrowCount)
            .unwrap_or(0)
    }

    /// Get child escrow IDs for a given parent.
    pub fn get_child_escrows(env: Env, parent_id: u64) -> Vec<u64> {
        env.storage()
            .persistent()
            .get(&DataKey::ChildEscrows(parent_id))
            .unwrap_or_else(|| vec![&env])
    }

    /// Auto-release all Active children of `parent_id` whose required parent
    /// status matches the parent's current status and whose release_time has passed.
    /// Recursively triggers grandchildren.
    pub fn trigger_children(env: Env, parent_id: u64) {
        let parent: Escrow = match env
            .storage()
            .persistent()
            .get(&DataKey::Escrow(parent_id))
        {
            Some(e) => e,
            None => return,
        };

        let children: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::ChildEscrows(parent_id))
            .unwrap_or_else(|| vec![&env]);

        let current_time = env.ledger().timestamp();

        for i in 0..children.len() {
            let child_id = children.get(i).unwrap();
            let mut child: Escrow = match env
                .storage()
                .persistent()
                .get(&DataKey::Escrow(child_id))
            {
                Some(e) => e,
                None => continue,
            };

            if child.status != EscrowStatus::Active {
                continue;
            }

            let required = match &child.required_parent_status {
                ParentStatusRequirement::None => continue,
                ParentStatusRequirement::Status(s) => s.clone(),
            };

            if required != parent.status {
                continue;
            }

            if current_time < child.release_time {
                continue;
            }

            // All conditions met — release the child automatically.
            let token_client = token::Client::new(&env, &child.token);
            token_client.transfer(
                &env.current_contract_address(),
                &child.beneficiary,
                &child.amount,
            );

            child.status = EscrowStatus::Released;
            env.storage()
                .persistent()
                .set(&DataKey::Escrow(child_id), &child);

            #[allow(deprecated)]
            env.events()
                .publish((Symbol::new(&env, "escrow_released"),), (child_id,));

            // Recursively trigger grandchildren.
            Self::trigger_children(env.clone(), child_id);
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Allocate and return the next escrow ID, incrementing EscrowCount.
    fn next_id(env: &Env) -> u64 {
        let count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::EscrowCount)
            .unwrap_or(0);
        let id = count + 1;
        env.storage().instance().set(&DataKey::EscrowCount, &id);
        id
    }

    /// Returns `true` if `ancestor_id` appears in the parent chain starting
    /// at `start_id`. Caps at 64 hops to guard against malicious cycles
    /// already in storage.
    fn is_ancestor(env: &Env, start_id: u64, ancestor_id: u64) -> bool {
        let mut current = start_id;
        for _ in 0..64u32 {
            let escrow: Escrow = match env
                .storage()
                .persistent()
                .get(&DataKey::Escrow(current))
            {
                Some(e) => e,
                None => return false,
            };
            if escrow.parent_escrow_id == 0 {
                // Root escrow — no more ancestors.
                return false;
            }
            let pid = escrow.parent_escrow_id;
            if pid == ancestor_id {
                return true;
            }
            current = pid;
        }
        false
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

    /// Convenience: deploy contract, mint tokens, return (admin, depositor, beneficiary, token, contract_id).
    fn setup(env: &Env) -> (Address, Address, Address, Address, Address) {
        let admin = Address::generate(env);
        let depositor = Address::generate(env);
        let beneficiary = Address::generate(env);
        let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
        let token = token_contract.address();
        StellarAssetClient::new(env, &token).mint(&depositor, &10_000);
        let contract_id = env.register(EscrowContract, ());
        (admin, depositor, beneficiary, token, contract_id)
    }

    // ── Original tests ────────────────────────────────────────────────────────

    #[test]
    fn test_create_escrow() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        assert_eq!(escrow_id, 1);
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Active);
        assert_eq!(client.get_count(), 1);
    }

    #[test]
    fn test_release() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        client.release(&escrow_id);
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Released);
    }

    #[test]
    fn test_dispute_then_refund() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        client.dispute(&escrow_id);
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Disputed);
        client.refund(&escrow_id);
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Refunded);
    }

    #[test]
    #[should_panic(expected = "Amount must be greater than zero")]
    fn test_zero_amount_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.create_escrow(&depositor, &beneficiary, &token, &0, &0u64);
    }

    #[test]
    fn test_release_time_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(500);
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        // release_time is 1000, current time is 500 — should fail
        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &1000u64);
        let result = client.try_release(&escrow_id);
        assert!(result.is_err());
    }

    // ── Parent-child tests ────────────────────────────────────────────────────

    /// Child cannot be manually released while parent is still Active.
    #[test]
    fn test_child_blocked_before_parent_releases() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let parent_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let child_id = client.create_child_escrow(
            &depositor,
            &beneficiary,
            &token,
            &50,
            &0u64,
            &parent_id,
            &EscrowStatus::Released,
        );

        // Parent is still Active — child release must fail
        let result = client.try_release(&child_id);
        assert!(
            result.is_err(),
            "Child should be blocked while parent is Active"
        );
    }

    /// Child is auto-released (via trigger_children) when parent is released.
    #[test]
    fn test_child_auto_releases_after_parent() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let parent_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let child_id = client.create_child_escrow(
            &depositor,
            &beneficiary,
            &token,
            &50,
            &0u64,
            &parent_id,
            &EscrowStatus::Released,
        );

        // Release parent — trigger_children should cascade to child
        client.release(&parent_id);

        assert_eq!(client.get_escrow(&parent_id).status, EscrowStatus::Released);
        assert_eq!(
            client.get_escrow(&child_id).status,
            EscrowStatus::Released,
            "Child should be auto-released after parent release"
        );
    }

    /// After parent is released, depositor can also manually release an eligible child.
    #[test]
    fn test_child_manual_release_after_parent() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let parent_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        // Child has release_time in the future so trigger_children won't auto-fire it.
        env.ledger().set_timestamp(500);
        let child_id = client.create_child_escrow(
            &depositor,
            &beneficiary,
            &token,
            &50,
            &1000u64, // release_time = 1000
            &parent_id,
            &EscrowStatus::Released,
        );

        // Release parent at t=500 (child not yet auto-triggered due to release_time)
        client.release(&parent_id);
        assert_eq!(client.get_escrow(&child_id).status, EscrowStatus::Active);

        // Advance time past child's release_time
        env.ledger().set_timestamp(1001);
        client.release(&child_id);
        assert_eq!(client.get_escrow(&child_id).status, EscrowStatus::Released);
    }

    /// get_child_escrows returns the registered child IDs.
    #[test]
    fn test_get_child_escrows() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let parent_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let child1 = client.create_child_escrow(
            &depositor, &beneficiary, &token, &10, &0u64,
            &parent_id, &EscrowStatus::Released,
        );
        let child2 = client.create_child_escrow(
            &depositor, &beneficiary, &token, &20, &0u64,
            &parent_id, &EscrowStatus::Released,
        );

        let children = client.get_child_escrows(&parent_id);
        assert_eq!(children.len(), 2);
        assert_eq!(children.get(0).unwrap(), child1);
        assert_eq!(children.get(1).unwrap(), child2);
    }

    /// 3-escrow chain: releasing grandparent cascades through parent to grandchild.
    #[test]
    fn test_chain_of_three_escrows() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let grandparent_id =
            client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let parent_id = client.create_child_escrow(
            &depositor, &beneficiary, &token, &50, &0u64,
            &grandparent_id, &EscrowStatus::Released,
        );
        let child_id = client.create_child_escrow(
            &depositor, &beneficiary, &token, &25, &0u64,
            &parent_id, &EscrowStatus::Released,
        );

        // Releasing the root should cascade all the way down
        client.release(&grandparent_id);

        assert_eq!(client.get_escrow(&grandparent_id).status, EscrowStatus::Released);
        assert_eq!(client.get_escrow(&parent_id).status, EscrowStatus::Released);
        assert_eq!(client.get_escrow(&child_id).status, EscrowStatus::Released);
    }

    /// Circular dependency is detected and rejected.
    ///
    /// We inject a cycle by:
    ///   1. Create escrow A (id=1, root)
    ///   2. Create escrow B as child of A (id=2, parent=1)
    ///   3. Inside env.as_contract(): write A back with parent_escrow_id = B (back-edge)
    ///      and reset EscrowCount to 1 so the next allocation produces id=2
    ///   4. Call create_child_escrow with parent=B(2)
    ///      → is_ancestor(2, new_id=2): walks B→A→B and finds pid==ancestor_id → panic
    #[test]
    #[should_panic(expected = "Circular dependency detected")]
    fn test_circular_dependency_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        // Build chain A(1) ← B(2)
        let id_a = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64); // 1
        let id_b = client.create_child_escrow(
            &depositor, &beneficiary, &token, &50, &0u64,
            &id_a, &EscrowStatus::Released,
        ); // 2

        // Inject back-edge and reset counter — must be done inside the contract context.
        env.as_contract(&contract_id, || {
            // Make A point to B as its parent → creates cycle A→B→A in storage.
            let mut escrow_a: Escrow = env
                .storage()
                .persistent()
                .get(&DataKey::Escrow(id_a))
                .unwrap();
            escrow_a.parent_escrow_id = id_b;
            env.storage()
                .persistent()
                .set(&DataKey::Escrow(id_a), &escrow_a);

            // Reset EscrowCount to id_b-1 so the next allocation produces id=id_b=2.
            // is_ancestor(id_b=2, new_id=2):
            //   iter 1: current=2, pid=1, 1≠2
            //   iter 2: current=1, pid=2, 2==2 → true → panic "Circular dependency detected"
            env.storage()
                .instance()
                .set(&DataKey::EscrowCount, &(id_b - 1));
        });

        // This must panic with "Circular dependency detected".
        client.create_child_escrow(
            &depositor, &beneficiary, &token, &10, &0u64,
            &id_b, &EscrowStatus::Released,
        );
    }
}
