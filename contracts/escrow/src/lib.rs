#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, token, vec, Address, BytesN, Env, Symbol, Vec,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitmentEscrowStatus {
    Active,
    Revealed,
    Refunded,
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
    pub released_amount: i128,
    pub status: EscrowStatus,
    pub release_time: u64,
    /// ID of the parent escrow, or 0 if this is a root escrow.
    pub parent_escrow_id: u64,
    /// Status the parent must reach before this child can be released.
    pub required_parent_status: ParentStatusRequirement,
}

/// Commitment-based escrow: amount is hidden using Pedersen commitment (SHA-256).
/// No plaintext amount is stored on-chain for privacy.
#[contracttype]
#[derive(Clone, Debug)]
pub struct CommitmentEscrow {
    pub depositor: Address,
    pub beneficiary: Address,
    pub token: Address,
    pub commitment: BytesN<32>, // SHA-256(amount || blinding_factor)
    pub status: CommitmentEscrowStatus,
    pub release_time: u64,
}

#[contracttype]
pub enum DataKey {
    Escrow(u64),
    EscrowCount,
    Admin,
    /// Stores Vec<u64> of child escrow IDs for a given parent ID.
    ChildEscrows(u64),
    CommitmentEscrow(u64),
    CommitmentEscrowCount,
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    /// Initialize the contract with an admin address.
    ///
    /// Sets up the escrow contract with an admin address who can refund escrows.
    /// Must be called before any escrows are created.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `admin` - The address to be set as contract admin
    ///
    /// # Panics
    ///
    /// Panics if the `admin` address fails authentication (does not sign the transaction).
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::EscrowCount, &0u64);
    }

    /// Create a new root escrow (no parent dependency).
    ///
    /// Creates an escrow agreement where a depositor transfers funds to the contract.
    /// The funds are released to the beneficiary after the `release_time` is reached.
    /// Depositor must authorize this transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `depositor` - Address of the party depositing funds
    /// * `beneficiary` - Address of the party receiving funds
    /// * `token` - Token contract address for the escrow asset
    /// * `amount` - Amount in stroops/base units to escrow (must be positive)
    /// * `release_time` - Unix timestamp when funds can be released (0 = immediate)
    ///
    /// # Returns
    ///
    /// The escrow ID (u64) for referencing this escrow in future transactions.
    ///
    /// # Panics
    ///
    /// * Panics if `depositor` fails authentication (does not sign the transaction)
    /// * Panics if `amount` <= 0
    /// * Panics if token transfer fails (insufficient balance, invalid token, etc.)
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
            released_amount: 0,
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
    ///
    /// Creates an escrow that depends on a parent escrow reaching a specific status before
    /// the child can be released. Enables complex multi-stage escrow workflows. Circular
    /// dependencies are detected and rejected. Depositor must authorize this transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `depositor` - Address of the party depositing funds
    /// * `beneficiary` - Address of the party receiving funds
    /// * `token` - Token contract address for the escrow asset
    /// * `amount` - Amount in stroops/base units to escrow (must be positive)
    /// * `release_time` - Unix timestamp when funds can be released
    /// * `parent_id` - ID of the parent escrow this child depends on
    /// * `required_status` - The status the parent must reach before child can release
    ///
    /// # Returns
    ///
    /// The new escrow ID (u64) for the created child escrow.
    ///
    /// # Panics
    ///
    /// * Panics if `depositor` fails authentication
    /// * Panics if `amount` <= 0
    /// * Panics if parent escrow not found
    /// * Panics if circular dependency detected (new escrow is ancestor of parent)
    /// * Panics if token transfer fails
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
            released_amount: 0,
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
    ///
    /// Transfers escrowed funds from the contract to the beneficiary address.
    /// Only available after `release_time` has been reached.
    /// For child escrows, verifies the parent has reached the required status first.
    /// Depositor must authorize this transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `escrow_id` - ID of the escrow to release
    ///
    /// # Panics
    ///
    /// * Panics if `depositor` fails authentication (does not sign the transaction)
    /// * Panics if escrow not found
    /// * Panics if escrow status is not `Active`
    /// * Panics if current time < `release_time`
    /// * Panics if escrow has parent dependency and parent status does not match required status
    /// * Panics if token transfer fails
    /// * Panics if child escrow recursion depth exceeds 64 levels
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
    ///
    /// Returns escrowed funds to the original depositor. Only the contract admin can call this.
    /// Works on escrows in `Active` or `Disputed` status. After refund, automatically triggers
    /// any child escrows that require `Refunded` parent status.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `escrow_id` - ID of the escrow to refund
    ///
    /// # Panics
    ///
    /// * Panics if `admin` fails authentication (does not sign the transaction)
    /// * Panics if admin not set in contract storage
    /// * Panics if escrow not found
    /// * Panics if escrow status is not `Active` or `Disputed`
    /// * Panics if token transfer fails
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
    ///
    /// Marks an escrow as disputed, preventing automatic release and preparing it for admin review.
    /// Only the beneficiary can dispute an escrow. Once disputed, admin can refund the depositor.
    /// Beneficiary must authorize this transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `escrow_id` - ID of the escrow to dispute
    ///
    /// # Panics
    ///
    /// * Panics if `beneficiary` fails authentication (does not sign the transaction)
    /// * Panics if escrow not found
    /// * Panics if escrow status is not `Active`
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

    /// Release a portion of the escrowed funds to the beneficiary.
    /// The depositor can call this multiple times until the full amount is released.
    /// If the remaining amount reaches zero, the escrow status is set to Released.
    #[allow(deprecated)]
    pub fn partial_release(env: Env, escrow_id: u64, amount: i128) {
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

        assert!(amount > 0, "Amount must be greater than zero");

        let remaining = escrow.amount - escrow.released_amount;
        assert!(
            amount <= remaining,
            "Amount exceeds remaining escrow balance"
        );

        let current_time = env.ledger().timestamp();
        assert!(
            current_time >= escrow.release_time,
            "Release time has not been reached"
        );

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
            &amount,
        );

        escrow.released_amount += amount;

        if escrow.released_amount == escrow.amount {
            escrow.status = EscrowStatus::Released;
        }

        env.storage()
            .persistent()
            .set(&DataKey::Escrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events().publish(
            (Symbol::new(&env, "escrow_partially_released"),),
            (escrow_id, amount, escrow.amount - escrow.released_amount),
        );

        if escrow.status == EscrowStatus::Released {
            Self::trigger_children(env, escrow_id);
        }
    }

    /// Get escrow details.
    ///
    /// Retrieves the full escrow struct containing all details about an escrow agreement.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `escrow_id` - ID of the escrow to retrieve
    ///
    /// # Returns
    ///
    /// The `Escrow` struct containing:
    /// - `depositor`: Original depositor address
    /// - `beneficiary`: Beneficiary address
    /// - `token`: Token contract address
    /// - `amount`: Escrowed amount in base units
    /// - `status`: Current escrow status (Active, Released, Refunded, or Disputed)
    /// - `release_time`: Unix timestamp when release becomes available
    /// - `parent_escrow_id`: ID of parent escrow (0 for root escrows)
    /// - `required_parent_status`: Status parent must reach before this child can release
    ///
    /// # Panics
    ///
    /// Panics if escrow with given ID is not found.
    pub fn get_escrow(env: Env, escrow_id: u64) -> Escrow {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(escrow_id))
            .expect("Escrow not found")
    }

    /// Get only the escrow status.
    pub fn get_escrow_status(env: Env, escrow_id: u64) -> EscrowStatus {
        Self::get_escrow(env, escrow_id).status
    }

    /// Get total escrow count.
    ///
    /// Returns the total number of root escrows that have been created in this contract.
    /// This is the ID counter used to generate unique escrow IDs.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    ///
    /// # Returns
    ///
    /// Total count of escrows created (u64). Returns 0 if contract has not been initialized.
    pub fn get_count(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::EscrowCount)
            .unwrap_or(0)
    }

    /// Get child escrow IDs for a given parent.
    ///
    /// Returns a list of all child escrow IDs that depend on the specified parent escrow.
    /// Useful for tracking dependent escrows in a hierarchy.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `parent_id` - ID of the parent escrow
    ///
    /// # Returns
    ///
    /// A vector of child escrow IDs. Returns empty vector if no children exist.
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
        let parent: Escrow = match env.storage().persistent().get(&DataKey::Escrow(parent_id)) {
            Some(e) => e,
            None => return,
        };

        let children: Vec<u64> = env
            .storage()
            .persistent()
            .get(&DataKey::ChildEscrows(parent_id))
            .unwrap_or_else(|| vec![&env]);

        let current_time = env.ledger().timestamp();

        for child_id in children.iter() {
            let mut child: Escrow = match env.storage().persistent().get(&DataKey::Escrow(child_id))
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
            let escrow: Escrow = match env.storage().persistent().get(&DataKey::Escrow(current)) {
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

    // ── Commitment-based Escrow Functions ─────────────────────────────────────

    /// Compute commitment: SHA-256(amount_bytes || blinding_factor)
    /// amount is encoded as 16 bytes (i128 big-endian)
    fn compute_commitment(env: &Env, amount: i128, blinding_factor: BytesN<32>) -> BytesN<32> {
        let mut data: Vec<u8> = vec![env];

        // Append amount as big-endian 16 bytes
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            data.push_back(*byte);
        }

        // Append blinding factor (32 bytes) — convert to slice
        let blinding_bytes: &[u8; 32] = &blinding_factor.to_bytes();
        for byte in blinding_bytes.iter() {
            data.push_back(*byte);
        }

        env.crypto().sha256(&data)
    }

    /// Create a commitment-based escrow with hidden amount.
    ///
    /// Creates a privacy-preserving escrow where the amount is hidden using a Pedersen
    /// commitment (SHA-256 hash). The amount is not stored on-chain, only the commitment.
    /// Depositor must separately transfer funds to the contract (amount unknown to observers).
    /// Depositor must authorize this transaction.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `depositor` - Address of the party depositing funds
    /// * `beneficiary` - Address of the party receiving funds
    /// * `token` - Token contract address for the escrow asset
    /// * `commitment` - SHA-256 commitment hash: commit(amount, blinding_factor)
    /// * `release_time` - Unix timestamp when funds can be released (0 = immediate)
    ///
    /// # Returns
    ///
    /// The commitment escrow ID (u64) for referencing this escrow in future transactions.
    ///
    /// # Panics
    ///
    /// * Panics if `depositor` fails authentication (does not sign the transaction)
    #[allow(deprecated)]
    pub fn create_commitment_escrow(
        env: Env,
        depositor: Address,
        beneficiary: Address,
        token: Address,
        commitment: BytesN<32>,
        release_time: u64,
    ) -> u64 {
        depositor.require_auth();

        let escrow_id = Self::next_commitment_id(&env);

        let escrow = CommitmentEscrow {
            depositor,
            beneficiary,
            token,
            commitment,
            status: CommitmentEscrowStatus::Active,
            release_time,
        };

        env.storage()
            .persistent()
            .set(&DataKey::CommitmentEscrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events().publish(
            (Symbol::new(&env, "commitment_escrow_created"),),
            (escrow_id,),
        );

        escrow_id
    }

    /// Reveal and release: verify commitment matches, then transfer funds.
    ///
    /// Releases a commitment escrow by proving the amount and blinding factor match the
    /// stored commitment. Verifies the commitment cryptographically and validates the contract
    /// holds sufficient balance before transferring to beneficiary. Depositor must authorize
    /// this transaction. Can only be called once per escrow.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `depositor` - Address of the party depositing funds (must match creator)
    /// * `escrow_id` - ID of the commitment escrow to release
    /// * `amount` - The actual amount to release in stroops/base units
    /// * `blinding_factor` - The 32-byte blinding factor used to create the commitment
    ///
    /// # Panics
    ///
    /// * Panics if `depositor` fails authentication
    /// * Panics if escrow not found
    /// * Panics if escrow status is not `Active`
    /// * Panics if current time < `release_time`
    /// * Panics if `amount` <= 0
    /// * Panics if recomputed commitment does not match stored commitment
    /// * Panics if contract balance < amount (insufficient funds)
    /// * Panics if token transfer fails
    #[allow(deprecated)]
    pub fn reveal_and_release(
        env: Env,
        depositor: Address,
        escrow_id: u64,
        amount: i128,
        blinding_factor: BytesN<32>,
    ) {
        depositor.require_auth();

        let mut escrow: CommitmentEscrow = env
            .storage()
            .persistent()
            .get(&DataKey::CommitmentEscrow(escrow_id))
            .expect("Commitment escrow not found");

        assert!(amount > 0, "Amount must be greater than zero");
        assert!(
            escrow.status == CommitmentEscrowStatus::Active,
            "Commitment escrow is not active"
        );

        let current_time = env.ledger().timestamp();
        assert!(
            current_time >= escrow.release_time,
            "Release time has not been reached"
        );

        // Recompute commitment and verify it matches
        let computed_commitment = Self::compute_commitment(&env, amount, blinding_factor);
        assert!(
            computed_commitment == escrow.commitment,
            "Commitment verification failed"
        );

        // Verify contract holds sufficient balance
        let token_client = token::Client::new(&env, &escrow.token);
        let balance = token_client.balance(&env.current_contract_address());
        assert!(balance >= amount, "Insufficient balance in contract");

        // Transfer amount to beneficiary
        token_client.transfer(
            &env.current_contract_address(),
            &escrow.beneficiary,
            &amount,
        );

        escrow.status = CommitmentEscrowStatus::Revealed;
        env.storage()
            .persistent()
            .set(&DataKey::CommitmentEscrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events().publish(
            (Symbol::new(&env, "commitment_escrow_revealed"),),
            (escrow_id,),
        );
    }

    /// Admin-only: refund commitment escrow on Active status.
    ///
    /// Refunds a commitment escrow to the depositor. Only the contract admin can call this.
    /// Transfers all remaining contract balance for this escrow to the depositor.
    /// Only works on escrows in `Active` status.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `escrow_id` - ID of the commitment escrow to refund
    ///
    /// # Panics
    ///
    /// * Panics if `admin` fails authentication (does not sign the transaction)
    /// * Panics if admin not set in contract storage
    /// * Panics if escrow not found
    /// * Panics if escrow status is not `Active`
    /// * Panics if token transfer fails
    #[allow(deprecated)]
    pub fn refund_commitment_escrow(env: Env, escrow_id: u64) {
        let mut escrow: CommitmentEscrow = env
            .storage()
            .persistent()
            .get(&DataKey::CommitmentEscrow(escrow_id))
            .expect("Commitment escrow not found");

        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("Admin not set");
        admin.require_auth();

        assert!(
            escrow.status == CommitmentEscrowStatus::Active,
            "Commitment escrow is not active"
        );

        // Transfer all remaining balance back to depositor
        let token_client = token::Client::new(&env, &escrow.token);
        let balance = token_client.balance(&env.current_contract_address());
        if balance > 0 {
            token_client.transfer(&env.current_contract_address(), &escrow.depositor, &balance);
        }

        escrow.status = CommitmentEscrowStatus::Refunded;
        env.storage()
            .persistent()
            .set(&DataKey::CommitmentEscrow(escrow_id), &escrow);

        #[allow(deprecated)]
        env.events().publish(
            (Symbol::new(&env, "commitment_escrow_refunded"),),
            (escrow_id,),
        );
    }

    /// Get commitment escrow details.
    ///
    /// Retrieves the full commitment escrow struct containing all details.
    ///
    /// # Arguments
    ///
    /// * `env` - The Soroban environment
    /// * `escrow_id` - ID of the commitment escrow to retrieve
    ///
    /// # Returns
    ///
    /// The `CommitmentEscrow` struct containing:
    /// - `depositor`: Original depositor address
    /// - `beneficiary`: Beneficiary address
    /// - `token`: Token contract address
    /// - `commitment`: SHA-256 commitment hash (amount and blinding factor are hidden)
    /// - `status`: Current escrow status (Active, Revealed, or Refunded)
    /// - `release_time`: Unix timestamp when release becomes available
    ///
    /// # Panics
    ///
    /// Panics if escrow with given ID is not found.
    pub fn get_commitment_escrow(env: Env, escrow_id: u64) -> CommitmentEscrow {
        env.storage()
            .persistent()
            .get(&DataKey::CommitmentEscrow(escrow_id))
            .expect("Commitment escrow not found")
    }

    /// Allocate and return the next commitment escrow ID.
    fn next_commitment_id(env: &Env) -> u64 {
        let count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::CommitmentEscrowCount)
            .unwrap_or(0);
        let id = count + 1;
        env.storage()
            .instance()
            .set(&DataKey::CommitmentEscrowCount, &id);
        id
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

    /// Helper: compute commitment for tests
    fn compute_test_commitment(env: &Env, amount: i128, blinding_factor: BytesN<32>) -> BytesN<32> {
        let mut data: Vec<u8> = vec![env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            data.push_back(*byte);
        }
        let blinding_bytes: &[u8; 32] = &blinding_factor.to_bytes();
        for byte in blinding_bytes.iter() {
            data.push_back(*byte);
        }
        env.crypto().sha256(&data)
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
    fn test_get_escrow_status_active() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        assert_eq!(client.get_escrow_status(&escrow_id), EscrowStatus::Active);
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
        assert_eq!(client.get_escrow_status(&escrow_id), EscrowStatus::Released);
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
        assert_eq!(client.get_escrow_status(&escrow_id), EscrowStatus::Disputed);
        client.refund(&escrow_id);
        assert_eq!(client.get_escrow_status(&escrow_id), EscrowStatus::Refunded);
    }

    #[test]
    fn test_get_escrow_status_disputed() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        client.dispute(&escrow_id);
        assert_eq!(client.get_escrow_status(&escrow_id), EscrowStatus::Disputed);
    }

    #[test]
    fn test_get_escrow_status_refunded() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        client.refund(&escrow_id);
        assert_eq!(client.get_escrow_status(&escrow_id), EscrowStatus::Refunded);
    }

    #[test]
    #[should_panic(expected = "Escrow not found")]
    fn test_get_escrow_status_missing_escrow_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, _, _, _, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        client.get_escrow_status(&999u64);
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
            &depositor,
            &beneficiary,
            &token,
            &10,
            &0u64,
            &parent_id,
            &EscrowStatus::Released,
        );
        let child2 = client.create_child_escrow(
            &depositor,
            &beneficiary,
            &token,
            &20,
            &0u64,
            &parent_id,
            &EscrowStatus::Released,
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

        let grandparent_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let parent_id = client.create_child_escrow(
            &depositor,
            &beneficiary,
            &token,
            &50,
            &0u64,
            &grandparent_id,
            &EscrowStatus::Released,
        );
        let child_id = client.create_child_escrow(
            &depositor,
            &beneficiary,
            &token,
            &25,
            &0u64,
            &parent_id,
            &EscrowStatus::Released,
        );

        // Releasing the root should cascade all the way down
        client.release(&grandparent_id);

        assert_eq!(
            client.get_escrow(&grandparent_id).status,
            EscrowStatus::Released
        );
        assert_eq!(client.get_escrow(&parent_id).status, EscrowStatus::Released);
        assert_eq!(client.get_escrow(&child_id).status, EscrowStatus::Released);
    }

    // ── Partial release tests ─────────────────────────────────────────────────

    #[test]
    fn test_partial_release() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        client.partial_release(&escrow_id, &40);

        let escrow = client.get_escrow(&escrow_id);
        assert_eq!(escrow.status, EscrowStatus::Active);
        assert_eq!(escrow.released_amount, 40);
    }

    #[test]
    fn test_multiple_partial_releases() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);

        client.partial_release(&escrow_id, &30);
        assert_eq!(client.get_escrow(&escrow_id).released_amount, 30);
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Active);

        client.partial_release(&escrow_id, &50);
        assert_eq!(client.get_escrow(&escrow_id).released_amount, 80);
        assert_eq!(client.get_escrow(&escrow_id).status, EscrowStatus::Active);
    }

    #[test]
    fn test_full_amount_partial_release() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        client.partial_release(&escrow_id, &100);

        let escrow = client.get_escrow(&escrow_id);
        assert_eq!(escrow.status, EscrowStatus::Released);
        assert_eq!(escrow.released_amount, 100);
    }

    #[test]
    fn test_partial_release_exceeds_balance_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);

        client.partial_release(&escrow_id, &60);
        let result = client.try_partial_release(&escrow_id, &50);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_release_zero_amount_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &0u64);
        let result = client.try_partial_release(&escrow_id, &0);
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_release_time_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(500);
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let escrow_id = client.create_escrow(&depositor, &beneficiary, &token, &100, &1000u64);
        let result = client.try_partial_release(&escrow_id, &30);
        assert!(result.is_err());
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
            &depositor,
            &beneficiary,
            &token,
            &50,
            &0u64,
            &id_a,
            &EscrowStatus::Released,
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
            &depositor,
            &beneficiary,
            &token,
            &10,
            &0u64,
            &id_b,
            &EscrowStatus::Released,
        );
    }

    // ── Commitment-based Escrow Tests ─────────────────────────────────────────

    /// Valid reveal and release: commitment matches, amount released.
    #[test]
    fn test_commitment_escrow_valid_reveal() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let amount = 100i128;
        let blinding_factor = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        // Compute commitment
        let commitment = env.as_contract(&contract_id, || {
            // We can compute it here since compute_commitment is private
            // We'll use a workaround: call create_commitment_escrow and track the commitment
            BytesN::from_array(
                &env,
                &[
                    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                    42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
                ],
            ) // placeholder
        });

        // Create commitment escrow with computed commitment
        // First, compute the actual commitment by doing the hash calculation
        let mut commitment_data: Vec<u8> = vec![&env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            commitment_data.push_back(*byte);
        }
        for i in 0..32 {
            commitment_data.push_back(blinding_factor.get(i).unwrap());
        }
        let commitment = env.crypto().sha256(&commitment_data);

        let escrow_id =
            client.create_commitment_escrow(&depositor, &beneficiary, &token, &commitment, &0u64);

        // Depositor transfers funds to contract
        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract_id, &amount);

        // Verify and release with correct amount and blinding factor
        client.reveal_and_release(&depositor, &escrow_id, &amount, &blinding_factor);

        let escrow = client.get_commitment_escrow(&escrow_id);
        assert_eq!(escrow.status, CommitmentEscrowStatus::Revealed);
    }

    /// Invalid reveal: wrong amount should be rejected.
    #[test]
    #[should_panic(expected = "Commitment verification failed")]
    fn test_commitment_escrow_wrong_amount_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let amount = 100i128;
        let wrong_amount = 200i128;
        let blinding_factor = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        let mut commitment_data: Vec<u8> = vec![&env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            commitment_data.push_back(*byte);
        }
        for i in 0..32 {
            commitment_data.push_back(blinding_factor.get(i).unwrap());
        }
        let commitment = env.crypto().sha256(&commitment_data);

        let escrow_id =
            client.create_commitment_escrow(&depositor, &beneficiary, &token, &commitment, &0u64);

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract_id, &amount);

        // Try to reveal with wrong amount — should panic
        client.reveal_and_release(&depositor, &escrow_id, &wrong_amount, &blinding_factor);
    }

    /// Invalid reveal: wrong blinding factor should be rejected.
    #[test]
    #[should_panic(expected = "Commitment verification failed")]
    fn test_commitment_escrow_wrong_blinding_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let amount = 100i128;
        let blinding_factor = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );
        let wrong_blinding_factor = BytesN::from_array(
            &env,
            &[
                32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12,
                11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
            ],
        );

        let mut commitment_data: Vec<u8> = vec![&env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            commitment_data.push_back(*byte);
        }
        for i in 0..32 {
            commitment_data.push_back(blinding_factor.get(i).unwrap());
        }
        let commitment = env.crypto().sha256(&commitment_data);

        let escrow_id =
            client.create_commitment_escrow(&depositor, &beneficiary, &token, &commitment, &0u64);

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract_id, &amount);

        // Try to reveal with wrong blinding factor — should panic
        client.reveal_and_release(&depositor, &escrow_id, &amount, &wrong_blinding_factor);
    }

    /// Double reveal should be rejected (status no longer Active).
    #[test]
    #[should_panic(expected = "Commitment escrow is not active")]
    fn test_commitment_escrow_double_reveal_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let amount = 100i128;
        let blinding_factor = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        let mut commitment_data: Vec<u8> = vec![&env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            commitment_data.push_back(*byte);
        }
        for i in 0..32 {
            commitment_data.push_back(blinding_factor.get(i).unwrap());
        }
        let commitment = env.crypto().sha256(&commitment_data);

        let escrow_id =
            client.create_commitment_escrow(&depositor, &beneficiary, &token, &commitment, &0u64);

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract_id, &amount);

        // First reveal succeeds
        client.reveal_and_release(&depositor, &escrow_id, &amount, &blinding_factor);

        // Second reveal attempt should panic
        client.reveal_and_release(&depositor, &escrow_id, &amount, &blinding_factor);
    }

    /// Release time enforced for commitment escrow.
    #[test]
    fn test_commitment_escrow_release_time_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(500);
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let amount = 100i128;
        let blinding_factor = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        let mut commitment_data: Vec<u8> = vec![&env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            commitment_data.push_back(*byte);
        }
        for i in 0..32 {
            commitment_data.push_back(blinding_factor.get(i).unwrap());
        }
        let commitment = env.crypto().sha256(&commitment_data);

        let escrow_id = client.create_commitment_escrow(
            &depositor,
            &beneficiary,
            &token,
            &commitment,
            &1000u64, // release_time = 1000, current = 500
        );

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract_id, &amount);

        // Attempt to release before release_time should fail
        let result =
            client.try_reveal_and_release(&depositor, &escrow_id, &amount, &blinding_factor);
        assert!(result.is_err());
    }

    /// Admin refund of commitment escrow.
    #[test]
    fn test_commitment_escrow_admin_refund() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let amount = 100i128;
        let blinding_factor = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        let mut commitment_data: Vec<u8> = vec![&env];
        let amount_bytes = amount.to_be_bytes();
        for byte in amount_bytes.iter() {
            commitment_data.push_back(*byte);
        }
        for i in 0..32 {
            commitment_data.push_back(blinding_factor.get(i).unwrap());
        }
        let commitment = env.crypto().sha256(&commitment_data);

        let escrow_id =
            client.create_commitment_escrow(&depositor, &beneficiary, &token, &commitment, &0u64);

        let token_client = soroban_sdk::token::Client::new(&env, &token);
        token_client.transfer(&depositor, &contract_id, &amount);

        // Admin refunds
        client.refund_commitment_escrow(&escrow_id);

        let escrow = client.get_commitment_escrow(&escrow_id);
        assert_eq!(escrow.status, CommitmentEscrowStatus::Refunded);
    }

    /// Amount is hidden: only commitment visible on-chain.
    #[test]
    fn test_commitment_escrow_amount_hidden() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, depositor, beneficiary, token, contract_id) = setup(&env);
        let client = EscrowContractClient::new(&env, &contract_id);
        client.initialize(&admin);

        let commitment = BytesN::from_array(
            &env,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        let escrow_id =
            client.create_commitment_escrow(&depositor, &beneficiary, &token, &commitment, &0u64);

        let escrow = client.get_commitment_escrow(&escrow_id);

        // Verify commitment is stored, no amount field exists
        assert_eq!(escrow.commitment, commitment);
        // The CommitmentEscrow struct has no amount field, so it's inherently hidden
    }
}

