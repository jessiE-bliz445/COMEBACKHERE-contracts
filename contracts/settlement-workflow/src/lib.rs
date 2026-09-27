#![no_std]

use compliance_client::ComplianceClient;
pub use multisig::Settlement;
pub use multisig::SettlementStatus;
pub use multisig::TreasuryError;
use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, Address, Env, Symbol, Vec,
};

/// Error type returned by `execute_with_compliance`.
/// Alias for `TreasuryError` to match the naming convention used in tests.
pub type SettlementWorkflowError = TreasuryError;

/// Cross-contract call surface this crate needs from the treasury contract.
/// `#[contractclient]` on a bare trait generates only an invocation client, not
/// a dependency on the `comebackhere-treasury` implementation crate, so this
/// contract doesn't statically link treasury's wasm exports (`pause`,
/// `unpause`, ...) alongside its own. See the `compliance_client` crate for
/// the same pattern, and Cargo.toml for why `treasury` is dev-only here.
#[contractclient(name = "TreasuryOnlyClient")]
pub trait TreasuryInterface {
    fn execute_settlement(env: Env, signer: Address, settlement_id: u64, token_contract: Address);
    fn get_signer_weight(env: Env, signer: Address) -> u32;
    /// Read-only settlement lookup. `#[contractimpl]` also generates a
    /// `try_get_settlement` client variant that never mutates state.
    fn get_settlement(env: Env, settlement_id: u64) -> Settlement;
}

/// Why a simulated settlement would not succeed, mirroring the checks in
/// [`SettlementWorkflowContract::execute_with_compliance`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulationFailure {
    /// `Compliance::is_allowed(merchant)` returned false.
    ComplianceCheckFailed,
    /// The settlement is not in a state treasury would execute (unknown ID,
    /// already executed, or on hold).
    TreasuryWouldReject,
}

/// Outcome of [`SettlementWorkflowContract::simulate_with_compliance`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SimulationResult {
    /// Every check the execution path runs would pass.
    WouldSucceed,
    /// Execution would fail, and this is the check that would fail first.
    WouldFail(SimulationFailure),
}

/// Storage keys for the settlement workflow contract.
///
/// `ExecutedSettlements` tracks the ordered list of settlement IDs executed through
/// this workflow contract (as opposed to executed directly against treasury, bypassing
/// the compliance gate). See `get_executed_settlement_ids_page` (#373).
///
/// `ComplianceId` and `TreasuryId` are the pinned configuration set once at
/// initialization (#364) so the contract enforces which instances it trusts rather
/// than trusting whatever a caller supplies per-call.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    ExecutedSettlements,
    ComplianceId,
    TreasuryId,
}

/// Reference on-chain implementation of the `SettlementWorkflow` role described in
/// `ARCHITECTURE.md`: gates `Treasury::execute_settlement` behind
/// `Compliance::is_allowed`. Treasury does not consult compliance itself, so this
/// contract is the enforcement point for the compliance gate in the payment lifecycle.
#[contract]
pub struct SettlementWorkflowContract;

#[contractimpl]
impl SettlementWorkflowContract {
    /// Pins the compliance and treasury contract instances this workflow trusts.
    /// Must be called exactly once before any `execute_with_compliance*` call; a
    /// second call traps with `AlreadyInitialized` (#364). Callers can no longer
    /// redirect the gate at an arbitrary compliance/treasury instance per-call.
    /// Emits: `workflow_initialized`.
    pub fn initialize(env: Env, compliance_id: Address, treasury_id: Address) {
        if env.storage().instance().has(&DataKey::ComplianceId) {
            soroban_sdk::panic_with_error!(env, TreasuryError::AlreadyInitialized);
        }
        env.storage()
            .instance()
            .set(&DataKey::ComplianceId, &compliance_id);
        env.storage()
            .instance()
            .set(&DataKey::TreasuryId, &treasury_id);
        env.events().publish(
            (Symbol::new(&env, "workflow_initialized"),),
            (compliance_id, treasury_id),
        );
    }

    /// Returns the pinned compliance contract instance.
    fn compliance_id(env: &Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::ComplianceId)
            .unwrap()
    }

    /// Returns the pinned treasury contract instance.
    fn treasury_id(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::TreasuryId).unwrap()
    }

    /// Checks `Compliance::is_allowed(merchant)` and, only if it passes, calls
    /// `Treasury::execute_settlement(..., settlement_id, token_contract)` using this
    /// contract's own address as the authorizing signer (it must be registered as a
    /// Treasury signer via `Treasury::set_signer` beforehand).
    /// Returns `Err(SettlementWorkflowError::ComplianceCheckFailed)` without touching Treasury
    /// if the compliance check fails, instead of panicking or reusing a generic
    /// `Unauthorized` (see #74).
    /// Emits: `settlement_workflow_executed` so indexers can distinguish this gated
    /// path from a direct `Treasury::execute_settlement` call (#366).
    pub fn execute_with_compliance(
        env: Env,
        settlement_id: u64,
        token_contract: Address,
        merchant: Address,
    ) -> Result<(), TreasuryError> {
        let compliance = ComplianceClient::new(&env, &Self::compliance_id(&env));
        compliance.require_allowed_for_treasury(&merchant)?;
        let treasury = TreasuryOnlyClient::new(&env, &Self::treasury_id(&env));
        treasury.execute_settlement(
            &env.current_contract_address(),
            &settlement_id,
            &token_contract,
        );
        env.events().publish(
            (
                Symbol::new(&env, "settlement_workflow_executed"),
                settlement_id,
            ),
            (merchant.clone(), token_contract.clone()),
        );
        Ok(())
    }

    /// Read-only preview of [`Self::execute_with_compliance`] (#618).
    ///
    /// Performs no state changes and emits no events, so operators and frontends
    /// can tell whether a settlement will pass compliance before submitting it
    /// and avoid a failed transaction.
    ///
    /// The compliance leg calls the *same*
    /// [`ComplianceClient::require_allowed_for_treasury`] that
    /// `execute_with_compliance` calls, so the two cannot drift. The treasury
    /// leg uses the read-only `try_get_settlement` rather than
    /// `try_execute_settlement`, because the latter actually settles the
    /// payout when its checks pass — that would make a "dry run" mutate state.
    ///
    /// Because quorum and treasury pause state are not readable from here, a
    /// [`SimulationResult::WouldSucceed`] means "the compliance gate passes and
    /// the settlement exists in an executable status"; it does not guarantee
    /// quorum. Execution can still fail with a treasury error such as
    /// `ThresholdNotMet`. The negative results, which is what callers use this
    /// for, are exact.
    pub fn simulate_with_compliance(
        env: Env,
        settlement_id: u64,
        _token_contract: Address,
        merchant: Address,
    ) -> SimulationResult {
        let compliance = ComplianceClient::new(&env, &Self::compliance_id(&env));
        if compliance.require_allowed_for_treasury(&merchant).is_err() {
            return SimulationResult::WouldFail(SimulationFailure::ComplianceCheckFailed);
        }
        let treasury = TreasuryOnlyClient::new(&env, &Self::treasury_id(&env));
        // `#[contractclient]` wraps the generated `try_get_settlement` client call
        // around the host invocation, hence the nested `Result`.
        let lookup = treasury.try_get_settlement(&settlement_id);
        match lookup {
            Ok(Ok(ref s)) if Self::is_executable_status(s) => SimulationResult::WouldSucceed,
            _ => SimulationResult::WouldFail(SimulationFailure::TreasuryWouldReject),
        }
    }

    /// Whether treasury's `execute_settlement` would accept a settlement in this
    /// status. Mirrors the status guards in `Treasury::execute_settlement`, and
    /// is shared by the dry run so the two agree.
    fn is_executable_status(settlement: &Settlement) -> bool {
        settlement.status == SettlementStatus::Pending
    }

    /// Batch variant of `execute_with_compliance` (#367). Runs the shared compliance
    /// gate for `merchant` once, then executes each settlement ID through the pinned
    /// treasury. Settlement IDs that don't exist, are already executed, or otherwise
    /// fail treasury execution are silently skipped (per treasury's batch precedent,
    /// #38) rather than aborting the whole batch; only successfully executed IDs are
    /// returned and emitted. If the shared compliance gate fails, the whole batch is
    /// rejected with `ComplianceCheckFailed`.
    /// Emits: `settlement_workflow_executed` for each settlement actually executed.
    pub fn execute_with_compliance_batch(
        env: Env,
        settlement_ids: Vec<u64>,
        token_contract: Address,
        merchant: Address,
    ) -> Vec<u64> {
        let compliance = ComplianceClient::new(&env, &Self::compliance_id(&env));
        compliance.require_allowed_for_treasury(&merchant).unwrap();
        let treasury = TreasuryOnlyClient::new(&env, &Self::treasury_id(&env));
        let mut executed = Vec::new(&env);
        for id in settlement_ids.iter() {
            let result = treasury.try_execute_settlement(
                &env.current_contract_address(),
                &id,
                &token_contract,
            );
            if result.is_ok() {
                executed.push_back(id);
                env.events().publish(
                    (Symbol::new(&env, "settlement_workflow_executed"), id),
                    (merchant.clone(), token_contract.clone()),
                );
            }
            // Invalid / already-executed / threshold-failed IDs are silently skipped.
        }
        executed
    }
}
