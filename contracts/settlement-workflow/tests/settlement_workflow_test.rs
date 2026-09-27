#[path = "reentrancy_suite/malicious_compliance.rs"]
mod malicious_compliance;

use compliance::{ComplianceContract, ComplianceContractClient};
use multisig::TreasuryError;
use settlement_workflow::{
    SettlementWorkflowContract, SettlementWorkflowContractClient, SettlementWorkflowError,
};
use soroban_sdk::{
    testutils::{Address as _, Events},
    token, Address, Env, Symbol, TryFromVal,
};
use treasury::{TreasuryContract, TreasuryContractClient};

/// Generous CPU-instruction ceiling for the two-hop cross-contract call chain
/// (Compliance::is_allowed → Treasury::execute_settlement). Native/test-host
/// numbers are far lower; this bound is wide enough to avoid flakiness while
/// still catching a large, unintended regression in the composed call chain (#368).
const MAX_EXECUTE_INSTRUCTIONS: u64 = 5_000_000;

fn setup() -> (
    Env,
    Address,
    Address,
    ComplianceContractClient<'static>,
    Address,
    TreasuryContractClient<'static>,
    Address,
    SettlementWorkflowContractClient<'static>,
    Address,
    Address,
) {
    setup_with_signer(true)
}

/// `register_workflow_signer` controls whether the workflow contract is registered
/// as a Treasury signer. Pass `false` to exercise the #370 precondition path where
/// the workflow's own address has not been registered via `Treasury::set_signer`.
fn setup_with_signer(
    register_workflow_signer: bool,
) -> (
    Env,
    Address,
    Address,
    ComplianceContractClient<'static>,
    Address,
    TreasuryContractClient<'static>,
    Address,
    SettlementWorkflowContractClient<'static>,
    Address,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);

    let compliance_id = env.register_contract(None, ComplianceContract);
    let compliance = ComplianceContractClient::new(&env, &compliance_id);
    compliance.initialize(&admin);

    let treasury_id = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &treasury_id);
    // #622 weight cap: no single signer's weight may be >= the threshold.
    // Threshold 2 with three signers of weight 1 each (admin, cosigner, and the
    // workflow added below) keeps every weight strictly below the threshold, so
    // no signer can approve alone. Quorum needs the admin + cosigner pair.
    let cosigner = Address::generate(&env);
    let mut initial_signers = soroban_sdk::Vec::new(&env);
    initial_signers.push_back((admin.clone(), 1u32));
    initial_signers.push_back((cosigner.clone(), 1u32));
    treasury.initialize(&admin, &2, &initial_signers);

    let workflow_id = env.register_contract(None, SettlementWorkflowContract);
    let workflow = SettlementWorkflowContractClient::new(&env, &workflow_id);
    // Pin the trusted compliance/treasury instances once at init (#364).
    workflow.initialize(&compliance_id, &treasury_id);
    // The workflow contract executes settlements as itself, so it must be an
    // authorized Treasury signer. Its weight (1) is below the threshold (2),
    // so the workflow can never satisfy quorum on its own.
    if register_workflow_signer {
        treasury.set_signer(&admin, &workflow_id, &1);
    }

    let token_id = env.register_stellar_asset_contract(admin.clone());

    (
        env,
        admin,
        merchant,
        compliance,
        compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        cosigner,
    )
}

#[test]
fn execution_blocked_when_compliance_returns_false() {
    let (
        env,
        admin,
        merchant,
        _compliance,
        _compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        _cosigner,
    ) = setup();

    let settlement_id = treasury.propose_settlement(&admin, &merchant, &10_000_000);
    token::StellarAssetClient::new(&env, &token_id).mint(&treasury_id, &10_000_000);

    let err = workflow
        .try_execute_with_compliance(&settlement_id, &token_id, &merchant)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, SettlementWorkflowError::ComplianceCheckFailed);
    assert_eq!(token::Client::new(&env, &token_id).balance(&merchant), 0);
}

#[test]
fn successful_path_executes_treasury_settlement() {
    let (
        env,
        admin,
        merchant,
        compliance,
        _compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        cosigner,
    ) = setup();

    compliance.allow_address(&admin, &merchant);
    let settlement_id = treasury.propose_settlement(&admin, &merchant, &10_000_000);
    // #622 weight cap: no single signer can reach quorum alone, so the two
    // non-workflow signers approve first and the workflow executes the result.
    treasury.approve_settlement(&admin, &settlement_id);
    treasury.approve_settlement(&cosigner, &settlement_id);
    token::StellarAssetClient::new(&env, &token_id).mint(&treasury_id, &10_000_000);

    workflow.execute_with_compliance(&settlement_id, &token_id, &merchant);

    assert_eq!(
        token::Client::new(&env, &token_id).balance(&merchant),
        10_000_000
    );
}

#[test]
fn unpause_restores_execution() {
    let (
        env,
        admin,
        merchant,
        compliance,
        _compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        cosigner,
    ) = setup();

    compliance.allow_address(&admin, &merchant);
    let settlement_id = treasury.propose_settlement(&admin, &merchant, &10_000_000);
    // #622 weight cap: no single signer can reach quorum alone, so the two
    // non-workflow signers approve first and the workflow executes the result.
    treasury.approve_settlement(&admin, &settlement_id);
    treasury.approve_settlement(&cosigner, &settlement_id);
    token::StellarAssetClient::new(&env, &token_id).mint(&treasury_id, &10_000_000);

    workflow.execute_with_compliance(&settlement_id, &token_id, &merchant);

    assert_eq!(
        token::Client::new(&env, &token_id).balance(&merchant),
        10_000_000
    );
}

#[test]
fn emits_settlement_workflow_executed_event() {
    let (
        env,
        admin,
        merchant,
        compliance,
        _compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        cosigner,
    ) = setup();

    compliance.allow_address(&admin, &merchant);
    let settlement_id = treasury.propose_settlement(&admin, &merchant, &10_000_000);
    // #622 weight cap: no single signer can reach quorum alone, so the two
    // non-workflow signers approve first and the workflow executes the result.
    treasury.approve_settlement(&admin, &settlement_id);
    treasury.approve_settlement(&cosigner, &settlement_id);
    token::StellarAssetClient::new(&env, &token_id).mint(&treasury_id, &10_000_000);

    workflow.execute_with_compliance(&settlement_id, &token_id, &merchant);

    let (_, topics, _) = env.events().all().last().unwrap();
    let emitted_symbol =
        Symbol::try_from_val(&env, &topics.get_unchecked(0)).expect("topic 0 is a Symbol");
    assert_eq!(
        emitted_symbol,
        Symbol::new(&env, "settlement_workflow_executed"),
        "expected a settlement_workflow_executed event to be emitted"
    );
}

#[test]
fn initialize_is_idempotent_and_pins_trusted_instances() {
    let env = Env::default();
    env.mock_all_auths();
    let compliance_id = Address::generate(&env);
    let treasury_id = Address::generate(&env);
    let workflow_id = env.register_contract(None, SettlementWorkflowContract);
    let workflow = SettlementWorkflowContractClient::new(&env, &workflow_id);

    workflow.initialize(&compliance_id, &treasury_id);
    // Second initialize must trap with AlreadyInitialized.
    let err = workflow
        .try_initialize(&compliance_id, &treasury_id)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, TreasuryError::AlreadyInitialized.into());
}

#[test]
fn batch_executes_multiple_settlements_and_skips_invalid_ids() {
    let (
        env,
        admin,
        merchant,
        compliance,
        _compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        cosigner,
    ) = setup();

    compliance.allow_address(&admin, &merchant);

    let good_1 = treasury.propose_settlement(&admin, &merchant, &5_000_000);
    let good_2 = treasury.propose_settlement(&admin, &merchant, &5_000_000);
    // #622 weight cap: no single signer can reach quorum alone, so the two
    // non-workflow signers approve each settlement before the workflow executes.
    treasury.approve_settlement(&admin, &good_1);
    treasury.approve_settlement(&cosigner, &good_1);
    treasury.approve_settlement(&admin, &good_2);
    treasury.approve_settlement(&cosigner, &good_2);
    // A settlement that does not exist.
    let bogus: u64 = 999;
    token::StellarAssetClient::new(&env, &token_id).mint(&treasury_id, &10_000_000);

    let mut ids = soroban_sdk::Vec::new(&env);
    ids.push_back(good_1);
    ids.push_back(bogus);
    ids.push_back(good_2);

    let executed = workflow.execute_with_compliance_batch(&ids, &token_id, &merchant);
    assert_eq!(
        executed,
        soroban_sdk::Vec::from_array(&env, [good_1, good_2])
    );
    assert_eq!(
        token::Client::new(&env, &token_id).balance(&merchant),
        10_000_000
    );
}

#[test]
fn batch_rejected_when_compliance_fails() {
    let (
        env,
        admin,
        merchant,
        _compliance,
        _compliance_id,
        treasury,
        _treasury_id,
        workflow,
        token_id,
        _cosigner,
    ) = setup();

    let good = treasury.propose_settlement(&admin, &merchant, &5_000_000);
    let mut ids = soroban_sdk::Vec::new(&env);
    ids.push_back(good);

    // merchant is not on the compliance allowlist — the batch must not succeed.
    // `execute_with_compliance_batch` calls `.unwrap()` on the compliance gate
    // rather than returning a `Result`, so the rejection surfaces as a host-level
    // failure instead of a typed contract error.
    assert!(
        workflow
            .try_execute_with_compliance_batch(&ids, &token_id, &merchant)
            .is_err(),
        "batch must not succeed when the compliance gate fails"
    );
}

#[test]
fn execute_with_compliance_stays_under_instruction_budget() {
    let (
        env,
        admin,
        merchant,
        compliance,
        _compliance_id,
        treasury,
        treasury_id,
        workflow,
        token_id,
        cosigner,
    ) = setup();

    // Lift budget limits so the call chain is measured, not artificially capped.
    env.cost_estimate().budget().reset_unlimited();
    compliance.allow_address(&admin, &merchant);
    let settlement_id = treasury.propose_settlement(&admin, &merchant, &10_000_000);
    // #622 weight cap: no single signer can reach quorum alone, so the two
    // non-workflow signers approve before the workflow executes.
    treasury.approve_settlement(&admin, &settlement_id);
    treasury.approve_settlement(&cosigner, &settlement_id);
    token::StellarAssetClient::new(&env, &token_id).mint(&treasury_id, &10_000_000);
    env.cost_estimate().budget().reset_tracker();

    workflow.execute_with_compliance(&settlement_id, &token_id, &merchant);

    let instructions = env.cost_estimate().budget().cpu_instruction_cost();
    assert!(
        instructions <= MAX_EXECUTE_INSTRUCTIONS,
        "execute_with_compliance used {instructions} instructions, \
         expected <= {MAX_EXECUTE_INSTRUCTIONS}"
    );
}
