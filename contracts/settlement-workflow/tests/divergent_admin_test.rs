//! Guards against the two admin surfaces (Compliance and Treasury) drifting
//! apart in a way that lets a settlement through a path nobody intended.
//!
//! The compliance admin controls *who may receive funds* (allowlist/blocklist);
//! the treasury admin controls *who may move funds* (signers, threshold). The
//! security property under test is that the workflow's compliance gate and the
//! treasury's own admin state agree: an address the compliance admin has
//! blocked must not be able to receive a settlement payout, and a settlement
//! that has not reached treasury quorum must not execute even when the
//! compliance gate passes.
//!
//! This replaces an earlier draft of this file that never compiled (it
//! referenced undefined methods and declared its helper structs twice), so it
//! previously contributed a hard build failure rather than any coverage.

use compliance::{ComplianceContract, ComplianceContractClient};
use soroban_sdk::{testutils::Address as _, Address, Env, Vec};
use treasury::{TreasuryContract, TreasuryContractClient};

struct Setup {
    env: Env,
    admin: Address,
    merchant: Address,
    cosigner: Address,
    compliance: ComplianceContractClient<'static>,
    treasury: TreasuryContractClient<'static>,
    treasury_id: Address,
    token_id: Address,
}

/// Threshold 2 with three signers of weight 1 each (admin, cosigner, workflow).
/// No single weight reaches the threshold, so quorum always requires more than
/// one approval — see the #622 signer weight cap.
fn setup(register_workflow_signer: bool) -> Setup {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let merchant = Address::generate(&env);
    let cosigner = Address::generate(&env);

    let compliance_id = env.register_contract(None, ComplianceContract);
    let compliance = ComplianceContractClient::new(&env, &compliance_id);
    compliance.initialize(&admin);

    let treasury_id = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &treasury_id);
    let mut signers = Vec::new(&env);
    signers.push_back((admin.clone(), 1u32));
    signers.push_back((cosigner.clone(), 1u32));
    treasury.initialize(&admin, &2, &signers);

    if register_workflow_signer {
        treasury.set_signer(&admin, &admin, &1);
    }

    let token_id = env.register_stellar_asset_contract(admin.clone());

    Setup {
        env,
        admin,
        merchant,
        cosigner,
        compliance,
        treasury,
        treasury_id,
        token_id,
    }
}

#[test]
fn compliance_block_overrides_a_previously_set_allow() {
    let s = setup(true);

    s.compliance.allow_address(&s.admin, &s.merchant);
    assert!(s.compliance.is_allowed(&s.merchant));

    // The compliance admin's block must win over the earlier allow, otherwise a
    // stale allow could be used to receive funds after a block.
    s.compliance.block_address(&s.admin, &s.merchant, &None);
    assert!(!s.compliance.is_allowed(&s.merchant));
    assert!(s.compliance.is_blocked(&s.merchant));
}

#[test]
fn clearing_a_block_restores_the_previous_allow() {
    let s = setup(true);

    s.compliance.allow_address(&s.admin, &s.merchant);
    s.compliance.block_address(&s.admin, &s.merchant, &None);
    assert!(!s.compliance.is_allowed(&s.merchant));

    // `clear_address` is the documented recovery path off the blocklist.
    s.compliance.clear_address(&s.admin, &s.merchant);
    assert!(!s.compliance.is_blocked(&s.merchant));
    assert!(s.compliance.is_allowed(&s.merchant));
}

#[test]
fn revoking_an_allow_disables_the_address_without_blocking_it() {
    let s = setup(true);

    s.compliance.allow_address(&s.admin, &s.merchant);
    s.compliance.revoke_allow(&s.admin, &s.merchant);

    // Revoke is a soft de-listing: allowed goes false, blocked stays false.
    assert!(!s.compliance.is_allowed(&s.merchant));
    assert!(!s.compliance.is_blocked(&s.merchant));
}

#[test]
fn treasury_rejects_execution_below_quorum_despite_allowlisted_merchant() {
    let s = setup(true);

    // Compliance is happy, but treasury quorum has not been reached.
    s.compliance.allow_address(&s.admin, &s.merchant);
    let settlement = s
        .treasury
        .propose_settlement(&s.admin, &s.merchant, &10_000_000);

    let err = s
        .treasury
        .try_execute_settlement(&s.admin, &settlement, &s.token_id)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, treasury::TreasuryError::ThresholdNotMet);
}

#[test]
fn treasury_executes_once_quorum_is_reached() {
    let s = setup(true);

    s.compliance.allow_address(&s.admin, &s.merchant);
    let settlement = s
        .treasury
        .propose_settlement(&s.admin, &s.merchant, &10_000_000);
    s.treasury.approve_settlement(&s.admin, &settlement);
    s.treasury.approve_settlement(&s.cosigner, &settlement);
    soroban_sdk::token::StellarAssetClient::new(&s.env, &s.token_id)
        .mint(&s.treasury_id, &10_000_000);

    s.treasury
        .execute_settlement(&s.admin, &settlement, &s.token_id);

    assert_eq!(
        soroban_sdk::token::Client::new(&s.env, &s.token_id).balance(&s.merchant),
        10_000_000
    );
}

#[test]
fn admin_transfer_moves_compliance_control_and_revokes_the_old_admin() {
    let s = setup(true);
    let new_admin = Address::generate(&s.env);

    s.compliance.transfer_admin(&s.admin, &new_admin);
    s.compliance.accept_admin(&new_admin);

    // The old admin can no longer mutate allowlist state.
    let err = s
        .compliance
        .try_allow_address(&s.admin, &s.merchant)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, compliance::ContractError::Unauthorized);

    // The new admin can.
    s.compliance.allow_address(&new_admin, &s.merchant);
    assert!(s.compliance.is_allowed(&s.merchant));
}
