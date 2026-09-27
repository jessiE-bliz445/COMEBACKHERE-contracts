//! Tests for the signer weight cap validation (#622).
//!
//! A single signer's weight must be strictly below the threshold to prevent
//! that signer from approving alone. These tests verify that:
//! 1. `set_signer` rejects weights that meet or exceed the threshold.
//! 2. `initialize` rejects initial signers with weights that meet or exceed the threshold.
//! 3. Weights below the threshold are accepted.

use soroban_sdk::{testutils::Address as _, Address, Env, Vec};
use treasury::{TreasuryContract, TreasuryContractClient, TreasuryError};

fn setup_with_threshold(threshold: u32) -> (Env, Address, TreasuryContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&admin, &threshold, &Vec::new(&env));
    (env, admin, client)
}

#[test]
fn set_signer_rejects_weight_equal_to_threshold() {
    let (env, admin, client) = setup_with_threshold(2);

    let signer = Address::generate(&env);
    let err = client
        .try_set_signer(&admin, &signer, &2)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, TreasuryError::SignerWeightExceedsThreshold);
}

#[test]
fn set_signer_rejects_weight_above_threshold() {
    let (env, admin, client) = setup_with_threshold(2);

    let signer = Address::generate(&env);
    let err = client
        .try_set_signer(&admin, &signer, &5)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, TreasuryError::SignerWeightExceedsThreshold);
}

#[test]
fn set_signer_accepts_weight_below_threshold() {
    let (env, admin, client) = setup_with_threshold(3);

    let signer = Address::generate(&env);
    // Weight 2 is below threshold 3 — should succeed.
    client.set_signer(&admin, &signer, &2);
    assert_eq!(client.get_signer_weight(&signer), 2);
}

#[test]
fn set_signer_accepts_weight_one_below_threshold() {
    let (env, admin, client) = setup_with_threshold(2);

    let signer = Address::generate(&env);
    // Weight 1 is below threshold 2 — should succeed.
    client.set_signer(&admin, &signer, &1);
    assert_eq!(client.get_signer_weight(&signer), 1);
}

#[test]
fn initialize_rejects_signer_weight_equal_to_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);

    let signer = Address::generate(&env);
    let mut signers = Vec::new(&env);
    signers.push_back((signer, 2));

    let err = client
        .try_initialize(&admin, &2, &signers)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, TreasuryError::SignerWeightExceedsThreshold);
}

#[test]
fn initialize_rejects_signer_weight_above_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);

    let signer = Address::generate(&env);
    let mut signers = Vec::new(&env);
    signers.push_back((signer, 10));

    let err = client
        .try_initialize(&admin, &3, &signers)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, TreasuryError::SignerWeightExceedsThreshold);
}

#[test]
fn initialize_accepts_signer_weight_below_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);

    let signer = Address::generate(&env);
    let mut signers = Vec::new(&env);
    signers.push_back((signer.clone(), 2));

    // Weight 2 is below threshold 3 — should succeed.
    client.initialize(&admin, &3, &signers);
    assert_eq!(client.get_signer_weight(&signer), 2);
}

#[test]
fn set_signer_rejects_oversized_weight_even_when_updating() {
    let (env, admin, client) = setup_with_threshold(3);

    let signer = Address::generate(&env);
    // First, set a valid weight.
    client.set_signer(&admin, &signer, &2);
    assert_eq!(client.get_signer_weight(&signer), 2);

    // Now try to update to a weight that meets the threshold.
    let err = client
        .try_set_signer(&admin, &signer, &3)
        .unwrap_err()
        .unwrap();
    assert_eq!(err, TreasuryError::SignerWeightExceedsThreshold);

    // Verify the weight was not changed.
    assert_eq!(client.get_signer_weight(&signer), 2);
}

#[test]
fn set_signer_zero_weight_always_allowed() {
    let (env, admin, client) = setup_with_threshold(1);

    let signer = Address::generate(&env);
    // Weight 0 deactivates the signer and should always be allowed,
    // even though threshold is 1.
    client.set_signer(&admin, &signer, &0);
    assert_eq!(client.get_signer_weight(&signer), 0);
}
