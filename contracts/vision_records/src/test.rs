#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use super::*;
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{symbol_short, Env, IntoVal, TryIntoVal};

#[test]
fn test_initialize() {
    let env = Env::default();
    let contract_id = env.register(VisionRecordsContract, ());
    let client = VisionRecordsContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.initialize(&admin);
    let events = env.events().all();

    assert!(client.is_initialized());
    assert_eq!(client.get_admin(), admin);
    let our_events: soroban_sdk::Vec<(
        soroban_sdk::Address,
        soroban_sdk::Vec<soroban_sdk::Val>,
        soroban_sdk::Val,
    )> = events;

    assert!(!our_events.is_empty());
    let event = our_events.get(our_events.len() - 1).unwrap();
    assert_eq!(event.1, (symbol_short!("INIT"),).into_val(&env));
    let payload: events::InitializedEvent = event.2.try_into_val(&env).unwrap();
    assert_eq!(payload.admin, admin);
}
