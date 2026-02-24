use soroban_sdk::{symbol_short, Address, Env, Symbol};

const WL_ENABLED: Symbol = symbol_short!("WL_EN");
const WL_ADDR: Symbol = symbol_short!("WL_ADR");

/// Enables or disables whitelist enforcement globally for the contract.
pub fn set_whitelist_enabled(env: &Env, enabled: bool) {
    env.storage().instance().set(&WL_ENABLED, &enabled);
}

/// Returns whether whitelist enforcement is globally enabled.
pub fn is_whitelist_enabled(env: &Env) -> bool {
    env.storage().instance().get(&WL_ENABLED).unwrap_or(false)
}

/// Adds an address to the whitelist.
pub fn add_to_whitelist(env: &Env, address: &Address) {
    env.storage()
        .persistent()
        .set(&(WL_ADDR, address.clone()), &true);
}

/// Removes an address from the whitelist.
pub fn remove_from_whitelist(env: &Env, address: &Address) {
    env.storage().persistent().remove(&(WL_ADDR, address.clone()));
}

/// Returns whether an address is in the whitelist.
pub fn is_whitelisted(env: &Env, address: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&(WL_ADDR, address.clone()))
        .unwrap_or(false)
}

/// Returns whether the address is allowed to call guarded functions.
///
/// When whitelist enforcement is disabled, all addresses are allowed.
pub fn require_whitelisted(env: &Env, address: &Address) -> bool {
    !is_whitelist_enabled(env) || is_whitelisted(env, address)
}
