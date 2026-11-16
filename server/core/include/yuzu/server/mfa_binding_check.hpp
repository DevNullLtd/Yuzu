#pragma once

// mfa_binding_check.hpp - how a store constructor treats the MFA binding trigger (#6079).
//
// `AuthDB` (auth.users_mfa_factor_gen) and `SessionStore` (session_store.sessions_mfa_rebind_guard)
// both refuse to OPEN when their trigger is not provably in force, so a serving process never
// makes an MFA decision it cannot bind. `kEnforce` is that behaviour and the default of every
// constructor. `kBypassForRecovery` exists for exactly the two host-CLI recovery one-shots
// (`--mfa-reset`, `--break-glass-arm`): an operator locked out because the trigger check fails
// must still be able to clear a factor or arm the break-glass account. A bypassed instance opens,
// logs a loud WARN naming the trigger state it found, and then reports its binding as NOT
// enforced for the whole life of the process (`mfa_binding_enforced()` / `rebind_guard_ok()` read
// false), so every binding decision made through it fails closed. The serving binary never passes
// `kBypassForRecovery`: ServerImpl builds its stores with the default.

#include <cstdint>

namespace yuzu::server {

enum class MfaBindingCheck : std::uint8_t {
    kEnforce = 0,       ///< a trigger not provably in force leaves the store closed (the default)
    kBypassForRecovery, ///< recovery one-shots only: open anyway, warn, binding reads not-enforced
};

} // namespace yuzu::server
