#pragma once

/// @file auth_lock_bounds.hpp
/// The one place the cross-file lock-wait ordering between `AuthDB` and the
/// ADR-0012 §3 query owners is stated as a constant (#6079 PR 2c governance).
///
/// `kAuthRecheckLockTimeout` is the write budget of `AuthDB` (auth_db.cpp
/// `kWriteTimeout`), and so the txn-scoped `lock_timeout` that
/// `AuthDB::recheck_role_locked` sets on the `auth.users` row lock a same-account
/// sign-in's post-mint recheck waits on. A recheck that times out fails closed
/// and sweeps the account's sessions, so a sign-in queued behind a stalled
/// credential change or MFA disable would be signed out for a database stall.
///
/// Both owners therefore keep their own per-wait `lock_timeout`
/// (`CredentialChangeOwner::kWriteTimeout`, `MfaDisableOwner::kWriteTimeout`)
/// STRICTLY BELOW this value, enforced by a `static_assert` beside each. The
/// guarantee is per WAIT, not per transaction: an owner's transaction can make
/// several sequential bounded waits (row lock, session rows, the audit INSERT,
/// the `session_meta` row), so this bound does not promise that a queued
/// recheck always outlasts a whole owner transaction. Raising an owner's timeout
/// to or past this value, or lowering this one to or below an owner's, is a
/// build failure by design: re-derive the ordering before changing either.

#include <chrono>

namespace yuzu::server {

inline constexpr std::chrono::milliseconds kAuthRecheckLockTimeout{2000};

} // namespace yuzu::server
