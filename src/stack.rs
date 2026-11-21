/// Number of stack bytes wiped after each operation that handles secret material.
///
/// ML-KEM-1024 decryption reaches deepest. With the wipe call removed, `tests/stack-probe`'s
/// `--measure` found it at most 48.4 KiB down in release builds (either AES backend, and LTO),
/// 49.6 KiB on libcrux's portable path and 59.9 KiB with `opt-level = "s"`, on aarch64 (Apple M4,
/// 2026-11-21). Removing the call changes the build slightly, so these are close, not exact. The
/// probe's CI job fails if a call reaches past the wipe, on x86_64 too. A larger wipe costs time
/// on every call, and stack on `no_std` targets.
const STACK_WIPE_BYTES: usize = 80 * 1024;

#[inline(never)]
fn run_isolated<T>(f: impl FnOnce() -> T) -> T {
    f()
}

/// Runs `f` in a separate stack frame and wipes the stack below this frame before returning,
/// whether `f` succeeds or fails.
///
/// The caller must ensure `T` contains no inline secret bytes (heap-backed types such as
/// [`SecretKey`](crate::SecretKey), `Vec<u8>`, and [`Error`](crate::Error) are safe).
pub(crate) fn with_stack_wipe<T>(f: impl FnOnce() -> T) -> T {
    let out = run_isolated(f);
    zeroize::zeroize_stack::<STACK_WIPE_BYTES>();
    out
}
