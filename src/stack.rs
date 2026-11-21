/// Number of stack bytes wiped after each operation that handles secret material.
///
/// Sized from the measured peak stack usage of ML-KEM-1024 decryption (~56–58 KiB in default
/// release and portable builds, ~69.5 KiB under `opt-level = "s"`), leaving headroom for
/// `x86_64` and compiler frame-layout differences without over-allocating on `no_std` stacks.
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
