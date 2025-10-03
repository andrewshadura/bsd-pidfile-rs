BSD pidfile for Rust
====================

This crate provides a reimplementation of a family of [`pidfile_*` functions][pidfile] provided in the BSD systems by [libutil][], and elsewhere by [libbsd][].

Known alternatives in pure Rust:

 * [pidfile](https://crates.io/crates/pidfile) by Carl Lerche, very advanced, but last updated in 2014 and no longer compiles with modern Rust.
 * [pidlock](https://crates.io/crates/pidlock) by Paul Hummer provides a lock-like API, but doesn’t actually use filesystem locks.
 * [qpidfile](https://crates.io/crates/qpidfile) by Jan Danielsson, well-maintained, but very basic.

The BSD pidfile functions employ very clever locking mechanism, detect concurrently running daemons and allow deferring writes to the PID file, so potential errors can be handled before a fork.

This crate reimplements the functionality of the pidfile functions in Rust using the [`flopen`][rust-flopen] crate.

[libutil]: https://man.netbsd.org/libutil.3
[libbsd]: https://libbsd.freedesktop.org/
[pidfile]: https://linux.die.net/man/3/pidfile
[rust-flopen]: https://github.com/andrewshadura/rust-flopen

License
-------

[MIT license](LICENSE-MIT), also known as the Expat license.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be licensed as above, without any additional
terms or conditions.
