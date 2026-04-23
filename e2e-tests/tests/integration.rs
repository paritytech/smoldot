// Single integration-test binary. Test suites live under `zombie_ci::` so
// the CI matrix filters with `cargo test -- zombie_ci::<suite>::<test>`.

mod zombie_ci;
