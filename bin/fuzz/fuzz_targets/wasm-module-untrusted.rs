#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = smoldot::executor::host::HostVmPrototype::new(smoldot::executor::host::Config {
        module: data,
        heap_pages: smoldot::executor::DEFAULT_HEAP_PAGES,
        exec_hint: smoldot::executor::vm::ExecHint::Untrusted,
        allow_unresolved_imports: true,
    });
});
