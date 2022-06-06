#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = smoldot::chain_spec::ChainSpec::from_json_bytes(data);
});
