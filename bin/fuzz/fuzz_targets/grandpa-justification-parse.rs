#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = smoldot::finality::justification::decode::decode_grandpa(data);
});
