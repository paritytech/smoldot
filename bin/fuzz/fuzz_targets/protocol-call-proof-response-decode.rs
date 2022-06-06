#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = smoldot::network::protocol::decode_call_proof_response(data);
});
