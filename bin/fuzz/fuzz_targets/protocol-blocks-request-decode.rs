#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = smoldot::network::protocol::decode_block_request(data);
});
