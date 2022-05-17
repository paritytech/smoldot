// Smoldot
// Copyright (C) 2019-2022  Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![cfg(test)]

#[test]
fn is_send() {
    // Makes sure that the virtual machine types implement `Send`.
    fn test<T: Send>() {}
    test::<super::VirtualMachine>();
    test::<super::VirtualMachinePrototype>();
}

// TODO: test below should run for both wasmi and wasmtime

#[test]
fn basic_seems_to_work() {
    let module = super::Module::new(
        &include_bytes!("./test-polkadot-runtime-v9160.wasm")[..],
        super::ExecHint::CompileAheadOfTime,
    )
    .unwrap();

    let prototype = super::VirtualMachinePrototype::new(&module, |_, _, _| Ok(0)).unwrap();

    // Note that this test doesn't test much, as anything elaborate would require implementing
    // the Substrate/Polkadot allocator.

    let mut vm = prototype
        .start(
            super::HeapPages::new(1024),
            "Core_version",
            &[super::WasmValue::I32(0), super::WasmValue::I32(0)],
        )
        .unwrap();

    loop {
        match vm.run(None) {
            Ok(super::ExecOutcome::Finished {
                return_value: Ok(_),
            }) => break,
            Ok(super::ExecOutcome::Finished {
                return_value: Err(_),
            }) => panic!(),
            Ok(super::ExecOutcome::Interrupted { id: 0, .. }) => break,
            Ok(super::ExecOutcome::Interrupted { .. }) => panic!(),
            Err(_) => panic!(),
        }
    }
}

#[test]
fn out_of_memory_access() {
    let input = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x00, 0x0b, 0x06,
        0x01, 0x00, 0x41, 0x03, 0x0b, 0x00,
    ];

    let module1 = super::Module::new(input, super::ExecHint::CompileAheadOfTime).unwrap();
    assert!(super::VirtualMachinePrototype::new(&module1, |_, _, _| Ok(0)).is_err());

    let module2 = super::Module::new(input, super::ExecHint::Untrusted).unwrap();
    assert!(super::VirtualMachinePrototype::new(&module2, |_, _, _| Ok(0)).is_err());
}

#[test]
fn has_start_function() {
    let input = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02,
        0x09, 0x01, 0x01, 0x71, 0x03, 0x69, 0x6d, 0x70, 0x00, 0x00, 0x08, 0x01, 0x00,
    ];

    let module1 = super::Module::new(input, super::ExecHint::CompileAheadOfTime).unwrap();
    assert!(super::VirtualMachinePrototype::new(&module1, |_, _, _| Ok(0)).is_err());

    let module2 = super::Module::new(input, super::ExecHint::Untrusted).unwrap();
    assert!(super::VirtualMachinePrototype::new(&module2, |_, _, _| Ok(0)).is_err());
}
