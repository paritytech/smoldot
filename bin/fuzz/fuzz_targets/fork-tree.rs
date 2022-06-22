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

#![no_main]

use smoldot::chain::fork_tree;
use std::{
    cell::{Cell, RefCell},
    ops::ControlFlow,
    rc::{Rc, Weak},
};

// This fuzzing test generates a list of operations that are then applied on a fork tree.

// Because the list of operations is generated ahead of time, we can't use `NodeIndex` as these
// are unpredictable. Instead, we use locally-assigned `u32`s and applying the operations will
// keep a mapping between `u32`s and `NodeIndex`es.
#[derive(Debug)]
enum Operation {
    Clear,
    Insert { parent: Option<u32>, new_id: u32 },
    PruneAncestors(u32),
    PruneUncles(u32),
}

libfuzzer_sys::fuzz_target!(|operations: OperationsList| {
    let mut tree = fork_tree::ForkTree::new();

    let mut ext_to_in_mapping =
        hashbrown::HashMap::<u32, fork_tree::NodeIndex, _>::with_capacity_and_hasher(
            0,
            fnv::FnvBuildHasher::default(),
        );

    for operation in operations.0 {
        match operation {
            Operation::Clear => {
                tree.clear();
            }
            Operation::Insert { parent, new_id } => {
                let in_id = tree.insert(parent.map(|id| ext_to_in_mapping[&id]), ());
                ext_to_in_mapping.insert(new_id, in_id);
            }
            Operation::PruneAncestors(id) => {
                let _ = tree.prune_ancestors(ext_to_in_mapping[&id]);
            }
            Operation::PruneUncles(id) => {
                let _ = tree.prune_uncles(ext_to_in_mapping[&id]);
            }
        }
    }
});

#[derive(Debug)]
struct OperationsList(Vec<Operation>);

impl<'a> arbitrary::Arbitrary<'a> for OperationsList {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // In order to generate a valid list of operations, we must track the tree separately.
        // To do so, we use `Rc`s and `Weak`s, which is the easiest (but non optimal) way to
        // maintain a tree.

        struct Node {
            id: Cell<Option<u32>>, // `None` iff root.
            parent: Weak<Node>,
            children: RefCell<Vec<Rc<Node>>>,
        }

        impl Node {
            fn gather_children(&self, out: &mut Vec<Rc<Node>>) {
                let children = self.children.borrow();
                out.extend(children.iter().cloned());
                for child in children.iter() {
                    child.gather_children(out);
                }
            }

            fn prune_uncles(self: &Rc<Self>) {
                if let Some(parent) = self.parent.upgrade() {
                    let mut parent_children = parent.children.borrow_mut();
                    parent_children.retain(|c| Rc::ptr_eq(c, self));
                    parent.prune_uncles();
                }
            }
        }

        let mut operations = Vec::new();

        let mut tree_root = Rc::new(Node {
            id: Cell::new(None),
            parent: Weak::new(),
            children: RefCell::new(Vec::new()),
        });

        let mut next_node_id = 0;

        u.arbitrary_loop(None, None, |u| {
            let mut all_nodes = Vec::new();
            all_nodes.push(tree_root.clone());
            tree_root.gather_children(&mut all_nodes);

            // Very rarely, we simply clear the tree.
            if u.ratio(1, 30)? {
                operations.push(Operation::Clear);
                tree_root = Rc::new(Node {
                    id: Cell::new(None),
                    parent: Weak::new(),
                    children: RefCell::new(Vec::new()),
                });

                return Ok(ControlFlow::Continue(()));
            }

            // 9/10th of the time, insert a new node in the tree.
            if u.ratio(9, 10)? {
                let index = u.choose_index(all_nodes.len())?;

                operations.push(Operation::Insert {
                    parent: all_nodes[index].id.get(),
                    new_id: next_node_id,
                });
                let parent = Rc::downgrade(&all_nodes[index]);
                all_nodes[index].children.borrow_mut().push(Rc::new(Node {
                    id: Cell::new(Some(next_node_id)),
                    parent,
                    children: RefCell::new(Vec::new()),
                }));
                next_node_id += 1;

                return Ok(ControlFlow::Continue(()));
            }

            // The remaining half of the time, we prune ancestors. Otherwise, we prune uncles.
            if u.ratio(1, 2)? {
                let index = u.choose_index(all_nodes.len() - 1)? + 1; // Avoid the tree root
                operations.push(Operation::PruneAncestors(
                    all_nodes[index].id.get().unwrap(),
                ));
                tree_root = all_nodes[index].clone();
                all_nodes[index].id.set(None);
            } else {
                let index = u.choose_index(all_nodes.len() - 1)? + 1; // Avoid the tree root
                operations.push(Operation::PruneUncles(all_nodes[index].id.get().unwrap()));
                all_nodes[index].prune_uncles();
            }

            Ok(ControlFlow::Continue(()))
        })?;

        Ok(OperationsList(operations))
    }
}
