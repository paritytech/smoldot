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

//! As explained in the documentation of smoldot, the database uses synchronous I/O operations.
//! For this reason, it is undesirable to access it from an asynchronous context.

use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    prelude::*,
};
use smoldot::database::full_sqlite::SqliteFullDatabase;
use std::thread;

/// Handle to the thread were the database accesses are performed.
///
/// Destroying this object stops the thread.
///
/// Use the `From` trait implementation to build a [`DatabaseThread`].
pub struct DatabaseThread {
    sender: Mutex<mpsc::Sender<Box<dyn FnOnce(&SqliteFullDatabase) + Send>>>,
}

impl DatabaseThread {
    /// Sends a closure to the database thread, executes it, then returns the value that the
    /// closure returned.
    pub async fn with_database<T: Send + 'static>(
        &self,
        closure: impl FnOnce(&SqliteFullDatabase) -> T + Send + 'static,
    ) -> T {
        let (tx, rx) = oneshot::channel();
        self.sender
            .lock()
            .await
            .send(Box::new(move |db| {
                let _ = tx.send(closure(db));
            }))
            .await
            .unwrap();
        rx.await.unwrap()
    }

    /// Similar to [`DatabaseThread::with_database`], but without any return value. This function
    /// is slightly more optimized for this use case.
    pub async fn with_database_detached(
        &self,
        closure: impl FnOnce(&SqliteFullDatabase) + Send + 'static,
    ) {
        self.sender
            .lock()
            .await
            .send(Box::new(move |db| {
                closure(db);
            }))
            .await
            .unwrap();
    }
}

impl From<SqliteFullDatabase> for DatabaseThread {
    fn from(db: SqliteFullDatabase) -> DatabaseThread {
        let (sender, mut rx) = mpsc::channel::<Box<dyn FnOnce(&SqliteFullDatabase) + Send>>(256);

        thread::Builder::new()
            .name("sqlite-database".into())
            .spawn(move || {
                // When the `DatabaseThread` is dropped, the sender will close, `rx.next()`
                // will return `None`, and the closure here will finish, ending the thread.
                while let Some(closure) = futures::executor::block_on(rx.next()) {
                    closure(&db)
                }
            })
            .unwrap();

        DatabaseThread {
            sender: Mutex::new(sender),
        }
    }
}
