// Smoldot
// Copyright (C) 2024  Pierre Krieger
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

use core::{iter, pin::Pin};

use super::{Address, ConnectionType, LogLevel, MultiStreamAddress, PlatformRef};
use alloc::{borrow::Cow, format, string::String};

/// Implementation of a [`PlatformRef`] that wraps around another platform and adds a prefix
/// before every log line and task name.
#[derive(Debug, Clone)]
pub struct WithPrefix<T> {
    inner: T,
    prefix: String,
}

impl<T> WithPrefix<T> {
    /// Builds a new [`WithPrefix`].
    pub const fn new(prefix: String, inner: T) -> Self {
        WithPrefix { inner, prefix }
    }
}

impl<T: PlatformRef> PlatformRef for WithPrefix<T> {
    type Delay = T::Delay;
    type Instant = T::Instant;
    type MultiStream = T::MultiStream;
    type Stream = T::Stream;
    type ReadWriteAccess<'a> = T::ReadWriteAccess<'a>;
    type StreamErrorRef<'a> = T::StreamErrorRef<'a>;
    type StreamConnectFuture = T::StreamConnectFuture;
    type MultiStreamConnectFuture = T::MultiStreamConnectFuture;
    type StreamUpdateFuture<'a> = T::StreamUpdateFuture<'a>;
    type NextSubstreamFuture<'a> = T::NextSubstreamFuture<'a>;

    fn now_from_unix_epoch(&self) -> core::time::Duration {
        self.inner.now_from_unix_epoch()
    }

    fn now(&self) -> Self::Instant {
        self.inner.now()
    }

    fn fill_random_bytes(&self, buffer: &mut [u8]) {
        self.inner.fill_random_bytes(buffer)
    }

    fn sleep(&self, duration: core::time::Duration) -> Self::Delay {
        self.inner.sleep(duration)
    }

    fn sleep_until(&self, when: Self::Instant) -> Self::Delay {
        self.inner.sleep_until(when)
    }

    fn spawn_task(&self, task_name: Cow<str>, task: impl Future<Output = ()> + Send + 'static) {
        self.inner
            .spawn_task(Cow::Owned(format!("{}-{}", self.prefix, task_name)), task)
    }

    fn log<'a>(
        &self,
        log_level: LogLevel,
        log_target: &'a str,
        message: &'a str,
        mut key_values: impl Iterator<Item = (&'a str, &'a dyn core::fmt::Display)>,
    ) {
        self.inner.log(
            log_level,
            &format!("{}-{}", self.prefix, log_target),
            message,
            // We have to use `iter::from_fn` due to a lifetime mismatch between the items
            // produced by the iterator and the newly-constructed log target.
            iter::from_fn(move || key_values.next()),
        )
    }

    fn client_name(&'_ self) -> Cow<'_, str> {
        self.inner.client_name()
    }

    fn client_version(&'_ self) -> Cow<'_, str> {
        self.inner.client_version()
    }

    fn supports_connection_type(&self, connection_type: ConnectionType) -> bool {
        self.inner.supports_connection_type(connection_type)
    }

    fn connect_stream(&self, address: Address) -> Self::StreamConnectFuture {
        self.inner.connect_stream(address)
    }

    fn connect_multistream(&self, address: MultiStreamAddress) -> Self::MultiStreamConnectFuture {
        self.inner.connect_multistream(address)
    }

    fn open_out_substream(&self, connection: &mut Self::MultiStream) {
        self.inner.open_out_substream(connection)
    }

    fn next_substream<'a>(
        &self,
        connection: &'a mut Self::MultiStream,
    ) -> Self::NextSubstreamFuture<'a> {
        self.inner.next_substream(connection)
    }

    fn read_write_access<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Result<Self::ReadWriteAccess<'a>, Self::StreamErrorRef<'a>> {
        self.inner.read_write_access(stream)
    }

    fn stream_reset_code(&self, error: &Self::StreamErrorRef<'_>) -> Option<u32> {
        self.inner.stream_reset_code(error)
    }

    fn wait_read_write_again<'a>(
        &self,
        stream: Pin<&'a mut Self::Stream>,
    ) -> Self::StreamUpdateFuture<'a> {
        self.inner.wait_read_write_again(stream)
    }
}
