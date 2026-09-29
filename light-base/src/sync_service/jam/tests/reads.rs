// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Verified state reads: reservation, retries and provenance.

use super::*;

#[test]
fn state_reads_provenance_retry_and_transient() {
    smol::block_on(async {
        for trust in [Trust::Finalized, Trust::Authenticated] {
            let mut reads = StateReads::default();
            let key = trie::state_key(8);
            let mut node = [0; 64];
            node[0] = 0x81;
            node[1..32].copy_from_slice(&key);
            node[32] = 7;
            let root = smoldot::jam::crypto::blake2b_256(&node);
            let read = StateRead {
                root_header: Some([3; 32]),
                at: [9; 32],
                root,
                trust,
                request: StateRequest {
                    block: [9; 32],
                    start: key,
                    end: key,
                    max_size: 4000,
                },
            };
            let result = reads.start(read.clone()).unwrap();
            assert!(reads.start(read.clone()).is_err());
            assert!(reads.reserve(0).is_some());
            assert!(reads.reserve(1).is_none());
            reads.release(0, true);
            assert!(reads.reserve(0).is_some());
            let bad = StateResponse {
                nodes: vec![node],
                entries: vec![(key, vec![8])],
            };
            assert!(reads.received(0, &bad).is_err());
            assert!(reads.reserve(0).is_none());
            assert!(reads.reserve(1).is_some());
            let good = StateResponse {
                nodes: vec![node],
                entries: vec![(key, vec![7])],
            };
            reads.received(1, &good).unwrap();
            let result = result.await.unwrap().unwrap();
            assert_eq!(result.root_header, read.root_header);
            assert_eq!(
                (result.at, result.root, result.trust),
                (read.at, root, trust)
            );
            assert_eq!(result.range.entries, good.entries);
        }
        let mut reads = StateReads::default();
        let req = StateRequest {
            block: [9; 32],
            start: [0; 31],
            end: [0; 31],
            max_size: 1,
        };
        let _rx = reads
            .start(StateRead {
                root_header: None,
                at: req.block,
                root: [0; 32],
                trust: Trust::Finalized,
                request: req,
            })
            .unwrap();
        assert!(reads.reserve(0).is_some());
        reads.release(0, false); // NoData: another peer, not the refusing peer.
        assert!(reads.reserve(0).is_none());
        assert!(reads.reserve(1).is_some());
        assert_eq!(classify_reset(Some(6)), net::RequestError::NoData);
        assert_eq!(classify_reset(Some(3)), net::RequestError::Transient);
        assert_eq!(classify_reset(Some(1)), net::RequestError::Rejected);
        assert_eq!(classify_reset(None), net::RequestError::ResetWithoutCode);
    });
}

#[test]
fn state_read_exhaustion_frees_slot() {
    smol::block_on(async {
        for peers in 0..=2 {
            let mut reads = StateReads::new(peers);
            let read = StateRead {
                at: [0; 32],
                root: [0; 32],
                trust: Trust::Finalized,
                root_header: None,
                request: StateRequest {
                    block: [0; 32],
                    start: [0; 31],
                    end: [0; 31],
                    max_size: 1,
                },
            };
            let rx = reads.start(read.clone()).unwrap();
            for peer in 0..peers {
                assert!(reads.reserve(peer).is_some());
                reads.release(peer, false);
            }
            assert_eq!(rx.await.unwrap().unwrap_err(), StateReadError::Unavailable);
            assert!(reads.start(read).is_ok());
        }
    });
}

/// How the first peer fails a state read.
#[derive(Clone, Copy, PartialEq)]
enum ReadFailure {
    /// The proof does not match the root.
    BadProof,
    NoData,
    Transient,
    /// A reset without a code, as Firefox reports every reset.
    ResetWithoutCode,
    /// The stream never opens, so the opening deadline fires first.
    OpeningDeadline,
}

#[test]
fn state_read_scripted_driver_retries_proof_nodata_and_transient() {
    smol::block_on(async {
        use ReadFailure::*;
        for failure in [
            BadProof,
            NoData,
            Transient,
            ResetWithoutCode,
            OpeningDeadline,
        ] {
            let state = Arc::new(async_lock::Mutex::new(root_state()));
            let params = state.lock().await.params.clone();
            let genesis = Final {
                hash: state.lock().await.tree.finalized().hash(),
                slot: 0,
            };
            let platform = platform(Control {
                handshake: handshake_frame(genesis, vec![]),
                supported: true,
                ..Control::default()
            });
            let key = trie::state_key(8);
            let value = vec![7; 336 * 6 + 2];
            let (root, good) = active_set_trie(&value);
            let mut bad = good.clone();
            *bad.last_mut().unwrap() ^= 1;
            let first = match failure {
                BadProof => Ok(bad),
                NoData => Err(Reset(Some(6), "no state")),
                ResetWithoutCode => Err(Reset(None, "Error in input stream")),
                _ => Err(Reset(Some(3), "busy")),
            };
            {
                let mut c = platform.0.lock().unwrap();
                c.io.stall_outbound = failure == OpeningDeadline;
                c.io.state_responses = if failure == OpeningDeadline {
                    [Ok(good)].into()
                } else {
                    [first, Ok(good)].into()
                };
            }
            // Authenticate two scripted headers, finalize the first with a real
            // signature, and read its state against the second's prior root.
            let read = {
                let (keys, public) = grandpa_key(42).await;
                let mut s = state.lock().await;
                assert!(s.finalized_read(key, key, 4000).is_none());
                s.authorities =
                    AuthoritySet::from_checkpoint(&params, 0, vec![public; 6], vec![public; 6])
                        .unwrap();
                let mut header = Header::decode(&params, s.tree.finalized().encoded()).unwrap();
                let mut target = None;
                for slot in 1..=2 {
                    let parent = s.tree.best().clone();
                    header.parent = parent.hash();
                    header.slot = slot;
                    header.prior_state_root = root;
                    target.get_or_insert(final_of(&params, &header));
                    let verified = assume_verified(&params, &header, parent.post_state().clone());
                    s.tree.insert_verified(verified).unwrap();
                }
                let target = target.unwrap();
                let commit = (target.clone(), root);
                let signer = (&keys, public);
                let proof = single_vote_justification(signer, (1, 0), commit, &[], &params).await;
                s.finalize(target.hash, &proof).unwrap();
                let read = s.finalized_read(key, key, 4000).unwrap();
                assert_eq!((read.at, read.root), (target.hash, root));
                assert_eq!(read.root_header, Some(s.tree.best().hash()));
                read
            };
            let rx = state.lock().await.reads.start(read.clone()).unwrap();
            // Run the failing peer first. NoData leaves the connection alive, so
            // end that turn as soon as it releases the shared reservation.
            let released = async {
                let mut shifted = false;
                loop {
                    let owner = state.lock().await.reads.owner;
                    if failure == OpeningDeadline {
                        if owner.is_some() && !shifted {
                            platform.0.lock().unwrap().clock_shift = Duration::from_secs(21);
                            shifted = true;
                        }
                        if shifted && owner.is_none() {
                            break;
                        }
                    } else if !platform.0.lock().unwrap().io.state_requests.is_empty()
                        && owner.is_none()
                    {
                        break;
                    }
                    future::yield_now().await;
                }
            };
            let mut fetch = FetchSize::default();
            let connection = fake_connection(&platform);
            let driver = drive(
                &platform,
                "state-test",
                &params,
                0,
                &state,
                connection,
                &mut fetch,
            );
            future::or(driver, released).await;
            // The teardown cleanup of `peer_loop`; also covers an opening
            // deadline firing before the queued read's deadline.
            state.lock().await.reads.release(0, false);
            platform.0.lock().unwrap().io.stall_outbound = false;
            let peer = if failure == Transient { 0 } else { 1 };
            if failure != Transient {
                assert!(state.lock().await.reads.reserve(0).is_none());
            }
            let mut fetch = FetchSize::default();
            let connection = fake_connection(&platform);
            let driver = drive(
                &platform,
                "state-test",
                &params,
                peer,
                &state,
                connection,
                &mut fetch,
            );
            let result = while_driving(10, "state read", driver, async {
                rx.await.unwrap().unwrap()
            })
            .await;
            assert_eq!(
                (result.at, result.root, result.trust),
                (read.at, read.root, read.trust)
            );
            assert_eq!(result.range.entries, vec![(key, value)]);
            assert_eq!(result.root_header, read.root_header);
            let reads = if failure == OpeningDeadline { 1 } else { 2 };
            assert_eq!(
                platform.0.lock().unwrap().io.state_requests,
                vec![read.request.encode().to_vec(); reads]
            );
        }
    });
}

/// A reset without a code fails a state read like `NoData`, but three in a
/// row end the connection; a response in between starts the count again.
#[test]
fn three_resets_without_code_in_a_row_end_the_connection() {
    smol::block_on(async {
        let mut state = root_state();
        // One peer, so each failed read ends at once and the next can start.
        state.reads = StateReads::new(1);
        let genesis = Final {
            hash: state.tree.finalized().hash(),
            slot: 0,
        };
        let params = state.params.clone();
        let state = Arc::new(async_lock::Mutex::new(state));
        let platform = platform(Control {
            handshake: handshake_frame(genesis, vec![]),
            supported: true,
            ..Control::default()
        });
        let key = trie::state_key(8);
        let (root, good) = active_set_trie(&[7; 336 * 6 + 2]);
        let codeless = || Err(Reset(None, "Error in input stream"));
        let responses = [
            codeless(),
            codeless(),
            Ok(good),
            codeless(),
            codeless(),
            codeless(),
        ];
        platform.0.lock().unwrap().io.state_responses = responses.into();
        let read = StateRead {
            at: [9; 32],
            root,
            trust: Trust::Finalized,
            root_header: None,
            request: StateRequest {
                block: [9; 32],
                start: key,
                end: key,
                max_size: 4000,
            },
        };
        let mut answered = Vec::new();
        let reads = async {
            for _ in 0..6 {
                let rx = state.lock().await.reads.start(read.clone()).unwrap();
                answered.push(rx.await.unwrap().is_ok());
            }
            future::pending().await
        };
        let mut fetch = FetchSize::default();
        let connection = fake_connection(&platform);
        let driver = drive_connection(
            &platform, "codeless", &params, 0, &state, connection, &mut fetch,
        );
        let end = within(10, "resets without a code", future::or(driver, reads)).await;
        assert_eq!(end.as_str(), "resets-without-code");
        // The third reset in a row fails its read before the connection ends.
        assert_eq!(answered[..5], [false, false, true, false, false]);
        assert_eq!(platform.0.lock().unwrap().io.state_requests.len(), 6);
    });
}
