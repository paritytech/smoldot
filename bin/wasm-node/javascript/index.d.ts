// Copyright 2018-2021 @paritytech/substrate-light-ui authors & contributors
// This software may be modified and distributed under the terms
// of the Apache-2.0 license. See the LICENSE file for details.

declare class SmoldotError extends Error {
  constructor(message: string) {}
}

export interface SmoldotClient {
  send_json_rpc(rpc: string): void;
}

export type SmoldotJsonRpcCallback = (response: string) => void;
export type SmoldotDatabaseSaveCallback = (response: string) => void;

export interface SmoldotOptions {
  max_log_level?: number;
  chain_spec: string;
  json_rpc_callback: SmoldotJsonRpcCallback;
  database_save_callback: SmoldotDatabaseSaveCallback;
  database_content?: string;
}

export interface Smoldot {
  start(options: SmoldotOptions): Promise<SmoldotClient>;
}

export var smoldot: Smoldot;

export default smoldot;
