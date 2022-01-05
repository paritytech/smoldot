/// <reference path="browser.d.ts" />
/// <reference types="node" />
import { Worker as NodeJsWorker } from 'worker_threads';
export * from './nodejs';
export { Socket as NodeJsSocket } from 'net';
export declare type CompatWorker = NodeJsWorker | Worker;
export declare type Timeout = NodeJS.Timeout | number;
export interface TcpConnectionOptions {
    port: number;
    host: string;
}
