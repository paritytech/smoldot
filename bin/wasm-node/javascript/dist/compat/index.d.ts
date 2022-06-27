/// <reference types="node" />
export function workerOnMessage(worker: any, callback: any): void;
export function workerOnError(worker: any, callback: any): void;
export function workerTerminate(worker: any): any;
export function postMessage(msg: any): void;
export function setOnMessage(callback: any): void;
export function performanceNow(): number;
export function isTcpAvailable(): boolean;
export function createConnection(opts: any, connectionListener: any): import("net").Socket;
export function getRandomValues(buffer: any): void;
