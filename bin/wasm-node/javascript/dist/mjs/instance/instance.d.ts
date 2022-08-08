import * as instance from './raw-instance.js';
export { PlatformBindings, ConnectionError, ConnectionConfig, Connection } from './raw-instance.js';
/**
 * Contains the configuration of the instance.
 */
export interface Config {
    logCallback: (level: number, target: string, message: string) => void;
    maxLogLevel: number;
    enableCurrentTask: boolean;
    cpuRateLimit: number;
}
export interface Instance {
    request: (request: string, chainId: number) => void;
    addChain: (chainSpec: string, databaseContent: string, potentialRelayChains: number[], jsonRpcCallback?: (response: string) => void) => Promise<{
        success: true;
        chainId: number;
    } | {
        success: false;
        error: string;
    }>;
    removeChain: (chainId: number) => void;
    databaseContent: (chainId: number, maxUtf8BytesSize?: number) => Promise<string>;
    startShutdown: () => void;
}
export declare function start(configMessage: Config, platformBindings: instance.PlatformBindings): Instance;
