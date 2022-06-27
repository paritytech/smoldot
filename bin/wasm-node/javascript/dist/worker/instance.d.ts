import { SmoldotWasmInstance } from './bindings.js';
export interface Config {
    logCallback: (level: number, target: string, message: string) => void;
    jsonRpcCallback: (response: string, chainId: number) => void;
    databaseContentCallback: (data: string, chainId: number) => void;
    currentTaskCallback?: (taskName: string | null) => void;
    cpuRateLimit: number;
    forbidTcp: boolean;
    forbidWs: boolean;
    forbidNonLocalWs: boolean;
    forbidWss: boolean;
}
export declare function startInstance(config: Config): Promise<SmoldotWasmInstance>;
