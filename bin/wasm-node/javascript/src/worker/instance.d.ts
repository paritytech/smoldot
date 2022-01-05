import { SmoldotWasmInstance } from './bindings';
export interface Config {
    logCallback: (level: number, target: string, message: string) => void;
    jsonRpcCallback: (response: string, chainId: number) => void;
    databaseContentCallback: (data: string, chainId: number) => void;
    forbidTcp: boolean;
    forbidWs: boolean;
    forbidNonLocalWs: boolean;
    forbidWss: boolean;
}
export declare function startInstance(config: Config): Promise<SmoldotWasmInstance>;
