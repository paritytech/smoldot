import { SmoldotWasmInstance } from './bindings';
export interface Config {
    instance?: SmoldotWasmInstance;
    logCallback: (level: number, target: string, message: string) => void;
    jsonRpcCallback: (response: string, chainId: number) => void;
    databaseContentCallback: (data: string, chainId: number) => void;
    forbidTcp: boolean;
    forbidWs: boolean;
    forbidNonLocalWs: boolean;
    forbidWss: boolean;
}
declare const _default: (config: Config) => WebAssembly.ModuleImports;
export default _default;
