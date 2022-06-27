import * as compat from '../compat/index.js';
import type { SmoldotWasmInstance } from './bindings.js';
export interface Config {
    instance?: SmoldotWasmInstance;
    logCallback: (level: number, target: string, message: string) => void;
    jsonRpcCallback: (response: string, chainId: number) => void;
    databaseContentCallback: (data: string, chainId: number) => void;
    currentTaskCallback?: (taskName: string | null) => void;
    forbidTcp: boolean;
    forbidWs: boolean;
    forbidNonLocalWs: boolean;
    forbidWss: boolean;
}
export default function (config: Config): compat.WasmModuleImports;
