import { SmoldotWasmInstance } from './bindings';
export interface Config {
    instance?: SmoldotWasmInstance;
}
declare const _default: (config: Config) => WebAssembly.ModuleImports;
export default _default;
