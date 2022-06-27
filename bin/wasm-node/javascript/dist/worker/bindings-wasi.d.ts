import * as compat from '../compat/index.js';
import type { SmoldotWasmInstance } from './bindings.js';
export interface Config {
    instance?: SmoldotWasmInstance;
    /**
     * List of environment variables to feed to the Rust program. An array of strings.
     * Example: `["RUST_BACKTRACE=1", "RUST_LOG=foo"];`
     *
     * Must never be modified after the bindings have been initialized.
     */
    envVars: string[];
}
declare const _default: (config: Config) => compat.WasmModuleImports;
export default _default;
