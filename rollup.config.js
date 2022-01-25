import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';
import json from '@rollup/plugin-json';

export default {
    input: 'src/server.ts',
    output: {
        dir: 'dist',
        format: 'es'
    },
    plugins: [json(), nodeResolve({ browser: false, preferBuiltins: true }), commonjs(), typescript({ target: "es2017", downlevelIteration: true })]
};