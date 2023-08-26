/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
import resolve from "@rollup/plugin-node-resolve";
import nodePolyfills from "rollup-plugin-polyfill-node";
import json from "@rollup/plugin-json";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import { uglify } from "rollup-plugin-uglify";
import pkg from "./package.json" assert { type: "json" };

const inputs = ["src/index.ts"];
const includes = ["src/**"];

export default [
    // browser-friendly UMD build
    {
        input: inputs,
        external: [],
        output: {
            name: "pheVotingJs",
            file: pkg.browser,
            format: "umd",
            sourcemap: "inline",
            globals: {
                crypto: "crypto",
            },
        },
        plugins: [
            typescript({
                tsconfig: "./tsconfig.json",
                include: includes,
            }),
            resolve({
                browser: true,
                preferBuiltins: false,
            }),
            /*nodePolyfills({
                crypto: true,
                exclude: [],
            }),*/
            commonjs(),
            json(),
            uglify(),
        ],
    },

    // CommonJS (for Node) and ES module (for bundlers) build.
    // (We could have three entries in the configuration array
    // instead of two, but it's quicker to generate multiple
    // builds from a single configuration where possible, using
    // an array for the `output` option, where we can specify
    // `file` and `format` for each target)
    {
        input: "src/index.ts",
        external: [],
        output: [
            { file: pkg.main, format: "cjs", sourcemap: "inline" },
            { file: pkg.module, format: "esm", sourcemap: "inline" },
        ],
        plugins: [
            resolve({
                browser: false,
                preferBuiltins: true,
            }),
            commonjs(),
            typescript({
                tsconfig: "./tsconfig.json",
                include: includes,
            }),
            json(),
            uglify(),
        ],
    },
];
