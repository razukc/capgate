#!/usr/bin/env node
// capgate CLI — thin wrapper over compile() + adapters.
//
// Usage:
//   capgate compile <manifest.json> [--target bwrap] [--pretty]
//
// Reads JSON from a file path (or "-" for stdin), lowers to the requested
// target, writes JSON to stdout. Errors go to stderr with a non-zero exit.
//
// This is deliberately minimal. Anything fancier (watch mode, multi-target,
// YAML output) belongs behind a feature flag, not here.

import { readFileSync } from 'node:fs';
import { compile, lowerToBwrap, CompilationError } from './policy/index.js';

interface Args {
  command: string | undefined;
  input: string | undefined;
  target: string;
  pretty: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: undefined,
    input: undefined,
    target: 'bwrap',
    pretty: false,
    help: false,
  };
  const rest = argv.slice(2);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '--pretty') args.pretty = true;
    else if (a === '--target') args.target = rest[++i];
    else if (!args.command) args.command = a;
    else if (!args.input) args.input = a;
  }
  return args;
}

const USAGE = `capgate — compile MCP manifests into sandbox policies

Usage:
  capgate compile <manifest.json|-> [--target bwrap] [--pretty]

Options:
  --target <name>   Adapter to lower to. Default: bwrap. Supported: bwrap.
  --pretty          Indent JSON output with 2 spaces.
  -h, --help        Show this message.

Examples:
  capgate compile manifests/filesystem.json --pretty
  cat manifest.json | capgate compile - --target bwrap
`;

function readInput(path: string): string {
  if (path === '-') return readFileSync(0, 'utf8');
  return readFileSync(path, 'utf8');
}

function main(): void {
  const args = parseArgs(process.argv);
  if (args.help || !args.command) {
    process.stdout.write(USAGE);
    process.exit(args.help ? 0 : 1);
  }
  if (args.command !== 'compile') {
    process.stderr.write(`capgate: unknown command "${args.command}"\n\n${USAGE}`);
    process.exit(2);
  }
  if (!args.input) {
    process.stderr.write(`capgate: compile requires a manifest path (or "-" for stdin)\n\n${USAGE}`);
    process.exit(2);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readInput(args.input));
  } catch (err) {
    process.stderr.write(`capgate: failed to read or parse manifest: ${(err as Error).message}\n`);
    process.exit(3);
  }

  try {
    const policy = compile(raw as Parameters<typeof compile>[0]);
    let output: unknown;
    switch (args.target) {
      case 'bwrap':
        output = lowerToBwrap(policy);
        break;
      default:
        process.stderr.write(`capgate: unsupported --target "${args.target}" (supported: bwrap)\n`);
        process.exit(2);
    }
    const indent = args.pretty ? 2 : 0;
    process.stdout.write(JSON.stringify(output, null, indent) + '\n');
  } catch (err) {
    if (err instanceof CompilationError) {
      process.stderr.write(`capgate: ${err.code}: ${err.message}\n`);
      process.exit(4);
    }
    throw err;
  }
}

main();
