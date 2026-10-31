# CoreTrust 18 Research

A reproducible, static-analysis research project for studying Mach-O binaries and Apple code-signature metadata.

**Status:** Early research tooling. This project does not implement a CoreTrust bypass, jailbreak, certificate forgery, or signature-enforcement circumvention.

## Goals

- Parse thin Mach-O headers and load commands without executing target files.
- Locate and inspect the structure of an embedded LC_CODE_SIGNATURE blob.
- Record structural facts that can be reproduced in tests.
- Build a documented corpus of harmless synthetic fixtures.
- Run tests automatically with GitHub Actions.

## Compatibility and limits

The initial parser is a host-side Python tool. It does not emulate iOS, reproduce Apple's CoreTrust trust decisions, validate a certificate chain, or establish whether a device is vulnerable. Results are structural observations only.

The target device discussed for this research is an iPhone 16 running iOS 18.5. No vulnerability or bypass is assumed to exist.

## Requirements

- Python 3.11 or newer
- No Mac, Windows PC, or iPhone required for host-side unit tests

## Quick start

    python -m pip install -e ".[dev]"
    pytest
    coretrust-inspect path/to/your/macho

The inspector reads a file as data. Only analyze files you are authorized to examine. Do not run unknown binaries.

## Project layout

- src/coretrust_research/macho.py — bounds-checked thin Mach-O parser
- src/coretrust_research/cli.py — command-line inspection interface
- tests/ — synthetic fixtures and parser tests
- .github/workflows/tests.yml — automated test workflow

## Research principles

1. Separate observed facts from hypotheses.
2. Preserve sample hashes and provenance when adding samples.
3. Prefer synthetic fixtures and public documentation.
4. Never describe a parser result as proof of exploitability.
5. Document device model, OS build, and test conditions for future on-device observations.

## License

MIT. See LICENSE.
