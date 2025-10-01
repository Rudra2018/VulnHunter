# Approved Security Tools Directory

This directory contains approved binaries for secure execution within the vulnerability detection framework.

## Installation Instructions

Place approved security analysis tools in this directory:

```bash
# Example: AFL++ fuzzing tools
cp /usr/bin/afl-fuzz ./tools/bin/
cp /usr/bin/afl-gcc ./tools/bin/
cp /usr/bin/afl-clang ./tools/bin/

# Static analysis tools
cp /usr/bin/cppcheck ./tools/bin/
cp /usr/local/bin/semgrep ./tools/bin/

# Set executable permissions
chmod +x ./tools/bin/*
```

## Security Policy

1. Only place tools you trust and have verified
2. Regularly audit contents of this directory
3. Remove unused tools to minimize attack surface
4. Tools must be from official sources or built from verified source code

## Approved Tool Categories

- Static analysis scanners (cppcheck, semgrep, etc.)
- Fuzzing tools (AFL++, libFuzzer, etc.)
- Code analysis utilities (clang-tidy, pylint, etc.)
- Build tools (make, cmake, gcc, clang)
- Language interpreters (python3, node, java)

## Prohibited Tools

- Network scanners (nmap, etc.)
- System administration tools (unless specifically needed)
- Compilers for untrusted code
- Tools with known vulnerabilities