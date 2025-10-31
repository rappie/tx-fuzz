# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TX-Fuzz is a Go package for generating random Ethereum transactions for testing execution layer clients. It generates fuzzed transactions to test client robustness against edge cases and malformed inputs.

## Development Commands

### Building

```bash
# Build the main livefuzzer tool
cd cmd/livefuzzer
go build

# Build specific EIP test tools
cd cmd/prague && go build
cd cmd/cancun && go build
cd cmd/shanghai && go build
```

### Linting

```bash
golangci-lint run
```

The project uses golangci-lint v2 with specific linters enabled (see .golangci.yml). Key enabled linters:
- staticcheck, govet, ineffassign
- misspell, unused, unconvert
- revive (with receiver-naming rule)

### Testing

The project uses example-based testing rather than traditional unit tests. Test executables are in `cmd/` subdirectories:
- `cmd/prague/` - Tests for Prague hard fork EIPs (7702, 7002, 7251, 2537, 3074)
- `cmd/cancun/` - Tests for Cancun hard fork EIPs (4788, 1153, 7516, 5656, 4844)
- `cmd/shanghai/` - Tests for Shanghai hard fork
- `cmd/eip4399/` - Tests for EIP-4399

### Running

```bash
# Run against local client (default port 8545)
./livefuzzer spam

# With custom RPC endpoint
./livefuzzer spam --rpc http://localhost:8545

# With seed for reproducibility
./livefuzzer spam --seed 12345

# With custom faucet key
./livefuzzer spam --sk 0x...

# Blob transactions
./livefuzzer blobs

# EIP-7702 (Pectra) transactions
./livefuzzer pectra

# Other commands
./livefuzzer airdrop     # Airdrop funds to test accounts
./livefuzzer create      # Create ephemeral accounts
./livefuzzer unstuck     # Unstuck accounts with nonce issues
```

## Architecture

### Core Package Structure

- **Root package (`txfuzz`)**: Core transaction generation functions
  - `transactions.go` - Main transaction generation logic (RandomTx, RandomValidTx, etc.)
  - `random.go` - Random data generation utilities
  - `accesslist.go` - Access list generation
  - `main.go` - Package-level constants (default RPC, SK, addresses)

- **`spammer/`**: Transaction spamming orchestration
  - `config.go` - Configuration management, CLI context parsing
  - `spam.go` - Core spam loop logic (SendBasicTransactions, SendBlobTransactions, Send7702Transactions)
  - `helper.go` - Account management (airdrop, unstuck)
  - `blob.go` - Blob transaction handling
  - `addresslist.go` - Static test account keys

- **`mutator/`**: Byte-level mutation strategies (borrowed from Go fuzzing)
  - Provides various mutation strategies: bit flips, arithmetic operations, byte swaps, etc.
  - Used to generate interesting edge cases

- **`helper/`**: High-level transaction execution helpers
  - Provides `Exec()`, `Execute()` functions used by EIP test programs
  - Handles transaction signing, gas estimation, RPC communication

- **`flags/`**: CLI flag definitions
  - Centralized flag definitions used across commands

- **`cmd/`**: Executable programs
  - `livefuzzer/` - Main interactive fuzzing tool with spam, blob, pectra commands
  - `prague/`, `cancun/`, `shanghai/`, `eip4399/` - Specific EIP test suites

### Key Design Patterns

1. **Filler-based generation**: Uses `FuzzyVM/filler.Filler` to generate random but valid EVM bytecode
2. **RPC-aware transactions**: Can query RPC for chainID, gas prices, nonces when generating valid transactions
3. **Mutation-based fuzzing**: Uses byte-level mutators to create edge cases from corpus elements
4. **Account pool management**: Maintains pool of funded accounts to enable parallel transaction sending
5. **Spam loop**: Continuous cycle of airdrop → spam → wait for slot time

### Transaction Generation Flow

1. Start with `RandomValidTx()` or similar function in root package
2. Use `filler.Filler` to generate random EVM bytecode via FuzzyVM
3. Apply mutations via `mutator.Mutator` if using corpus
4. Query RPC for real-world values (nonce, gas price, chain ID) when generating valid txs
5. Sign transaction with test account key
6. Send via `helper.SendTransaction()` or spammer's batched sending

### Important Implementation Details

- Default test faucet key is hardcoded in `main.go` (SK, ADDR constants)
- Static test account keys are stored in `spammer/addresslist.go`
- Default RPC endpoint: `http://127.0.0.1:8545`
- Default gas limit for spam: 30,000,000
- Supports EIP-1559 (dynamic fee), EIP-2930 (access list), EIP-4844 (blob), EIP-7702 transactions

## Dependencies

- `github.com/ethereum/go-ethereum` - Core Ethereum types and RPC client
- `github.com/MariusVanDerWijden/FuzzyVM` - EVM bytecode generation
- `github.com/holiman/goevmlab` - EVM testing utilities
- `github.com/urfave/cli/v2` - CLI framework
- Go 1.23.0+ required (toolchain go1.24.0)

## Common Patterns

### Adding new transaction type
1. Add generation function to root `transactions.go`
2. Add spam function to `spammer/spam.go` (e.g., `Send7702Transactions`)
3. Add CLI command to `cmd/livefuzzer/main.go`
4. Add command flags to appropriate flag group

### Adding EIP test cases
1. Create test function in appropriate `cmd/` directory (prague, cancun, etc.)
2. Use `helper.Execute()` or `helper.Exec()` for sending test transactions
3. Call test function from `main()` in that cmd's main.go
