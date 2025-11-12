package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	// Parse CLI flags
	rpcURL := flag.String("rpc", "http://127.0.0.1:8545", "RPC endpoint URL")
	flag.Parse()

	// Get JSON file path
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(os.Stderr, "Usage: go run replay_tx.go <json-file> [--rpc <url>]\n")
		fmt.Fprintf(os.Stderr, "Example: go run replay_tx.go ./failed_txs/20251103_124540/legacy_114650_nonce_20991.json\n")
		os.Exit(1)
	}
	jsonFile := args[0]

	// Setup logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Run replay
	if err := replayTransaction(jsonFile, *rpcURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func replayTransaction(jsonFile string, rpcURL string) error {
	// Read and parse JSON
	slog.Info(fmt.Sprintf("Reading failed transaction from: %s", jsonFile))
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var failedCtx txfuzz.FailedTxContext
	if err := json.Unmarshal(data, &failedCtx); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Validate error type
	slog.Info(fmt.Sprintf("Original error: %s", failedCtx.Error.Message))

	// Decode RLP transaction
	slog.Info(fmt.Sprintf("Decoding transaction RLP (type=%d, nonce=%d)", failedCtx.Transaction.Type, failedCtx.Transaction.Nonce))
	rlpHex := strings.TrimPrefix(failedCtx.Transaction.RLP, "0x")
	rlpBytes, err := hex.DecodeString(rlpHex)
	if err != nil {
		return fmt.Errorf("failed to decode RLP hex: %w", err)
	}

	var tx types.Transaction
	if err := tx.UnmarshalBinary(rlpBytes); err != nil {
		return fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	// Extract sender
	var signer types.Signer
	if tx.Type() == types.BlobTxType || tx.Type() == types.DynamicFeeTxType {
		signer = types.LatestSignerForChainID(tx.ChainId())
	} else if tx.Type() == types.SetCodeTxType {
		signer = types.NewPragueSigner(tx.ChainId())
	} else {
		signer = types.LatestSignerForChainID(tx.ChainId())
	}

	sender, err := types.Sender(signer, &tx)
	if err != nil {
		return fmt.Errorf("failed to extract sender: %w", err)
	}

	slog.Info(fmt.Sprintf("Transaction decoded: hash=%s sender=%s gas=%d", tx.Hash().Hex(), sender.Hex(), tx.Gas()))

	// Print comprehensive transaction details
	fmt.Println(txfuzz.FormatTransactionDetails(&tx, sender))

	// Connect to RPC
	slog.Info(fmt.Sprintf("Connecting to RPC: %s", rpcURL))
	backend, err := ethclient.Dial(rpcURL)
	if err != nil {
		return fmt.Errorf("failed to connect to RPC: %w", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Perform gas estimation
	slog.Info("Calling EstimateGas on RPC...")
	msg := ethereum.CallMsg{
		From:      sender,
		To:        tx.To(),
		Gas:       0, // Let RPC estimate without constraints
		GasPrice:  tx.GasPrice(),
		GasFeeCap: tx.GasFeeCap(),
		GasTipCap: tx.GasTipCap(),
		Value:     tx.Value(),
		Data:      tx.Data(),
	}

	estimatedGas, gasErr := backend.EstimateGas(ctx, msg)
	if gasErr != nil {
		slog.Warn(fmt.Sprintf("Gas estimation failed: %v", gasErr))
	} else {
		slog.Info(fmt.Sprintf("Gas estimation succeeded: %d (original was %d)", estimatedGas, tx.Gas()))
	}

	// Send transaction
	slog.Info("Sending transaction to network...")
	sendErr := backend.SendTransaction(ctx, &tx)
	if sendErr != nil {
		slog.Warn(fmt.Sprintf("Transaction send failed: %v", sendErr))
	} else {
		slog.Info(fmt.Sprintf("Transaction sent successfully: %s", tx.Hash().Hex()))
	}

	// Summary
	fmt.Println("\n=== Replay Summary ===")
	fmt.Printf("File:            %s\n", jsonFile)
	fmt.Printf("Original Error:  %s\n", failedCtx.Error.Message)
	fmt.Printf("Transaction:     %s (type=%d, nonce=%d, gas=%d)\n", tx.Hash().Hex(), tx.Type(), tx.Nonce(), tx.Gas())
	fmt.Printf("Sender:          %s\n", sender.Hex())
	if gasErr != nil {
		fmt.Printf("Gas Estimation:  FAILED - %v\n", gasErr)
	} else {
		fmt.Printf("Gas Estimation:  SUCCESS - %d gas\n", estimatedGas)
	}
	if sendErr != nil {
		fmt.Printf("Transaction:     FAILED - %v\n", sendErr)
	} else {
		fmt.Printf("Transaction:     SENT - %s\n", tx.Hash().Hex())
	}

	return nil
}
