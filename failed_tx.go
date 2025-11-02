package txfuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// FailedTxContext contains complete context about a failed transaction
type FailedTxContext struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`

	Error ErrorInfo `json:"error"`

	Network NetworkState `json:"network"`

	Transaction TransactionInfo `json:"transaction"`

	AccountState AccountState `json:"accountState,omitempty"`

	Fuzzer FuzzerContext `json:"fuzzer,omitempty"`
}

// ErrorInfo contains information about the failure
type ErrorInfo struct {
	Message string `json:"message"`
}

// NetworkState contains network state at the time of failure
type NetworkState struct {
	RPC         string `json:"rpc,omitempty"`
	ChainID     string `json:"chainId"`
	BlockNumber uint64 `json:"blockNumber,omitempty"`
	BaseFee     string `json:"baseFee,omitempty"`
	BlobBaseFee string `json:"blobBaseFee,omitempty"`
}

// TransactionInfo contains the transaction details
type TransactionInfo struct {
	Type   uint8  `json:"type"`
	Hash   string `json:"hash"`
	RLP    string `json:"rlp"` // Hex-encoded RLP of signed transaction
	Sender string `json:"sender"`
	Nonce  uint64 `json:"nonce"`

	// Transaction-specific fields (populated based on type)
	GasLimit   uint64 `json:"gasLimit"`
	GasPrice   string `json:"gasPrice,omitempty"`
	GasTipCap  string `json:"gasTipCap,omitempty"`
	GasFeeCap  string `json:"gasFeeCap,omitempty"`
	To         string `json:"to"` // Empty string for contract creation
	Value      string `json:"value"`
	Data       string `json:"data"`
	AccessList string `json:"accessList,omitempty"`

	// Blob-specific fields
	BlobFeeCap string `json:"blobFeeCap,omitempty"`
	BlobHashes string `json:"blobHashes,omitempty"`

	// EIP-7702 specific
	AuthList string `json:"authList,omitempty"`
}

// AccountState contains account state at time of failure
type AccountState struct {
	Balance string `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

// FuzzerContext contains fuzzer-specific context
type FuzzerContext struct {
	Seed          string  `json:"seed,omitempty"`
	GasMultiplier float64 `json:"gasMultiplier,omitempty"`
}

// failedTxStorage holds the storage configuration
type failedTxStorage struct {
	enabled     bool
	baseDir     string
	rpcEndpoint string
}

var storage *failedTxStorage

// SetFailedTxStorage enables or disables failed transaction storage
func SetFailedTxStorage(enabled bool, baseDir string, rpcEndpoint string) {
	if enabled {
		storage = &failedTxStorage{
			enabled:     true,
			baseDir:     baseDir,
			rpcEndpoint: rpcEndpoint,
		}
		slog.Debug(fmt.Sprintf("Failed transaction storage enabled: dir=%s", baseDir))
	} else {
		storage = nil
	}
}

// SaveFailedTransaction saves a failed transaction to disk with full context
func SaveFailedTransaction(ctx context.Context, backend *ethclient.Client, tx *types.Transaction, err error) {
	if storage == nil || !storage.enabled {
		return
	}

	// Extract transaction details
	txInfo, sender := extractTransactionInfo(tx)

	// Gather network state
	networkState := gatherNetworkState(ctx, backend, storage.rpcEndpoint)

	// Gather account state
	accountState := gatherAccountState(ctx, backend, sender)

	// Build full context
	failedCtx := FailedTxContext{
		Version:      "1.0",
		Timestamp:    time.Now().UTC(),
		Error:        ErrorInfo{Message: err.Error()},
		Network:      networkState,
		Transaction:  txInfo,
		AccountState: accountState,
		Fuzzer:       FuzzerContext{}, // Will be populated if we add fuzzer context tracking
	}

	// Save to disk
	if err := saveToFile(failedCtx, tx.Type(), tx.Nonce()); err != nil {
		slog.Warn(fmt.Sprintf("Failed to save failed transaction: %v", err))
	} else {
		slog.Info(fmt.Sprintf("Saved failed transaction: nonce=%d type=%d", tx.Nonce(), tx.Type()))
	}
}

// extractTransactionInfo extracts all relevant info from a transaction
func extractTransactionInfo(tx *types.Transaction) (TransactionInfo, common.Address) {
	// Determine signer
	var signer types.Signer
	var from common.Address

	if tx.Type() == types.BlobTxType || tx.Type() == types.DynamicFeeTxType {
		signer = types.LatestSignerForChainID(tx.ChainId())
	} else if tx.Type() == types.SetCodeTxType {
		signer = types.NewPragueSigner(tx.ChainId())
	} else {
		signer = types.LatestSignerForChainID(tx.ChainId())
	}

	from, _ = types.Sender(signer, tx)

	// Serialize transaction to RLP
	rlpBytes, err := tx.MarshalBinary()
	if err != nil {
		rlpBytes = []byte{}
	}

	// Build transaction info
	info := TransactionInfo{
		Type:     tx.Type(),
		Hash:     tx.Hash().Hex(),
		RLP:      fmt.Sprintf("0x%x", rlpBytes),
		Sender:   from.Hex(),
		Nonce:    tx.Nonce(),
		GasLimit: tx.Gas(),
		Value:    tx.Value().String(),
		Data:     fmt.Sprintf("0x%x", tx.Data()),
	}

	// To address (may be nil for contract creation)
	if tx.To() != nil {
		info.To = tx.To().Hex()
	}

	// Gas pricing fields (type-dependent)
	if tx.GasPrice() != nil && tx.GasPrice().Sign() > 0 {
		info.GasPrice = tx.GasPrice().String()
	}
	if tx.GasTipCap() != nil && tx.GasTipCap().Sign() > 0 {
		info.GasTipCap = tx.GasTipCap().String()
	}
	if tx.GasFeeCap() != nil && tx.GasFeeCap().Sign() > 0 {
		info.GasFeeCap = tx.GasFeeCap().String()
	}

	// Access list
	if tx.AccessList() != nil && len(tx.AccessList()) > 0 {
		alBytes, _ := json.Marshal(tx.AccessList())
		info.AccessList = string(alBytes)
	}

	// Blob fields
	if tx.BlobGasFeeCap() != nil && tx.BlobGasFeeCap().Sign() > 0 {
		info.BlobFeeCap = tx.BlobGasFeeCap().String()
	}
	if tx.BlobHashes() != nil && len(tx.BlobHashes()) > 0 {
		hashesBytes, _ := json.Marshal(tx.BlobHashes())
		info.BlobHashes = string(hashesBytes)
	}

	return info, from
}

// gatherNetworkState fetches current network state
func gatherNetworkState(ctx context.Context, backend *ethclient.Client, rpcEndpoint string) NetworkState {
	state := NetworkState{
		RPC: rpcEndpoint,
	}

	// Chain ID
	if chainID, err := backend.ChainID(ctx); err == nil {
		state.ChainID = fmt.Sprintf("0x%x", chainID)
	}

	// Current block number
	if header, err := backend.HeaderByNumber(ctx, nil); err == nil {
		state.BlockNumber = header.Number.Uint64()
		if header.BaseFee != nil {
			state.BaseFee = header.BaseFee.String()
		}
	}

	return state
}

// gatherAccountState fetches account state at time of failure
func gatherAccountState(ctx context.Context, backend *ethclient.Client, account common.Address) AccountState {
	state := AccountState{}

	// Balance
	if balance, err := backend.BalanceAt(ctx, account, nil); err == nil {
		state.Balance = balance.String()
	}

	// Nonce
	if nonce, err := backend.NonceAt(ctx, account, nil); err == nil {
		state.Nonce = nonce
	}

	return state
}

// saveToFile writes the failed transaction context to a JSON file
func saveToFile(ctx FailedTxContext, txType uint8, nonce uint64) error {
	// Determine transaction type name for subdirectory
	typeName := getTypeName(txType)

	// Create directory structure: baseDir/YYYY-MM-DD/typeName/
	dateStr := ctx.Timestamp.Format("2006-01-02")
	dir := filepath.Join(storage.baseDir, dateStr, typeName)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Generate filename: tx_HHMMSS_nonce_N.json
	timeStr := ctx.Timestamp.Format("150405")
	filename := fmt.Sprintf("tx_%s_nonce_%d.json", timeStr, nonce)
	filepath := filepath.Join(dir, filename)

	// Marshal to JSON with indentation
	jsonBytes, err := json.MarshalIndent(ctx, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write atomically: write to temp file, then rename
	tempPath := filepath + ".tmp"
	if err := os.WriteFile(tempPath, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempPath, filepath); err != nil {
		os.Remove(tempPath) // Clean up temp file
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// getTypeName returns a human-readable name for a transaction type
func getTypeName(txType uint8) string {
	switch txType {
	case types.LegacyTxType:
		return "legacy"
	case types.AccessListTxType:
		return "access_list"
	case types.DynamicFeeTxType:
		return "dynamic_fee"
	case types.BlobTxType:
		return "blob"
	case types.SetCodeTxType:
		return "set_code"
	default:
		return fmt.Sprintf("type_%d", txType)
	}
}

// bigIntToString safely converts *big.Int to string
func bigIntToString(val *big.Int) string {
	if val == nil {
		return "0"
	}
	return val.String()
}
