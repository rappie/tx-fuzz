package txfuzz

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// GetTypeName returns human-readable name for transaction type
func GetTypeName(txType uint8) string {
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

// FormatTransactionDetails returns a formatted multi-line string with comprehensive transaction details
func FormatTransactionDetails(tx *types.Transaction, sender common.Address) string {
	var b strings.Builder

	b.WriteString("\n=== Transaction Details ===\n")

	// Basic info
	b.WriteString(fmt.Sprintf("Type:              %s (%d)\n", GetTypeName(tx.Type()), tx.Type()))
	b.WriteString(fmt.Sprintf("Hash:              %s\n", tx.Hash().Hex()))
	b.WriteString(fmt.Sprintf("Nonce:             %d\n", tx.Nonce()))
	b.WriteString(fmt.Sprintf("From:              %s\n", sender.Hex()))

	// To address (handle contract creation)
	if tx.To() != nil {
		b.WriteString(fmt.Sprintf("To:                %s\n", tx.To().Hex()))
	} else {
		b.WriteString("To:                <Contract Creation>\n")
	}

	// Value
	b.WriteString(fmt.Sprintf("Value:             %s wei", tx.Value().String()))
	if tx.Value().Sign() > 0 {
		ethValue := new(big.Float).Quo(new(big.Float).SetInt(tx.Value()), big.NewFloat(1e18))
		b.WriteString(fmt.Sprintf(" (%.6f ETH)", ethValue))
	}
	b.WriteString("\n")

	// Data (truncated with size)
	dataLen := len(tx.Data())
	if dataLen > 0 {
		dataHex := common.Bytes2Hex(tx.Data())
		if dataLen <= 32 {
			b.WriteString(fmt.Sprintf("Data:              0x%s (%d bytes)\n", dataHex, dataLen))
		} else {
			b.WriteString(fmt.Sprintf("Data:              0x%s...%s (%d bytes)\n",
				dataHex[:64], dataHex[len(dataHex)-8:], dataLen))
		}
	} else {
		b.WriteString("Data:              <none>\n")
	}

	// Gas parameters
	b.WriteString("\nGas Parameters:\n")
	b.WriteString(fmt.Sprintf("  Gas Limit:       %d\n", tx.Gas()))

	if tx.Type() == 0 || tx.Type() == 1 {
		// Legacy or AccessList
		if tx.GasPrice() != nil {
			b.WriteString(fmt.Sprintf("  Gas Price:       %s wei (%.2f gwei)\n",
				tx.GasPrice().String(),
				float64(tx.GasPrice().Uint64())/1e9))
		}
	} else {
		// EIP-1559, blob, or set code
		if tx.GasTipCap() != nil {
			b.WriteString(fmt.Sprintf("  Gas Tip Cap:     %s wei (%.2f gwei)\n",
				tx.GasTipCap().String(),
				float64(tx.GasTipCap().Uint64())/1e9))
		}
		if tx.GasFeeCap() != nil {
			b.WriteString(fmt.Sprintf("  Gas Fee Cap:     %s wei (%.2f gwei)\n",
				tx.GasFeeCap().String(),
				float64(tx.GasFeeCap().Uint64())/1e9))
		}
	}

	// Chain ID
	if tx.ChainId() != nil {
		b.WriteString(fmt.Sprintf("\nChain ID:          %s\n", tx.ChainId().String()))
	}

	// Signature
	v, r, s := tx.RawSignatureValues()
	b.WriteString("\nSignature:\n")
	b.WriteString(fmt.Sprintf("  V:               %s\n", v.String()))
	b.WriteString(fmt.Sprintf("  R:               0x%s\n", r.Text(16)))
	b.WriteString(fmt.Sprintf("  S:               0x%s\n", s.Text(16)))
	b.WriteString(fmt.Sprintf("  Protected:       %t\n", tx.Protected()))

	// Type-specific fields
	if tx.Type() >= 1 && tx.AccessList() != nil && len(tx.AccessList()) > 0 {
		b.WriteString(fmt.Sprintf("\nAccess List:       %d entries\n", len(tx.AccessList())))
		for i, entry := range tx.AccessList() {
			b.WriteString(fmt.Sprintf("  [%d] Address: %s\n", i, entry.Address.Hex()))
			b.WriteString(fmt.Sprintf("      Keys: %d\n", len(entry.StorageKeys)))
		}
	}

	if tx.Type() == 3 {
		// Blob transaction
		if tx.BlobGasFeeCap() != nil {
			b.WriteString(fmt.Sprintf("\nBlob Fee Cap:      %s wei\n", tx.BlobGasFeeCap().String()))
		}
		if hashes := tx.BlobHashes(); len(hashes) > 0 {
			b.WriteString(fmt.Sprintf("Blob Hashes:       %d blobs\n", len(hashes)))
			for i, hash := range hashes {
				b.WriteString(fmt.Sprintf("  [%d] %s\n", i, hash.Hex()))
			}
		}
		if tx.BlobGas() > 0 {
			b.WriteString(fmt.Sprintf("Blob Gas:          %d\n", tx.BlobGas()))
		}
	}

	if tx.Type() == 4 {
		// Set code transaction (EIP-7702)
		b.WriteString("\nSet Code Transaction (EIP-7702)\n")
	}

	// Size
	b.WriteString(fmt.Sprintf("\nTransaction Size:  %d bytes\n", tx.Size()))
	b.WriteString("==========================================")

	return b.String()
}
