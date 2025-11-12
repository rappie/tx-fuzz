package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/MariusVanDerWijden/tx-fuzz/helper"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	// Setup consistent logging
	handler := txfuzz.NewCompactHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	cl, sk := helper.GetRealBackend()
	backend := ethclient.NewClient(cl)
	sender := common.HexToAddress(txfuzz.ADDR)
	nonce, err := txfuzz.GetPendingNonce(context.Background(), backend, sender)
	if err != nil {
		panic(err)
	}
	chainid := txfuzz.GetChainID(backend)
	fmt.Printf("Nonce: %v\n", nonce)
	gp, _ := backend.SuggestGasPrice(context.Background())
	tx := types.NewContractCreation(nonce, common.Big1, 500000, gp, []byte{0x44, 0x44, 0x55})
	signedTx, _ := types.SignTx(tx, types.NewLondonSigner(chainid), sk)
	backend.SendTransaction(context.Background(), signedTx)
}
