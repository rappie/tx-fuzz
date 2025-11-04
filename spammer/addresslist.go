package spammer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func CreateAddresses(N int) ([]string, []string) {
	keys := make([]string, 0, N)
	addrs := make([]string, 0, N)

	k := CreateAddressesRaw(N)
	for _, sk := range k {
		addr := crypto.PubkeyToAddress(sk.PublicKey)
		skHex := "0x" + common.Bytes2Hex(crypto.FromECDSA(sk))
		// Sanity check marshalling
		skTest, err := crypto.ToECDSA(crypto.FromECDSA(sk))
		if err != nil {
			panic(err)
		}
		_ = skTest
		keys = append(keys, skHex)
		addrs = append(addrs, addr.Hex())
	}
	return keys, addrs
}

func CreateAddressesRaw(N int) []*ecdsa.PrivateKey {
	keys := make([]*ecdsa.PrivateKey, 0, N)

	for i := 0; i < N; i++ {
		// WARNING= USES UNSECURE RANDOMNESS
		sk, err := crypto.GenerateKey()
		if err != nil {
			panic(err)
		}
		keys = append(keys, sk)
	}
	return keys
}

// CreateKeys generates N private keys deterministically from a seed.
// Same seed always produces the same keys, enabling reproducible fuzzing.
func CreateKeys(N int, seed int64) []*ecdsa.PrivateKey {
	keys := make([]*ecdsa.PrivateKey, 0, N)
	rng := rand.New(rand.NewSource(seed))

	for i := 0; i < N; i++ {
		keyBytes := make([]byte, 32)
		rng.Read(keyBytes)

		sk, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate key %d: %v", i, err))
		}
		keys = append(keys, sk)
	}
	return keys
}

func Airdrop(config *Config, value *big.Int) error {
	backend := ethclient.NewClient(config.backend)
	sender := crypto.PubkeyToAddress(config.faucet.PublicKey)
	config.Logger.Info(fmt.Sprintf("Starting airdrop from faucet %s", sender))
	var tx *types.Transaction
	chainid := txfuzz.GetChainID(backend)
	for _, addr := range config.keys {
		nonce, err := txfuzz.GetPendingNonce(context.Background(), backend, sender)
		if err != nil {
			config.Logger.Error(fmt.Sprintf("Failed to get pending nonce for airdrop: %v", err))
			return err
		}
		to := crypto.PubkeyToAddress(addr.PublicKey)
		gp, err := backend.SuggestGasPrice(context.Background())
		if err != nil {
			config.Logger.Error(fmt.Sprintf("Failed to suggest gas price for airdrop: %v", err))
			return err
		}
		gas, _ := txfuzz.EstimateGas(backend, ethereum.CallMsg{
			From:     crypto.PubkeyToAddress(config.faucet.PublicKey),
			To:       &to,
			Gas:      30_000_000,
			GasPrice: gp,
			Value:    value,
		}, 30_000, config.GasMultiplier)
		tx2 := types.NewTransaction(nonce, to, value, gas, gp, nil)
		signedTx, _ := types.SignTx(tx2, types.LatestSignerForChainID(chainid), config.faucet)
		if err := txfuzz.SendTransaction(context.Background(), backend, signedTx, 0, 0); err != nil {
			return err
		}
		tx = signedTx
		time.Sleep(time.Duration(config.TxDelay) * time.Millisecond)
	}
	// Wait for the last transaction to be mined
	if _, err := bind.WaitMined(context.Background(), backend, tx); err != nil {
		return err
	}
	return nil
}
