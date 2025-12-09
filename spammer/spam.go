package spammer

import (
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"sync"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
)

type Spam func(*Config, *ecdsa.PrivateKey) error

func SpamTransactions(config *Config, fun Spam) error {
	config.Logger.Info(fmt.Sprintf("Starting transaction spam: %d tx/account, %d accounts, seed=0x%x",
		config.N, len(config.keys), config.seed))

	errCh := make(chan error, len(config.keys))
	var wg sync.WaitGroup
	wg.Add(len(config.keys))
	for _, key := range config.keys {
		// Start a fuzzing thread
		go func(key *ecdsa.PrivateKey) {
			defer wg.Done()
			errCh <- fun(config, key)
		}(key)
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// CreateFiller creates a new filler from corpus or random data.
// Should be called per-transaction to get fresh mutations.
func CreateFiller(config *Config) *filler.Filler {
	if len(config.corpus) != 0 {
		elemIndex := rand.Int31n(int32(len(config.corpus)))
		// Copy corpus element to avoid mutating the original
		elem := make([]byte, len(config.corpus[elemIndex]))
		copy(elem, config.corpus[elemIndex])
		config.mut.MutateBytes(&elem)
		return filler.NewFiller(elem)
	}
	// Use random data
	random := make([]byte, 10000)
	config.mut.FillBytes(&random)
	config.mut.MutateBytes(&random)
	return filler.NewFiller(random)
}
