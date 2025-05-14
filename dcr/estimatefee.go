package dcr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/decred/dcrd/wire"
)

const (
	externalApiUrl        = "https://explorer.dcrdata.org/insight/api"
	testnetExternalApiUrl = "https://testnet.dcrdata.org/insight/api"
)

// FetchFeeFromOracle gets the fee rate from the external API.
func (w *Wallet) FetchFeeFromOracle(ctx context.Context, nBlocks uint64) (float64, error) {
	var url string
	if w.chainParams.Net == wire.TestNet3 {
		url = testnetExternalApiUrl
	} else { // mainnet and simnet
		url = externalApiUrl
	}
	url += "/utils/estimatefee?nbBlocks=" + strconv.FormatUint(nBlocks, 10)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	httpResponse, err := http.DefaultClient.Do(r)
	if err != nil {
		return 0, err
	}
	defer httpResponse.Body.Close()
	if httpResponse.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unable to get fee from %s: returned status %s", url, httpResponse.Status)
	}
	c := make(map[uint64]float64)
	reader := io.LimitReader(httpResponse.Body, 1<<14)
	err = json.NewDecoder(reader).Decode(&c)
	if err != nil {
		return 0, err
	}
	dcrPerKB, ok := c[nBlocks]
	if !ok {
		return 0, errors.New("no fee rate for requested number of blocks")
	}
	return dcrPerKB, nil
}
