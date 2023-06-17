package main

import (
	"errors"
	"fmt"
	"gotss/example/test"
	"sync"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	fmt.Println("running key gen for ", id)
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPRefresh(c *cmp.Config, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, hRefresh, n)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}

	signature := signResult.(*ecdsa.Signature)
	sigEth, err := signature.SigEthereum()
	fmt.Println("eth sig from ", c.ID, " is ", hexutil.Encode(sigEth))
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}

	// Recover the public key from the signature
	sigPublicKey, err := crypto.Ecrecover(m, sigEth)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("public key from sig is", hexutil.Encode(sigPublicKey))

	return nil
}

func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// CMP KEYGEN
	fmt.Println("cmp keygen")
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}

	// CMP REFRESH
	//fmt.Println("cmp refresh")
	//refreshConfig, err := CMPRefresh(keygenConfig, n, pl)
	//if err != nil {
	//	return err
	//}

	//fmt.Printf("%+v\n", keygenConfig)

	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	// CMP SIGN
	fmt.Println("cmp sign")
	err = CMPSign(keygenConfig, message, signers, n, pl)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	//ids := party.IDSlice{"a", "b", "c", "d", "e", "f"}
	ids := party.IDSlice{"a", "b", "c"}
	threshold := 2
	messageToSign := []byte("hello")
	hash := crypto.Keccak256Hash(messageToSign)

	net := test.NewNetwork(ids)

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(0)
			defer pl.TearDown()
			if err := All(id, ids, threshold, hash.Bytes(), net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
