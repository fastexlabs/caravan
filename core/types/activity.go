package types

import "github.com/ethereum/go-ethereum/common"

//go:generate go run ../../rlp/rlpgen -type Activity -out gen_activity_rlp.go

type Activity struct {
	Address       common.Address `json:"contract_address"`
	DeltaActivity uint64         `json:"delta_activity"`
}
