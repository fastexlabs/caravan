// Code generated by rlpgen. DO NOT EDIT.

//go:build !norlpgen
// +build !norlpgen

package types

import "github.com/ethereum/go-ethereum/rlp"
import "io"

func (obj *Activity) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteBytes(obj.Address[:])
	w.WriteUint64(obj.DeltaActivity)
	w.ListEnd(_tmp0)
	return w.Flush()
}
