//go:build gofuzz
// +build gofuzz

package fuzz

import "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"

func FuzzNode(data []byte) int {
	n, err := node.UnmarshalBinary(data)
	if err != nil {
		return 0
	}

	_, err = n.CompactMarshalBinary()
	if err != nil {
		panic(err)
	}
	return 1
}
