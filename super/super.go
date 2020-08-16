package super

import (
	"fmt"
	"github.com/ethereum/go-ethereum/eth"
)

type SuperAPI struct{
	e *eth.Ethereum
}

func (s *SuperAPI) SayHi() string {
	fmt.Println("Hello world!")
	return "Hello world!"
}

func (s *SuperAPI) BroadcastInfo(num string) {
	s.e.ProtocolManager().BroadcastInfo(num)
}

func (s *SuperAPI) ModifyBlock(txHash string) string {
	bc := s.e.BlockChain()
	bc.Modify(txHash)
	s.BroadcastInfo(txHash)
	return "Success!"
}

func NewMyAPI(ethereum *eth.Ethereum) *SuperAPI {
	return &SuperAPI{ethereum}
}
