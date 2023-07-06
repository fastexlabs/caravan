package vm

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// StatefulPrecompiledContract is the basic interface for native Go contracts with EVM state access.
// The implimentation requires a deterministic gas count.
type StatefulPrecompiledContract interface {
	Run(evm *EVM, caller ContractRef, addr common.Address, input []byte, gas uint64, readOnly bool) (ret []byte, leftOverGas uint64, err error)
}

// RunStatefulPrecompiledContract runs stateful precompiled contract.
func RunStatefulPrecompiledContract(p StatefulPrecompiledContract, evm *EVM, caller ContractRef, addr common.Address, input []byte, gas uint64, readOnly bool) (ret []byte, leftOverGas uint64, err error) {
	return p.Run(evm, caller, addr, input, gas, readOnly)
}

var deployerAddress common.Address = common.HexToAddress("0x1000000000000000000000000000000000000002")

// deployer returns the deployer of given smart contract.
type deployer struct{}

func (d *deployer) Run(evm *EVM, caller ContractRef, addr common.Address, input []byte, gas uint64, readOnly bool) (ret []byte, leftOverGas uint64, err error) {
	gasCost := d.RequiredGas()
	if gas < gasCost {
		return nil, gas, ErrOutOfGas
	}
	deployer := evm.StateDB.GetDeployer(common.BytesToAddress(input))
	return deployer.Bytes(), gas - gasCost, nil
}

func (d *deployer) RequiredGas() uint64 {
	return GasQuickStep
}

// WrappedPrecompiledContract is the custom wrapper for known precompiled contracts
// that implements StatefulPrecompiledContract interface.
type WrappedPrecompiledContract struct {
	p PrecompiledContract
}

func (wp *WrappedPrecompiledContract) Run(evm *EVM, caller ContractRef, addr common.Address, input []byte, gas uint64, readOnly bool) (ret []byte, leftOverGas uint64, err error) {
	return RunPrecompiledContract(wp.p, input, gas)
}

func WrapPrecompiledContract(p PrecompiledContract) StatefulPrecompiledContract {
	return &WrappedPrecompiledContract{
		p: p,
	}
}

const selectorLen = 4

type Selector [selectorLen]byte

var functionSignatureRegex = regexp.MustCompile(`[\w]+\(((([\w]+)?)|((([\w]+),)+([\w]+)))\)`)

type statefulPrecompiledFunction func(evm *EVM, caller ContractRef, addr common.Address, input []byte, gas uint64, readOnly bool) (ret []byte, leftOverGas uint64, err error)

type statefulPrecompiledContractWithSelectors struct {
	fallback  statefulPrecompiledFunction
	functions map[Selector]statefulPrecompiledFunction
}

func (sc *statefulPrecompiledContractWithSelectors) Run(evm *EVM, caller ContractRef, addr common.Address, input []byte, gas uint64, readOnly bool) (ret []byte, leftOverGas uint64, err error) {
	if len(input) == 0 && sc.fallback != nil {
		return sc.fallback(evm, caller, addr, nil, gas, readOnly)
	}
	if len(input) < selectorLen {
		return nil, gas, errors.New("missing function selector of precompiled contract")
	}

	var selector Selector
	functionInput := make([]byte, len(input)-selectorLen)
	copy(selector[:], input[:selectorLen])
	copy(functionInput, input[selectorLen:])

	function, ok := sc.functions[selector]
	if !ok {
		return nil, gas, fmt.Errorf("invalid function selector %#x", selector)
	}

	return function(evm, caller, addr, functionInput, gas, readOnly)
}

func NewStatefulPrecompiledFunctionWithSelectors(fallback statefulPrecompiledFunction, fns map[string]statefulPrecompiledFunction) StatefulPrecompiledContract {
	functions := make(map[Selector]statefulPrecompiledFunction, len(fns))
	for signature, function := range fns {
		if !functionSignatureRegex.MatchString(signature) {
			panic(fmt.Errorf("invalid function signature: %s", signature))
		}
		hash := crypto.Keccak256([]byte(signature))
		var selector Selector
		copy(selector[:], hash[:4])
		functions[selector] = function
	}
	return &statefulPrecompiledContractWithSelectors{
		fallback:  fallback,
		functions: functions,
	}
}
