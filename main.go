package main

import (
	"fmt"

	"zed/utils"

	"github.com/holiman/uint256"
)

func main() {
	// b, _ := utils.I2BEBSP(10, 8)
	// b_256, _ := utils.I2BEBSPu256(*uint256.NewInt(10), 8)
	val := uint256.Int{
		^uint64(0),
		^uint64(0),
		^uint64(0),
		^uint64(0),
	}
	l, _ := utils.I2LEBSPu256(val, 256)
	fmt.Println("le", l)
	i, _ := utils.LEBS2IP(l)
	iu256, _ := utils.LEBS2IPu256(l)
	fmt.Println("i:", i)
	fmt.Println("iu256:", iu256)
}
