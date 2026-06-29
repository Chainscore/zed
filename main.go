package main

import (
	"fmt"

	"zed/utils"

	"github.com/holiman/uint256"
)

func main() {
	a, _ := utils.I2LEBSP(10, 8)
	b, _ := utils.I2LEBSPu256(*uint256.NewInt(10), 8)
	fmt.Println(a, b)
}
