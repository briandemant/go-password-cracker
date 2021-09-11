package main

import (
	"fmt"
	"github.com/briandemant/go-password-cracker/cracker"
	"os"
)

func main() {
	argsWithoutProg := os.Args[1:]
	//fmt.Println(argsWithoutProg)
	password := cracker.FasterCrackSHA1Hash(argsWithoutProg[0])
	if password == "PASSWORD NOT IN DATABASE" {
		fmt.Println(password)
	} else {
		fmt.Println("password is: ", password)
	}
}
