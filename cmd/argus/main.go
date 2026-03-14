package main

import (
	"argus/internal/cli"
	"fmt"
	"os"
)

var version = "dev"

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Println(version)
			return
		}
	}

	os.Exit(cli.Execute(os.Args))
}
