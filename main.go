package main

import (
	"os"

	"github.com/torkve/bidichan/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
