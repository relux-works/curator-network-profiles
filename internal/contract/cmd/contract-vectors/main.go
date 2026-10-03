// SPDX-License-Identifier: Apache-2.0

// Command contract-vectors regenerates testdata/contract/vectors.json
// and prints the appendix blocks (-markdown) from internal/contract.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/relux-works/curator-network-profiles/internal/atomicfile"
	"github.com/relux-works/curator-network-profiles/internal/contract"
)

func main() {
	fs := flag.NewFlagSet("contract-vectors", flag.ContinueOnError)
	write := fs.String("write", "", "write the vectors file to this path")
	markdown := fs.Bool("markdown", false, "print the appendix blocks on stdout")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	set, err := contract.Vectors()
	if err != nil {
		fmt.Fprintln(os.Stderr, "contract-vectors:", err)
		os.Exit(1)
	}
	if *write != "" {
		data, err := set.JSON()
		if err == nil {
			err = atomicfile.Write(*write, data)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "contract-vectors:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "wrote", *write)
	}
	if *markdown {
		md, err := set.Markdown()
		if err != nil {
			fmt.Fprintln(os.Stderr, "contract-vectors:", err)
			os.Exit(1)
		}
		fmt.Print(md)
	}
}
