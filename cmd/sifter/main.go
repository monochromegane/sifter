package main

import (
	"flag"
	"fmt"

	"github.com/monochromegane/sifter"
)

var (
	k     int
	m     int
	base  string
	cache string
	n     bool
)

func init() {
	flag.IntVar(&k, "k", 3, "usage of k")
	flag.IntVar(&m, "m", 500, "usage of m")
	flag.StringVar(&base, "b", "hoge", "usage of b")
	flag.StringVar(&cache, "c", "cache", "usage of c")
	flag.BoolVar(&n, "n", false, "usage of n")
}

func main() {
	flag.Parse()
	sift := sifter.NewSifter(k, m)

	args := flag.Args()
	if args[0] == "build" {
		err := sift.CreateCacheNew(base, cache)
		if err != nil {
			panic(err)
		}
	}
	if args[0] == "find" {
		pattern := args[1]
		candidates, err := sift.Select(pattern, cache)
		if err != nil {
			panic(err)
		}
		for i, _ := range candidates {
			fmt.Printf("%s", candidates[i])
			if n {
				fmt.Printf("\n")
			} else {
				fmt.Printf(" ")
			}
		}
		if !n {
			fmt.Println()
		}
	}
}
