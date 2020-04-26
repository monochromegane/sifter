package main

import (
	"flag"

	"github.com/monochromegane/sifter"
)

var (
	in string
	k  int
)

func init() {
	// pd.DataFrame(sum([[''.join(c) for c in list(itertools.combinations_with_replacement(list(string.ascii_letters), r))] for r in range(1,4)], [])).to_csv('in.txt', header=False, index=None)
	flag.StringVar(&in, "i", "in.txt", "usage of i")
	flag.IntVar(&k, "k", 3, "usage of k")
}

func main() {
	flag.Parse()
	err := sifter.PrepareHash(k, in)
	if err != nil {
		panic(err)
	}
}
