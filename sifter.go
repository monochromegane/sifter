package sifter

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sync/errgroup"
)

type Sifter struct {
	k      int
	length int
}

func NewSifter(k, length int) *Sifter {
	return &Sifter{
		k:      k,
		length: length,
	}
}

type pathHashs struct {
	path string
	set  map[int64]struct{}
}

func (s *Sifter) CreateCacheNew(baseDir, cacheDir string) error {
	tmpDir, err := ioutil.TempDir("", "sifter")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	pathHashsCh := make(chan pathHashs, 5000)
	paths := []string{}
	done := make(chan bool)
	go func() {
		sem := make(chan struct{}, 20)
		wg := new(sync.WaitGroup)
		cnt := 0
		for ph := range pathHashsCh {
			paths = append(paths, ph.path)
			// s.saveFilter(filepath.Join(tmpDir, fmt.Sprintf("%d.bin", cnt)), ph.set)

			set := map[int64]struct{}{}
			for k, _ := range ph.set {
				set[k] = struct{}{}
			}
			sem <- struct{}{}
			fmt.Printf("[%d]: %s (%d)\n", cnt, ph.path, len(ph.set))
			wg.Add(1)
			go func(dir string, set map[int64]struct{}) {
				s.saveFilter(dir, set)
				<-sem
				wg.Done()
			}(filepath.Join(tmpDir, fmt.Sprintf("%d.bin", cnt)), set)
			cnt++
		}
		wg.Wait()
		done <- true
	}()

	eg := &errgroup.Group{}
	eg.Go(func() error {
		return s.walk(baseDir, pathHashsCh)
	})
	if err := eg.Wait(); err != nil {
		return err
	}
	close(pathHashsCh)
	<-done

	err = s.savePaths(cacheDir, paths)
	if err != nil {
		return err
	}

	filters := make([][]byte, len(paths))
	for i := 0; i < len(paths); i++ {
		bytes, err := ioutil.ReadFile(filepath.Join(tmpDir, fmt.Sprintf("%d.bin", i)))
		if err != nil {
			return err
		}
		filters[i] = bytes
	}
	return s.inverteFilter(cacheDir, filters)
}

func (s *Sifter) inverteFilter(cacheDir string, filters [][]byte) error {
	for i := 0; i < s.length; i++ {
		file, err := os.Create(filepath.Join(cacheDir, fmt.Sprintf("hash_%05d.bin", i)))
		if err != nil {
			return err
		}

		byteIdx := i / 8
		bitIdx := i % 8
		flags := make([]bool, len(filters))
		for j, _ := range filters {
			flag := readBitAt(bitIdx, filters[j][byteIdx])
			flags[j] = flag
		}

		bs := toBytes(flags)
		_, err = file.Write(bs)
		if err != nil {
			return err
		}
		file.Close()
	}
	return nil
}

func (s *Sifter) saveFilter(out string, set map[int64]struct{}) error {
	file, err := os.Create(out)
	if err != nil {
		return err
	}
	defer file.Close()

	byteLength := (s.length / 8) + 1
	bs := make([]byte, byteLength)
	for i := 0; i < byteLength; i++ {
		v := make([]bool, 8)
		s := i * 8
		e := s + 8
		vi := 0
		for j := s; j < e; j++ {
			_, ok := set[int64(j)]
			v[vi] = ok
			vi += 1
		}
		b := toByte(v)
		bs[i] = b
	}
	_, err = file.Write(bs)
	return err
}

func (s *Sifter) Select(pattern, cacheDir string) ([]string, error) {
	paths, err := s.loadPath(cacheDir)
	if err != nil {
		return nil, err
	}

	patterns := ngram(pattern)
	hashSet := map[int64]struct{}{}
	for i, _ := range patterns {
		hashs := hash(s.k, s.length, patterns[i])
		// hashs := hashUsingPrepared(s.k, s.length, patterns[i])
		for j, _ := range hashs {
			hashSet[hashs[j]] = struct{}{}
		}
	}

	candidates, err := s.findCandidates(hashSet, cacheDir)
	if err != nil {
		return nil, err
	}

	candidatePaths := make([]string, len(candidates))
	cnt := 0
	for k := range candidates {
		candidatePaths[cnt] = paths[k]
		cnt++
	}
	return candidatePaths, nil
}

func (s *Sifter) loadPath(cacheDir string) ([]string, error) {
	file, err := os.Open(filepath.Join(cacheDir, "path.txt"))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	paths := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		paths = append(paths, scanner.Text())
	}
	return paths, nil
}

func (s *Sifter) findCandidates(hashSet map[int64]struct{}, cacheDir string) (map[int]struct{}, error) {
	first := true
	candidates := map[int]struct{}{}
	for hash, _ := range hashSet {
		bytes, err := ioutil.ReadFile(filepath.Join(cacheDir, fmt.Sprintf("hash_%05d.bin", hash)))
		if err != nil {
			return nil, err
		}

		if first {
			for i, _ := range bytes {
				for j := 0; j < 8; j++ {
					flag := readBitAt(j, bytes[i])
					if flag {
						candidates[(i*8)+j] = struct{}{}
					}
				}
			}
			first = false
		} else {
			if len(candidates) == 0 {
				break
			}

			keys := make([]int, len(candidates))
			cnt := 0
			for k := range candidates {
				keys[cnt] = k
				cnt++
			}
			for i, _ := range keys {
				candidate := keys[i]
				bytesIdx := candidate / 8
				bitIdx := candidate % 8
				flag := readBitAt(bitIdx, bytes[bytesIdx])
				if !flag {
					delete(candidates, keys[i])
				}
			}
		}
	}

	return candidates, nil
}

func (s *Sifter) walk(base string, ch chan pathHashs) error {
	return concurrentWalk(base, func(info fileInfo) error {
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		path := info.path

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		// defer file.Close()

		set := map[int64]struct{}{}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			text := scanner.Text()
			for i, _ := range text {
				hs := hash(s.k, s.length, string(text[i]))
				// hs := hashUsingPrepared(s.k, s.length, string(text[i]))
				for _, h := range hs {
					set[h] = struct{}{}
				}
				if i >= 1 {
					hs2 := hash(s.k, s.length, string(text[i-1:i+1]))
					// hs2 := hashUsingPrepared(s.k, s.length, string(text[i-1:i+1]))
					for _, h := range hs2 {
						set[h] = struct{}{}
					}
				}
				if i >= 2 {
					hs3 := hash(s.k, s.length, string(text[i-2:i+1]))
					// hs3 := hashUsingPrepared(s.k, s.length, string(text[i-2:i+1]))
					for _, h := range hs3 {
						set[h] = struct{}{}
					}
				}
			}
		}
		file.Close()
		ch <- pathHashs{
			path: path,
			set:  set,
		}
		return nil
	})
}

func (s *Sifter) savePaths(cacheDir string, paths []string) error {
	file, err := os.Create(filepath.Join(cacheDir, "path.txt"))
	if err != nil {
		return err
	}
	defer file.Close()
	for i, _ := range paths {
		file.WriteString(fmt.Sprintln(paths[i]))
	}
	return nil
}

func PrepareHash(k int, in string) error {
	file, err := os.Open(in)
	if err != nil {
		return err
	}
	defer file.Close()

	prepareHash := map[string][]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := scanner.Text()

		hash := calcMD5Hash(s)
		hashA := hash[:int(len(hash)/2)]
		hashB := hash[int(len(hash)/2):]

		i64HashA, _ := strconv.ParseUint(hashA, 16, 64)
		i64HashB, _ := strconv.ParseUint(hashB, 16, 64)

		hashs := make([]string, k)
		for i := 0; i < k; i++ {
			hashs[i] = doubleHashingForPrepare(i64HashA, i64HashB, i)
		}
		prepareHash[s] = hashs
	}

	out, err := os.Create("prepared_hash.go")
	if err != nil {
		return err
	}
	defer out.Close()

	fmt.Fprintf(out, `// AUTO-GENERATED BY sifter

package sifter

var preparedHash = %#v

`, prepareHash)

	return nil
}

func hashUsingPrepared(k, l int, s string) []int64 {
	if prepare, ok := preparedHash[s]; ok {
		if len(prepare) >= k {
			hashs := make([]int64, k)
			for i := 0; i < k; i++ {
				hashs[i] = doubleHashingUsingPrepare(prepare[i], l)
			}
			return hashs
		}
	}
	return hash(k, l, s)
}

func hash(k, l int, s string) []int64 {
	hash := calcMD5Hash(s)
	hashA := hash[:int(len(hash)/2)]
	hashB := hash[int(len(hash)/2):]

	i64HashA, _ := strconv.ParseUint(hashA, 16, 64)
	i64HashB, _ := strconv.ParseUint(hashB, 16, 64)
	hashs := make([]int64, k)

	for i := 0; i < k; i++ {
		hashs[i] = doubleHashing(i64HashA, i64HashB, i, l)
	}
	return hashs
}

// Refs:
// - Kirsch, Adam, and Michael Mitzenmacher. "Less hashing, same performance: building a better bloom filter." European Symposium on Algorithms. Springer, Berlin, Heidelberg, 2006.
// - (Implementation of Go) https://cipepser.hatenablog.com/entry/2017/02/04/090629
func calcMD5Hash(str string) string {
	hasher := md5.New()
	hasher.Write([]byte(str))

	return hex.EncodeToString(hasher.Sum(nil))
}

func doubleHashingForPrepare(hashA, hashB uint64, n int) string {
	var bigHashA big.Int
	bigHashA.SetUint64(hashA)
	var bigHashB big.Int
	bigHashB.SetUint64(hashB)

	h := new(big.Int).Mul(big.NewInt(int64(n)), &bigHashB)
	h = new(big.Int).Add(&bigHashA, h)
	return h.String()
}

func doubleHashingUsingPrepare(prepare string, length int) int64 {
	var bigHash big.Int
	bigHash.SetString(prepare, 10)

	h := new(big.Int).Rem(&bigHash, big.NewInt(int64(length)))
	hash := h.Int64()
	if hash < 0 {
		hash += int64(length)
	}
	return hash
}

func doubleHashing(hashA, hashB uint64, n, length int) int64 {
	var bigHashA big.Int
	bigHashA.SetUint64(hashA)
	var bigHashB big.Int
	bigHashB.SetUint64(hashB)

	h := new(big.Int).Mul(big.NewInt(int64(n)), &bigHashB)
	h = new(big.Int).Add(&bigHashA, h)
	h = new(big.Int).Rem(h, big.NewInt(int64(length)))

	hash := h.Int64()
	if hash < 0 {
		hash += int64(length)
	}
	return hash
}

func ngram(pattern string) []string {
	if len(pattern) <= 2 {
		return []string{pattern}
	}
	grams := make([]string, len(pattern)-2)
	for i, _ := range pattern {
		if i >= 2 {
			grams[i-2] = pattern[i-2 : i+1]
		}
	}
	return grams
}
