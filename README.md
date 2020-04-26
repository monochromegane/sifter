# Sifter

[WIP] A lightweight index for full text search tools using bloom filter.

## Usage

Build index (Currently, it's too slow)

```sh
$ sifter -m 1000 -k 3 build
```

Find candidates using index

```sh
$ sifter -m 1000 -k 3 find PATTERN
```

Try full text search using your favorite tool with sifter

```sh
pt PATTERN `sifter -m 1000 -k 3 find PATTERN`
```
