How to ship BPF with your Go project
===

This repository shows you how to use [bpf2go](https://github.com/cilium/ebpf) to embed pre-compiled eBPF in your Go project for easy distribution.

```
$ go get github.com/cilium/ebpf/cmd/bpf2go@v0.12.2

$ make clean && make
$ sudo ./ship-xdp-with-go
```

It's the basis of a lightning talk at the [2020 eBPF Summit](https://ebpf.io/summit-2020).

# ship-xdp-tc-with-go
