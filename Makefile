
PROJECT = ship-xdp-with-go

.PHONY: clean $(PROJECT)


all: xdp_acl.c main.go
	@go generate && go build

clean:
	@rm -rf *.o *_bpfeb.go *_bpfel.go $(PROJECT)
