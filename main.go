package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go xdpACL xdp_acl.c -- -I./include -nostdinc -O3

const (
	XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << 0

	XDP_FLAGS_AUTO_MODE = 0 // custom
	XDP_FLAGS_SKB_MODE  = 1 << 1
	XDP_FLAGS_DRV_MODE  = 1 << 2
	XDP_FLAGS_HW_MODE   = 1 << 3
	XDP_FLAGS_REPLACE   = 1 << 4

	XDP_FLAGS_MODES = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE
	XDP_FLAGS_MASK  = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE
)

func main() {

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		fmt.Println("WARNING: Failed to adjust rlimit")
	}

	var objs xdpACLObjects

	if err := loadXdpACLObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	link, err := netlink.LinkByName("enp5s0f1")
	if err != nil {
		panic(err)
	}

	/*-----attach to TC------*/

	info, _ := objs.TcSay.Info()

	fmt.Println("info.Name: ", info.Name)

	info2, _ := objs.XdpAclFunc.Info()

	fmt.Println("info2.Name: ", info2.Name)

	filterattrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS, // netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		fmt.Println("QdiscAdd err: ", err.Error())
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.TcSay.FD(),
		Name:         "hi-tc",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		fmt.Println("FilterAdd err: ", err)
		panic(err)
	}

	defer func() {

		err = netlink.FilterDel(filter)
		if err != nil {
			fmt.Println("FilterDel err : ", err.Error())
		}

		// filters, err = netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		// if err != nil {
		// 	panic(err)
		// }

		// fmt.Println("after del len(filters) = ", len(filters))

		if err := netlink.QdiscDel(qdisc); err != nil {
			fmt.Println("QdiscDel err: ", err.Error())
		}

		// fmt.Println("after del: len(qdiscs) == ", len(qdiscs))
	}()

	/*-----attach to xdp------*/

	err = netlink.LinkSetXdpFdWithFlags(link, objs.XdpAclFunc.FD(), XDP_FLAGS_AUTO_MODE)
	if err != nil {
		panic(err)
	}

	count := uint64(0)
	// key := uint64(1)
	if err := objs.FrameCount.Put(uint64(1), &count); err != nil {
		fmt.Println("key not exist")
	}

	go printFrameCount(&objs)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("XDP program successfully loaded and attached.")
	log.Println("Press CTRL+C to stop.")

	for range signalChan {
		close(signalChan)
		cleanUp(link)
	}

}

func cleanUp(link netlink.Link) {
	fmt.Println("----- cleanUp")
	netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlags((link).Type()))
}

func xdpFlags(linkType string) int {
	if linkType == "veth" || linkType == "tuntap" {
		return 2
	}
	return 0 // native xdp (xdpdrv) by default
}

func printFrameCount(objs *xdpACLObjects) {
	for range time.Tick(time.Second) {
		var count uint64
		if err := objs.FrameCount.Lookup(uint64(1), &count); err != nil {
			panic(err)
		}

		fmt.Println("Saw", count, "packets")
	}
}

// func openRawSock(index int) (int, error) {
// 	const ETH_P_ALL uint16 = 0x300
// 	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(ETH_P_ALL))
// 	if err != nil {
// 		return 0, err
// 	}
// 	sll := syscall.SockaddrLinklayer{}
// 	sll.Protocol = ETH_P_ALL
// 	sll.Ifindex = index
// 	if err := syscall.Bind(sock, &sll); err != nil {
// 		return 0, err
// 	}
// 	return sock, nil
// }

// func SafeQdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
// 	qdiscs, err := netlink.QdiscList(link)
// 	if err != nil {
// 		return nil, err
// 	}
// 	result := []netlink.Qdisc{}
// 	for _, qdisc := range qdiscs {
// 		// filter out pfifo_fast qdiscs because
// 		// older kernels don't return them
// 		_, pfifo := qdisc.(*netlink.PfifoFast)
// 		if !pfifo {
// 			result = append(result, qdisc)
// 		}
// 	}
// 	return result, nil
// }
