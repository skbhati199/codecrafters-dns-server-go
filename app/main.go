package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strings"
)

const hdrSize = 12
const (
	qroffset   int  = 7
	qrMask     byte = 1 << qroffset
	rdoffset   int  = 0
	rdMask     byte = 1 << rdoffset
	opcodeMask byte = ((1 << 4) - 1) << 3
	rcodeMask  byte = (1 << 4) - 1
)

type DNSHeader struct {
	id      uint16
	flags   DNSFlag
	qdcount uint16
	ancount uint16
	nscount uint16
	arcount uint16
}
type DNSFlag [2]byte

func NewDNSFlag() DNSFlag {
	return [2]byte{}
}
func (f *DNSFlag) SetQR(v int) {
	if v != 0 {
		v = 1
	}
	f[0] = (f[0] & ^qrMask) | (byte(v) * qrMask)
}
func (f *DNSFlag) Opcode() uint8 {
	return f[0] & opcodeMask >> 3
}
func (f *DNSFlag) SetOpcode(code uint8) {
	code = code & 15
	f[0] = (f[0] & ^opcodeMask) | (code << 3)
}
func (f *DNSFlag) RD() int {
	v := f[0] & rdMask
	if v != 0 {
		return 1
	}
	return 0
}
func (f *DNSFlag) SetRD(v int) {
	if v != 0 {
		v = 1
	}
	f[0] = (f[0] & ^rdMask) | (byte(v) * rdMask)
}
func (f *DNSFlag) SetRCode(code uint8) {
	code = code & 15
	f[1] = (f[1] & ^rcodeMask) | byte(code)
}
func NewDNSHeader(data []byte) *DNSHeader {
	hdr := &DNSHeader{
		id:      toUint16(data[0:2]),
		qdcount: toUint16(data[4:6]),
		ancount: toUint16(data[6:8]),
		nscount: toUint16(data[8:12]),
		arcount: toUint16(data[10:12]),
	}
	copy(hdr.flags[:], data[2:4])
	return hdr
}

type DNSQuestion struct {
	labels []string
	typ    uint16
	class  uint16
}

func NewDNSQuestion(start int, data []byte) (*DNSQuestion, int) {
	i := start
	labels := []string{}
	pointerEnd := -1
	for {
		l := int(data[i])
		i++
		if l == 0 {
			if pointerEnd == -1 {
				return &DNSQuestion{
					labels: labels,
					typ:    toUint16(data[i : i+2]),
					class:  toUint16(data[i+2 : i+4]),
				}, i + 4
			} else {
				return &DNSQuestion{
					labels: labels,
					typ:    toUint16(data[pointerEnd : pointerEnd+2]),
					class:  toUint16(data[pointerEnd+2 : pointerEnd+4]),
				}, pointerEnd + 4
			}
		}
		if (l >> 6) == 3 {
			pointerEnd = i + 1
			i = (l & ((1 << 6) - 1) << 8) | int(data[i])
			continue
		}
		labels = append(labels, string(data[i:i+l]))
		i = i + l
	}
}
func (q *DNSQuestion) AsBytes() []byte {
	var bs []byte
	for _, l := range q.labels {
		bs = append(bs, byte(len(l)))
		bs = append(bs, []byte(l)...)
	}
	bs = append(bs, byte(0))
	bs = append(bs, fromUint16(q.typ)...)
	bs = append(bs, fromUint16(q.class)...)
	return bs
}

type ResourceRecord struct {
	name  []string
	typ   uint16
	class uint16
	ttl   uint32
	rdlen uint16
	rdata []byte
}

func (r *ResourceRecord) AsBytes() []byte {
	var bs []byte
	for _, l := range r.name {
		bs = append(bs, byte(len(l)))
		bs = append(bs, []byte(l)...)
	}
	bs = append(bs, byte(0))
	bs = append(bs, fromUint16(r.typ)...)
	bs = append(bs, fromUint16(r.class)...)
	bs = append(bs, fromUint32(r.ttl)...)
	bs = append(bs, fromUint16(r.rdlen)...)
	bs = append(bs, r.rdata...)
	return bs
}

type DNSMessage struct {
	hdr *DNSHeader
	qs  []*DNSQuestion
	rrs []*ResourceRecord
}

func toUint16(bs []byte) uint16 {
	return uint16(bs[0])<<8 | uint16(bs[1])
}
func fromUint16(n uint16) []byte {
	return []byte{byte(n >> 8), byte(n & 255)}
}
func fromUint32(n uint32) []byte {
	return []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n & 255)}
}
func NewDNSMessage(data []byte) (*DNSMessage, error) {
	if len(data) < hdrSize {
		return nil, fmt.Errorf("message is too short")
	}
	hdr := NewDNSHeader(data)
	qoffset := hdrSize
	qs := make([]*DNSQuestion, hdr.qdcount)
	for i := 0; i < int(hdr.qdcount); i++ {
		qs[i], qoffset = NewDNSQuestion(qoffset, data)
	}
	return &DNSMessage{
		hdr: hdr,
		qs:  qs,
	}, nil
}
func (m *DNSMessage) AsBytes() []byte {
	b := make([]byte, hdrSize)
	copy(b[0:2], fromUint16(m.hdr.id))
	copy(b[2:4], m.hdr.flags[:])
	copy(b[4:6], fromUint16(m.hdr.qdcount))
	copy(b[6:8], fromUint16(m.hdr.ancount))
	copy(b[8:10], fromUint16(m.hdr.nscount))
	copy(b[10:12], fromUint16(m.hdr.arcount))
	for _, q := range m.qs {
		b = append(b, q.AsBytes()...)
	}
	for _, r := range m.rrs {
		b = append(b, r.AsBytes()...)
	}
	return b
}
func handle(resolver *net.Resolver, req *DNSMessage) (*DNSMessage, error) {
	fmt.Printf("%08b", req.hdr.flags[0])
	fmt.Printf("%08b", req.hdr.flags[1])
	flag := NewDNSFlag()
	flag.SetQR(1)
	flag.SetOpcode(req.hdr.flags.Opcode())
	fmt.Println(req.hdr.flags.RD())
	flag.SetRD(req.hdr.flags.RD())
	if req.hdr.flags.Opcode() != 0 {
		flag.SetRCode(4)
	}
	fmt.Printf("%08b", flag[0])
	fmt.Printf("%08b", flag[1])

	var rrs []*ResourceRecord
	for _, q := range req.qs {
		if resolver == nil {
			rrs = append(rrs, &ResourceRecord{
				name:  q.labels,
				typ:   1,
				class: 1,
				ttl:   60,
				rdlen: 4,
				rdata: []byte{byte(8), byte(8), byte(8), byte(8)},
			})
			continue
		}
		ips, err := resolver.LookupIPAddr(context.Background(), strings.Join(q.labels, "."))
		if err != nil {
			return nil, fmt.Errorf("fail to lookup: %w", err)
		}
		for _, ip := range ips {
			rrs = append(rrs, &ResourceRecord{
				name:  q.labels,
				typ:   1,
				class: 1,
				ttl:   60,
				rdlen: 4,
				rdata: []byte(ip.IP),
			})
		}
	}
	m := &DNSMessage{
		hdr: &DNSHeader{
			id:      req.hdr.id,
			flags:   flag,
			qdcount: uint16(len(req.qs)),
			ancount: uint16(len(rrs)),
			nscount: 0,
			arcount: 0,
		},
		qs:  req.qs,
		rrs: rrs,
	}
	return m, nil
}
func main() {
	ns := flag.String("resolver", "", "Resolver address")
	flag.Parse()
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()
	var resolver *net.Resolver
	if len(*ns) != 0 {
		resolver = newResolver(*ns)
	}
	buf := make([]byte, 512)
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		msg, err := NewDNSMessage(buf[:size])
		if err != nil {
			fmt.Println("Error parsing incoming message:", err)
			break
		}
		response, err := handle(resolver, msg)
		if err != nil {
			fmt.Printf("Fail to handle request: %v", err)
			break
		}
		_, err = udpConn.WriteToUDP(response.AsBytes(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
			break
		}
	}
}
