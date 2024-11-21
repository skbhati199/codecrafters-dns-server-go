package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}

type DNSRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type DNSFlags struct {
	QR     uint16 // Query (0) / Response (1)
	Opcode uint16 // 4-bit opcode
	AA     uint16 // Authoritative Answer flag
	TC     uint16 // Truncation flag
	RD     uint16 // Recursion Desired flag
	RA     uint16 // Recursion Available flag
	Z      uint16 // Reserved for future use (3 bits)
	RCODE  uint16 // Response code (4 bits)
}

func EncodeDNSFlags(flags DNSFlags) uint16 {
	var encoded uint16

	encoded |= flags.QR << 15     // QR (Query/Response) bit is the most significant bit
	encoded |= flags.Opcode << 11 // Opcode takes bits 11-14
	encoded |= flags.AA << 10     // AA (Authoritative Answer)
	encoded |= flags.TC << 9      // TC (Truncated)
	encoded |= flags.RD << 8      // RD (Recursion Desired)
	encoded |= flags.RA << 7      // RA (Recursion Available)
	encoded |= flags.Z << 4       // Z (Reserved bits)
	encoded |= flags.RCODE & 0x0F // RCODE (Response code) takes bits 0-3

	return encoded
}

func DecodeDNSFlags(flags uint16) DNSFlags {
	var decoded DNSFlags

	decoded.QR = flags >> 15              // QR (Query/Response) bit is the most significant bit
	decoded.Opcode = (flags >> 11) & 0x0F // Opcode is bits 11-14
	decoded.AA = (flags >> 10) & 0x01     // AA (Authoritative Answer)
	decoded.TC = (flags >> 9) & 0x01      // TC (Truncated)
	decoded.RD = (flags >> 8) & 0x01      // RD (Recursion Desired)
	decoded.RA = (flags >> 7) & 0x01      // RA (Recursion Available)
	decoded.Z = (flags >> 4) & 0x07       // Z (Reserved bits)
	decoded.RCODE = flags & 0x0F          // RCODE (Response code) is bits 0-3

	return decoded
}
func PrintMessage(message []byte) {

	header, questions, answers, err := ParseDNSMessage(message)
	if err != nil {
		log.Fatalf("Error parsing DNS message: %v", err)
	}

	// Print parsed data
	fmt.Printf("DNS Header:\n")
	fmt.Printf("  ID: %d\n", header.ID)
	fmt.Printf("  Flags: %d\n", header.Flags)
	fmt.Printf("  QDCount: %d\n", header.QDCount)
	fmt.Printf("  ANCount: %d\n", header.ANCount)
	fmt.Printf("  NSCount: %d\n", header.NSCount)
	fmt.Printf("  ARCount: %d\n", header.ARCount)

	fmt.Printf("\nDNS Questions:\n")
	for _, q := range questions {
		fmt.Printf("  QName: %s\n", q.QName)
		fmt.Printf("  QType: %d\n", q.QType)
		fmt.Printf("  QClass: %d\n", q.QClass)
	}

	fmt.Printf("\nDNS Answers:\n")
	for _, a := range answers {
		fmt.Printf("  Name: %s\n", a.Name)
		fmt.Printf("  Type: %d\n", a.Type)
		fmt.Printf("  Class: %d\n", a.Class)
		fmt.Printf("  TTL: %d\n", a.TTL)
		fmt.Printf("  RDLength: %d\n", a.RDLength)
		fmt.Printf("  RData: %v\n", a.RData)
	}

	fmt.Println("End of the DNS message")
}
func IPAddressStringToBytes(ipStr string) ([]byte, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address format: %s", ipStr)
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}

	return ip, nil
}

// ParseDNSMessage parses a DNS message byte slice into structured DNS components
// func ParseDNSMessage(message []byte) (header DNSHeader, questions []DNSQuestion, answers []DNSRecord, authorities []DNSRecord, additionals []DNSRecord, err error) {
func ParseDNSMessage(message []byte) (header DNSHeader, questions []DNSQuestion, answers []DNSRecord, err error) {
	// Parse DNS header
	header.ID = binary.BigEndian.Uint16(message[0:2])
	header.Flags = binary.BigEndian.Uint16(message[2:4])
	header.QDCount = binary.BigEndian.Uint16(message[4:6])
	header.ANCount = binary.BigEndian.Uint16(message[6:8])
	header.NSCount = binary.BigEndian.Uint16(message[8:10])
	header.ARCount = binary.BigEndian.Uint16(message[10:12])

	offset := 12

	for i := 0; i < int(header.QDCount); i++ {
		qname, qnameLen := ParseDomainName(message, offset)
		offset += qnameLen

		qtype := binary.BigEndian.Uint16(message[offset : offset+2])
		offset += 2

		qclass := binary.BigEndian.Uint16(message[offset : offset+2])
		offset += 2

		question := DNSQuestion{
			QName:  qname,
			QType:  qtype,
			QClass: qclass,
		}

		questions = append(questions, question)
	}
	// log.Println("So far so good")
	// Parse answers, authorities, and additionals (similar structure)
	answers, offset = ParseDNSRecords(message, offset, int(header.ANCount))
	// authorities, offset = parseDNSRecords(message, offset, int(header.NSCount))
	// additionals, offset = parseDNSRecords(message, offset, int(header.ARCount))

	return header, questions, answers, nil
}

func ParseDNSRecords(message []byte, offset int, count int) (records []DNSRecord, newOffset int) {
	for i := 0; i < count; i++ {
		name, nameLen := ParseDomainName(message, offset)
		offset += nameLen

		typ := binary.BigEndian.Uint16(message[offset : offset+2])
		offset += 2

		class := binary.BigEndian.Uint16(message[offset : offset+2])
		offset += 2

		ttl := binary.BigEndian.Uint32(message[offset : offset+4])
		offset += 4

		rdlength := binary.BigEndian.Uint16(message[offset : offset+2])
		offset += 2

		rdata := message[offset : offset+int(rdlength)]
		offset += int(rdlength)

		record := DNSRecord{
			Name:     name,
			Type:     typ,
			Class:    class,
			TTL:      ttl,
			RDLength: rdlength,
			RData:    rdata,
		}

		records = append(records, record)
	}

	return records, offset
}

func ParseDomainName(message []byte, offset int) (name string, length int) {
	var parts []string
	for {
		length := int(message[offset])
		log.Println(message[offset:])
		if length == 0 {
			offset++
			break
		}

		offset++
		part := string(message[offset : offset+length])
		parts = append(parts, part)
		offset += length
	}

	name = ""
	for i, part := range parts {
		if i > 0 {
			name += "."
		}
		name += part
	}

	return name, offset - offset
}

// func EncodeDNSMessage(header DNSHeader, questions []DNSQuestion, answers []DNSRecord, additionals []DNSRecord) []byte {
func EncodeDNSMessage(header DNSHeader, questions []DNSQuestion, answers []DNSRecord) []byte {
	message := make([]byte, 0)

	// Encode DNS header
	message = append(message, encodeUint16(header.ID)...)
	message = append(message, encodeUint16(header.Flags)...)
	message = append(message, encodeUint16(header.QDCount)...)
	message = append(message, encodeUint16(header.ANCount)...)
	message = append(message, encodeUint16(header.NSCount)...)
	message = append(message, encodeUint16(header.ARCount)...)

	// Encode questions
	for _, q := range questions {
		message = append(message, EncodeDomainName(q.QName)...)
		message = append(message, encodeUint16(q.QType)...)
		message = append(message, encodeUint16(q.QClass)...)
	}

	// // Encode answers, authorities, and additionals (similar structure)
	message = EncodeDNSRecords(message, answers)
	// message = encodeDNSRecords(message, additionals)

	return message
}

func EncodeDNSRecords(message []byte, records []DNSRecord) []byte {
	for _, record := range records {
		message = append(message, EncodeDomainName(record.Name)...)
		message = append(message, encodeUint16(record.Type)...)
		message = append(message, encodeUint16(record.Class)...)
		message = append(message, encodeUint32(record.TTL)...)
		message = append(message, encodeUint16(record.RDLength)...)
		message = append(message, record.RData...)
	}
	return message
}

func EncodeDomainName(name string) []byte {
	var encoded []byte

	labels := splitLabels(name)

	for _, label := range labels {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}

	encoded = append(encoded, 0x00)

	return encoded
}

func splitLabels(name string) []string {
	labels := make([]string, 0)
	start := 0

	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}

	labels = append(labels, name[start:])

	return labels
}

func encodeUint16(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}

func encodeUint32(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}

func Forwad(question string, resolver string) (addrs []string, err error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, network, resolver)
		},
	}
	return r.LookupHost(context.Background(), question)
}

// func Lookup(question string, resolver string, port string) (addr string) {
// 	addr = ""
//     if ips, err := Forwad(question, resolver+ ":" +port)); err != nil {
//         addr = ips[0]
//     }
// 	return addr
// }

func IsIPv4(address string) bool {
	return strings.Count(address, ":") < 2
}

func IsIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

func FilterIpV4(ips []string) (ipV4s []string) {
	for _, ip := range ips {
		if IsIPv4(ip) {
			ipV4s = append(ipV4s, ip)
		}
	}
	return ipV4s
}
