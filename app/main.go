package main
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)
type DNSMessage struct {
	Header          DNSHeader
	Questions       []DNSQuestion
	ResourceRecords []DNSResourceRecords
}
func (dnsMessage DNSMessage) serialize() []byte {
	buffer := []byte{}
	buffer = append(buffer, dnsMessage.Header.serialize()...)
	for _, question := range dnsMessage.Questions {
		buffer = append(buffer, question.serialize()...)
	}
	for _, rr := range dnsMessage.ResourceRecords {
		buffer = append(buffer, rr.serialize()...)
	}
	return buffer
}
func createNewDnsMessage(buffer []byte) DNSMessage {
	query := parseHeader(buffer)
	questions := parseQuestions(buffer, query.QDCOUNT)
	answers := []DNSResourceRecords{}
	for _, question := range questions {
		answers = append(answers, DNSResourceRecords{
			Name:     question.Name,
			Type:     1,
			Class:    1,
			TTL:      0,
			RDLength: 4,
			RData:    []byte("\x08\x08\x08\x08"), // []byte{8, 8, 8, 8}
		})
	}
	var rCode uint8
	if query.OPCODE != 0 {
		rCode = 4
	} else {
		rCode = 0
	}
	headers := DNSHeader{
		ID:      query.ID,
		QR:      1,
		OPCODE:  query.OPCODE,
		AA:      0,
		TC:      0,
		RD:      query.RD,
		RA:      0,
		Z:       0,
		RCODE:   rCode,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: query.NSCOUNT,
		ARCOUNT: query.ARCOUNT,
	}
	return DNSMessage{
		Header:          headers,
		Questions:       questions,
		ResourceRecords: answers,
	}
}
type DNSHeader struct {
	ID      uint16 // Packet Identifier (ID): random ID assigned to query packets.
	QR      uint8  // Query/Response Indicator (QR): 1 for a reply packet, 0 for a question packet.
	OPCODE  uint8  // Operation Code (OPCODE): Specifies the kind of query in a message.
	AA      uint8  // Authoritative Answer (AA): 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
	TC      uint8  // Truncation (TC): 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
	RD      uint8  // Recursion Desired (RD): Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise. (expected 0)
	RA      uint8  // Recursion Available (RA): Server sets this to 1 to indicate that recursion is available. (expected 0)
	Z       uint8  // Reserved (Z): Used by DNSSEC queries. At inception, it was reserved for future use. (expected 0)
	RCODE   uint8  // Response Code (RCODE): Response code indicating the status of the response. (0: no error, 1: format error, 2: server failure, 3: name error, 4: not implemented, 5: refused)
	QDCOUNT uint16 // Question Count (QDCOUNT): num questions in the Question section (expected 0)
	ANCOUNT uint16 // Answer Record Count (ANCOUNT): num records in the Answer section (expected 0)
	NSCOUNT uint16 // Authority Record Count (NSCOUNT): num records in the Authority section (expected 0)
	ARCOUNT uint16 // Additional Record Count (ARCOUNT): num records in the Additional section (expected 0)
}
func (header DNSHeader) serialize() []byte {
	buffer := make([]byte, 12)
	binary.BigEndian.PutUint16(buffer[0:2], header.ID)
	buffer[2] = (header.QR << 7) | (header.OPCODE << 3) | (header.AA << 2) | (header.TC << 1) | header.RD
	buffer[3] = (header.RA << 7) | (header.Z << 4) | header.RCODE
	binary.BigEndian.PutUint16(buffer[4:6], header.QDCOUNT)
	binary.BigEndian.PutUint16(buffer[6:8], header.ANCOUNT)
	binary.BigEndian.PutUint16(buffer[8:10], header.NSCOUNT)
	binary.BigEndian.PutUint16(buffer[10:12], header.ARCOUNT)
	return buffer
}
// Only handle A-type queries
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}
func (question DNSQuestion) serialize() []byte {
	buffer := []byte{}
	labels := strings.Split(question.Name, ".")
	for _, label := range labels {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}
	buffer = append(buffer, '\x00')
	buffer = append(buffer, byte(question.Type>>8), byte(question.Type))
	buffer = append(buffer, byte(question.Class>>8), byte(question.Class))
	return buffer
}
// Only handle A-type answers
type DNSResourceRecords struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}
func (answer DNSResourceRecords) serialize() []byte {
	buffer := []byte{}
	labels := strings.Split(answer.Name, ".")
	for _, label := range labels {
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}
	buffer = append(buffer, '\x00')
	buffer = append(buffer, byte(answer.Type>>8), byte(answer.Type))
	buffer = append(buffer, byte(answer.Class>>8), byte(answer.Class))
	buffer = append(buffer, byte(answer.TTL>>24), byte(answer.TTL>>16), byte(answer.TTL>>8), byte(answer.TTL))
	buffer = append(buffer, byte(answer.RDLength>>8), byte(answer.RDLength))
	buffer = append(buffer, answer.RData...)
	return buffer
}
func parseHeader(serializedBuf []byte) DNSHeader {
	buffer := serializedBuf[:12]
	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(buffer[0:2]),
		QR:      buffer[2] >> 7,
		OPCODE:  (buffer[2] >> 3) & 0x0F, // 0xF = 0000 1111
		AA:      (buffer[2] >> 2) & 0x01,
		TC:      (buffer[2] >> 1) & 0x01,
		RD:      buffer[2] & 0x01, // 0x1 = 0000 0001
		RA:      buffer[3] >> 7,
		Z:       (buffer[3] >> 4) & 0x07, // 0x7 = 0000 0111
		RCODE:   buffer[3] & 0x0F,        // 0xF = 0000 1111
		QDCOUNT: binary.BigEndian.Uint16(buffer[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(buffer[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(buffer[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(buffer[10:12]),
	}
	return header
}
func parseLabel(buf []byte, source []byte) string {
	offset := 0
	labels := []string{}
	for {
		if buf[offset] == 0 {
			break
		}
		if (buf[offset]&0xC0)>>6 == 0b11 {
			ptr := int(binary.BigEndian.Uint16(buf[offset:offset+2]) << 2 >> 2)
			length := bytes.Index(source[ptr:], []byte{0})
			labels = append(labels, parseLabel(source[ptr:ptr+length+1], source))
			offset += 2
			continue
		}
		length := int(buf[offset])
		substring := buf[offset+1 : offset+1+length]
		labels = append(labels, string(substring))
		offset += length + 1
	}
	return strings.Join(labels, ".")
}
func parseQuestions(serializedBuf []byte, numQues uint16) []DNSQuestion {
	var questionList []DNSQuestion
	offset := 12
	for i := uint16(0); i < numQues; i++ {
		len := bytes.Index(serializedBuf[offset:], []byte{0})
		label := parseLabel(serializedBuf[offset:offset+len+1], serializedBuf)
		questionList = append(questionList, DNSQuestion{
			Name:  label,
			Type:  1,
			Class: 1,
		})
		offset += len + 1
		offset += 4 // 2 bytes for type, 2 bytes for class
	}
	return questionList
}
func main() {
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
	buf := make([]byte, 512)
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}
		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)
		response := createNewDnsMessage(buf[:size])
		_, err = udpConn.WriteToUDP(response.serialize(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}