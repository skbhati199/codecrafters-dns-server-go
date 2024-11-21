package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"strings"
)

type DNSMessage struct {
	Header          DNSHeader
	Questions       []DNSQuestion
	ResourceRecords []DNSResourceRecords
	serialize       func() []byte
}

func (question DNSQuestion) serialize() []byte {
	buffer := []byte{}
	labels := strings.Split(question.Name, ".")
	for _, label := range labels {
		if len(label) > 63 {
			// Truncate label if it's too long
			label = label[:63]
		}
		buffer = append(buffer, byte(len(label)))
		buffer = append(buffer, []byte(label)...)
	}
	buffer = append(buffer, 0) // null terminator
	buffer = append(buffer, byte(question.Type>>8), byte(question.Type))
	buffer = append(buffer, byte(question.Class>>8), byte(question.Class))
	return buffer
}

func parseLabel(buf []byte, offset int) (string, int) {
	startOffset := offset
	var labels []string
	for {
		if offset >= len(buf) {
			break
		}
		if buf[offset] == 0 {
			offset++
			break
		}
		if (buf[offset] & 0xC0) == 0xC0 {
			pointer := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3FFF)
			pointedName, _ := parseLabel(buf, pointer)
			labels = append(labels, pointedName)
			offset += 2
			break
		}
		length := int(buf[offset])
		offset++
		if offset+length > len(buf) {
			break
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), offset - startOffset
}

func parseQuestions(serializedBuf []byte, numQues uint16) []DNSQuestion {
	var questionList []DNSQuestion
	offset := 12
	for i := uint16(0); i < numQues; i++ {
		name, nameLength := parseLabel(serializedBuf, offset)
		offset += nameLength
		if offset+4 > len(serializedBuf) {
			break
		}
		questionList = append(questionList, DNSQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(serializedBuf[offset : offset+2]),
			Class: binary.BigEndian.Uint16(serializedBuf[offset+2 : offset+4]),
		})
		offset += 4
	}
	return questionList
}

func handleDNSQuery(conn *net.UDPConn, source *net.UDPAddr, query []byte, resolver string) {
	queryHeader := parseHeader(query)

	if queryHeader.QDCOUNT > 1 {
		// Handle multiple questions
		responses := [][]byte{}
		for _, question := range parseQuestions(query, queryHeader.QDCOUNT) {
			singleQuery := createSingleQuestionQuery(queryHeader, question)
			response, err := forwardDNSQuery(singleQuery, resolver)
			if err != nil {
				fmt.Println("Error forwarding DNS query:", err)
				return
			}
			responses = append(responses, response)
		}
		mergedResponse := mergeResponses(responses, queryHeader.ID)
		conn.WriteToUDP(mergedResponse, source)
	} else {
		// Forward single question query
		response, err := forwardDNSQuery(query, resolver)
		if err != nil {
			fmt.Println("Error forwarding DNS query:", err)
			return
		}
		// Ensure the response has the same ID as the original query
		binary.BigEndian.PutUint16(response[:2], queryHeader.ID)
		conn.WriteToUDP(response, source)
	}
}

func mergeResponses(responses [][]byte, originalID uint16) []byte {
	if len(responses) == 0 {
		return nil
	}

	mergedHeader := parseHeader(responses[0])
	mergedHeader.ID = originalID
	mergedHeader.QDCOUNT = 0
	mergedHeader.ANCOUNT = 0

	var mergedQuestions []DNSQuestion
	var mergedAnswers []DNSResourceRecords

	for _, response := range responses {
		header := parseHeader(response)
		questions := parseQuestions(response, header.QDCOUNT)
		answers := parseAnswers(response, header.ANCOUNT)

		mergedHeader.QDCOUNT += header.QDCOUNT
		mergedHeader.ANCOUNT += header.ANCOUNT
		mergedQuestions = append(mergedQuestions, questions...)
		mergedAnswers = append(mergedAnswers, answers...)
	}

	mergedMessage := DNSMessage{
		Header:          mergedHeader,
		Questions:       mergedQuestions,
		ResourceRecords: mergedAnswers,
	}

	return mergedMessage.serialize()
}

func createNewDnsMessage(buffer []byte) DNSMessage {
	query := parseHeader(buffer)
	questions := parseQuestions(buffer, query.QDCOUNT)
	answers := []DNSResourceRecords{}
	headers := DNSHeader{
		ID:      query.ID,
		QR:      1,
		OPCODE:  query.OPCODE,
		AA:      0,
		TC:      0,
		RD:      query.RD,
		RA:      1,
		Z:       0,
		RCODE:   0,
		QDCOUNT: uint16(len(questions)),
		ANCOUNT: uint16(len(answers)),
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
	return DNSMessage{
		Header:          headers,
		Questions:       questions,
		ResourceRecords: answers,
	}
}

type DNSHeader struct {
	ID      uint16
	QR      uint8
	OPCODE  uint8
	AA      uint8
	TC      uint8
	RD      uint8
	RA      uint8
	Z       uint8
	RCODE   uint8
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
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

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

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
		OPCODE:  (buffer[2] >> 3) & 0x0F,
		AA:      (buffer[2] >> 2) & 0x01,
		TC:      (buffer[2] >> 1) & 0x01,
		RD:      buffer[2] & 0x01,
		RA:      buffer[3] >> 7,
		Z:       (buffer[3] >> 4) & 0x07,
		RCODE:   buffer[3] & 0x0F,
		QDCOUNT: binary.BigEndian.Uint16(buffer[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(buffer[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(buffer[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(buffer[10:12]),
	}
	return header
}

func forwardDNSQuery(query []byte, resolver string) ([]byte, error) {
	conn, err := net.Dial("udp", resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

func main() {
	resolver := flag.String("resolver", "", "DNS resolver address (ip:port)")
	flag.Parse()

	if *resolver == "" {
		fmt.Println("Please provide a resolver address using --resolver flag")
		return
	}

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

	fmt.Println("DNS forwarder listening on 127.0.0.1:2053")
	fmt.Println("Forwarding queries to", *resolver)

	buf := make([]byte, 512)
	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			continue
		}

		go handleDNSQuery(udpConn, source, buf[:size], *resolver)
	}
}

func createSingleQuestionQuery(header DNSHeader, question DNSQuestion) []byte {
	header.QDCOUNT = 1
	dnsMessage := DNSMessage{
		Header:    header,
		Questions: []DNSQuestion{question},
	}
	return dnsMessage.serialize()
}

func parseAnswers(serializedBuf []byte, numAns uint16) []DNSResourceRecords {
	var answerList []DNSResourceRecords
	offset := 12 // Start after the header

	// Skip questions
	for i := uint16(0); i < parseHeader(serializedBuf).QDCOUNT; i++ {
		for serializedBuf[offset] != 0 {
			if (serializedBuf[offset] & 0xC0) == 0xC0 {
				offset += 2
				break
			}
			offset += int(serializedBuf[offset]) + 1
		}
		offset += 5 // 1 for null byte, 2 for TYPE, 2 for CLASS
	}

	for i := uint16(0); i < numAns; i++ {
		name, nameLength := parseName(serializedBuf, offset)
		offset += nameLength

		answer := DNSResourceRecords{
			Name:     name,
			Type:     binary.BigEndian.Uint16(serializedBuf[offset : offset+2]),
			Class:    binary.BigEndian.Uint16(serializedBuf[offset+2 : offset+4]),
			TTL:      binary.BigEndian.Uint32(serializedBuf[offset+4 : offset+8]),
			RDLength: binary.BigEndian.Uint16(serializedBuf[offset+8 : offset+10]),
		}
		offset += 10
		answer.RData = serializedBuf[offset : offset+int(answer.RDLength)]
		offset += int(answer.RDLength)

		answerList = append(answerList, answer)
	}

	return answerList
}

func parseName(buf []byte, offset int) (string, int) {
	startOffset := offset
	var name string
	for {
		if buf[offset] == 0 {
			offset++
			break
		}
		if (buf[offset] & 0xC0) == 0xC0 {
			pointer := int(binary.BigEndian.Uint16(buf[offset:offset+2]) & 0x3FFF)
			pointedName, _ := parseName(buf, pointer)
			name += pointedName
			offset += 2
			break
		}
		length := int(buf[offset])
		name += string(buf[offset+1:offset+1+length]) + "."
		offset += length + 1
	}
	return name, offset - startOffset
}

func getLabelLength(buf []byte) int {
	length := 0
	for {
		if buf[length] == 0 {
			return length + 1
		}
		if (buf[length] & 0xC0) == 0xC0 {
			return length + 2
		}
		length += int(buf[length]) + 1
	}
}
