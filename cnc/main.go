package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	ENCRYPTION_KEY = 42
)

var CRLF = []byte{'\r', '\n', '\r', '\n'}
var KEYS = []string{
	"<REDACTED>",
}

type Envelope struct {
	Action string  `json:"action"`
	Data   *string `json:"data"`
}

type Payload struct {
	PigeonID   string `json:"pigeonID"`
	PrivateKey string `json:"privateKey"`
	Key        string `json:"crypt0rKey"`
}

func main() {
	ln, err := net.Listen("tcp", ":1337")
	if err != nil {
		panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error on accept => ", err.Error())
			continue
		}

		fmt.Println("New connection from ", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	time.Sleep(100 * time.Millisecond)

	buffer := make([]byte, 0, 20480)

	for {
		buf := make([]byte, 2048)
		size, err := conn.Read(buf)
		if err != nil {
			fmt.Println("[", conn.RemoteAddr(), "] Error while reading socket: ", err.Error())
			return
		} else if size < 2048 {
			buf = buf[:size]
			buffer = append(buffer, buf...)
			break
		}

		buffer = append(buffer, buf...)
	}

	fmt.Println("[", conn.RemoteAddr(), "] Received ", len(buffer), " bytes.")

	token := bytes.Split(buffer, CRLF)

	header := string(token[0])

	if code := checkHeader(header); code != 200 {
		fmt.Println("[", conn.RemoteAddr(), "] Header invalid. Code => ", code)
		gtfo(conn, code, nil)
		return
	}

	// Decode payload
	for i, _ := range token[1] {
		token[1][i] ^= ENCRYPTION_KEY
	}

	var envelope Envelope
	err := json.Unmarshal(token[1], &envelope)
	if err != nil {
		fmt.Println("[", conn.RemoteAddr(), "] Cannot unmarshal json => ", err.Error(), "; ( ", len(token[1]), " bytes / ", len(token), " chunks)\n", strings.Replace(string(token[1]), "\n", "    ", 100))
		gtfo(conn, 400, nil)
		return
	}

	var code uint16
	var data string
	if envelope.Action == "keygen" {
		code = 200
		data = fmt.Sprintf("{ \"generatedKey\": \"$$%s$$\" }", getKey())
		gtfo(conn, code, encrypt(data))
		return
	} else if envelope.Action == "register" {
		// Try to parse Data
		dec, err := base64.StdEncoding.DecodeString(*envelope.Data)
		if err != nil {
			fmt.Println("[", conn.RemoteAddr(), "] Cannot decode b64 => ", err.Error())
			gtfo(conn, 400, []byte(`{ "message": "Wrong b64 fella." }`))
			return
		}

		dec = decryptPayload(dec)
		if dec == nil {
			fmt.Println("[", conn.RemoteAddr(), "] Wrong encrypt")
			gtfo(conn, 400, []byte(`{ "message": "Fucked enc. GTFO" }`))
			return
		}

		fmt.Println("[", conn.RemoteAddr(), "] Encryption pass.")
		code = 200
	} else {
		code = 400
		data = `{ "message": "Wrong action bro." }`
	}

	gtfo(conn, code, []byte(data))
}

func checkHeader(header string) uint16 {
	// Check header values
	headerLines := strings.Split(header, "\r\n")
	if len(headerLines) < 4 {
		return 400
	}

	if !strings.HasPrefix(headerLines[0], "POST /gate.php ") {
		return 404
	}

	headerLines = headerLines[1:]
	for _, line := range headerLines {
		if strings.HasPrefix(line, "User-Agent:") {
			if line != "User-Agent: Crypt0r" {
				return 401
			}
		} else if strings.HasPrefix(line, "Host:") {
			if line != "Host: crypt0r.gate" {
				return 404
			}
		} else if strings.HasPrefix(line, "Content-Type:") {
			if line != "Content-Type: application/json" {
				return 417
			}
		}
	}

	return 200
}

func checkPayload(payload *Payload) (uint16, string) {
	if strings.Count(payload.PigeonID, "-") != 2 {
		return 400, `{ "message": "GTFO BRO." }`
	}

	if len(payload.PrivateKey) < 80 {
		return 400, `{ "message": "WTF with the key? FUUU." }`
	}

	if payload.Key == "CTF-INSA-8A02B1CBC441DF0912FF38012A8B4C7E" {
		fmt.Println(payload.Key)
		return 401, `{ "message": "Wrong key. GTFO DAWG." }`
	}

	return 200, fmt.Sprintf("{ \"message\": \"Got it bro! Let's make $$$ :)\", \"special\": %d }", rand.Uint32())
}

func gtfo(conn net.Conn, code uint16, data []byte) {
	var codeMessage string

	switch code {
	case 200:
		codeMessage = "200 OK"
	case 400:
		codeMessage = "400 Bad Request"
	case 401:
		codeMessage = "401 Unauthorized"
	case 404:
		codeMessage = "404 Not Found"
	case 417:
		codeMessage = "417 Expectation failed"
	}

	if data == nil {
		fmt.Println("[", conn.RemoteAddr(), "] Header KO. Response => ", code)
		header := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: text/html\r\nContent-Length: 4\r\nServer: Crypt0r\r\n\r\nGTFO", codeMessage)
		conn.Write([]byte(header))
		return
	}

	fmt.Println("[", conn.RemoteAddr(), "] Header pass. Response => ", code)
	response := fmt.Sprintf("HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nServer: Crypt0r\r\n\r\n%s", codeMessage, len(data), string(data))
	conn.Write([]byte(response))
}

func getKey() string {
	return KEYS[rand.Int()%len(KEYS)]
}

func encrypt(data string) []byte {
	b := []byte(data)

	for i, _ := range b {
		b[i] ^= ENCRYPTION_KEY
	}

	return b
}

func decryptPayload(data []byte) []byte {
	buffer := make([]byte, len(data))
	for _, v := range KEYS {
		k := []byte(v)

		if data[0]^k[0] == '{' {
			for i, _ := range buffer {
				buffer[i] = data[i] ^ k[i%len(k)]
			}

			if buffer[len(buffer)-1] == '}' || buffer[len(buffer)-2] == '}' {
				return buffer
			}
		}
	}

	return nil
}
