package portchecker

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	NonceBytes        = 32
	DefaultServerAddr = ""
	DefaultTimeout    = 10 * time.Second
)

type Config struct {
	ServerAddr string
	Timeout    time.Duration
}

type Req struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Nonce    string `json:"nonce"`
}

type Resp struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type checkError struct {
	reason error
	error  error
}

func (ce *checkError) isEmpty() bool {
	return ce.reason == nil && ce.error == nil
}

type tcpConn net.TCPConn

func (conn *tcpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := (*net.TCPConn)(conn).Read(b)
	return n, nil, err
}

func (conn *tcpConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return (*net.TCPConn)(conn).Write(b)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func handleConn(conn net.PacketConn, nonceSent string, deadline time.Time) *checkError {
	conn.SetDeadline(deadline)

	nonceReceived := make([]byte, len([]byte(nonceSent)))
	_, addr, err := conn.ReadFrom(nonceReceived)
	if err != nil {
		return &checkError{err, nil}
	}

	if nonceSent != string(nonceReceived) {
		return &checkError{nil, fmt.Errorf("nonce received (%s) is different from nonce sent (%s)", nonceReceived, nonceSent)}
	}

	bytesSent := randomBytes(NonceBytes)
	_, err = conn.WriteTo(bytesSent, addr)
	if err != nil {
		return &checkError{err, nil}
	}

	bytesReceived := make([]byte, NonceBytes)
	_, _, err = conn.ReadFrom(bytesReceived)
	if err != nil {
		return &checkError{err, nil}
	}

	if !bytes.Equal(bytesSent, bytesReceived) {
		return &checkError{nil, fmt.Errorf("bytes received (%x) is different from bytes sent (%x)", bytesReceived, bytesSent)}
	}

	return &checkError{nil, nil}
}

func remoteCheck(serverAddr, protocol string, port uint16, nonceSent string, timeout time.Duration) *checkError {
	req := &Req{
		Protocol: protocol,
		Port:     port,
		Nonce:    nonceSent,
	}

	b, err := json.Marshal(req)
	if err != nil {
		return &checkError{nil, err}
	}

	client := &http.Client{
		Timeout: timeout,
	}
	r, err := client.Post(serverAddr, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return &checkError{nil, err}
	}
	defer r.Body.Close()

	if r.StatusCode == http.StatusInternalServerError {
		return &checkError{nil, errors.New("server error")}
	}

	resp := &Resp{}
	err = json.NewDecoder(r.Body).Decode(resp)
	if err != nil {
		return &checkError{nil, err}
	}

	if r.StatusCode != http.StatusOK {
		return &checkError{nil, errors.New(resp.Error)}
	}

	if !resp.Success {
		return &checkError{errors.New(resp.Error), nil}
	}

	return &checkError{nil, nil}
}

func CheckPort(protocol string, port uint16, configs ...*Config) (bool, error, error) {
	serverAddr := DefaultServerAddr
	if len(configs) > 0 && len(configs[0].ServerAddr) > 0 {
		serverAddr = configs[0].ServerAddr
	}

	if len(serverAddr) == 0 {
		return false, nil, errors.New("ServerAddr should not be empty")
	}

	timeout := DefaultTimeout
	if len(configs) > 0 && configs[0].Timeout > 0 {
		timeout = configs[0].Timeout
	}

	deadline := time.Now().Add(timeout)
	nonceSent := base64.StdEncoding.EncodeToString(randomBytes(NonceBytes))
	protocol = strings.ToLower(protocol)
	errChan := make(chan *checkError, 2)

	switch protocol {
	case "tcp":
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: int(port)})
		if err != nil {
			return false, err, nil
		}
		listener.SetDeadline(deadline)
		defer listener.Close()

		go func() {
			for {
				conn, err := listener.AcceptTCP()
				if err != nil {
					errChan <- &checkError{err, nil}
					return
				}

				ce := handleConn((*tcpConn)(conn), nonceSent, deadline)
				if ce.isEmpty() {
					errChan <- ce
				}
			}
		}()
	case "udp":
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
		if err != nil {
			return false, err, nil
		}
		defer conn.Close()

		go func() {
			errChan <- handleConn(conn, nonceSent, deadline)
		}()
	default:
		return false, nil, fmt.Errorf("unknown protocol: %s", protocol)
	}

	go func() {
		errChan <- remoteCheck(serverAddr, protocol, port, nonceSent, timeout)
	}()

	for i := 0; i < 2; i++ {
		ce := <-errChan
		if !ce.isEmpty() {
			return false, ce.reason, ce.error
		}
	}

	return true, nil, nil
}
