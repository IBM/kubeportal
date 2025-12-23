package messaging

import (
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"slices"
	"time"
)

type Message int

const (
	MsgNone Message = iota
	MsgConnAccepted
	MsgConnRejected
	MsgVerifyConn
	MsgConnVerificationReady
)

type MsgConnInfo struct {
	KubeIdentifier string
	AgentID        string
	SvcActToken    string
	ConnectionID   string
}

func Write(c net.Conn, payload any) error {
	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	defer c.SetWriteDeadline(time.Time{})
	return gob.NewEncoder(c).Encode(payload)
}

func Expect(c net.Conn, expectedMsgs ...Message) (Message, error) {
	var msg Message
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return msg, err
	}
	defer c.SetReadDeadline(time.Time{})
	if err := gob.NewDecoder(&unbufferedReader{c}).Decode(&msg); err != nil {
		return msg, err
	}
	if !slices.Contains(expectedMsgs, msg) {
		return msg, fmt.Errorf("expected one of %v, got: %d", expectedMsgs, msg)
	}
	return msg, nil
}

func WriteAndExpect(c net.Conn, payload any, expectedMsgs ...Message) (Message, error) {
	if err := Write(c, payload); err != nil {
		return MsgNone, err
	}
	return Expect(c, expectedMsgs...)
}

func ReadConnInfo(c net.Conn) (MsgConnInfo, error) {
	var info MsgConnInfo
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return info, err
	}
	defer c.SetReadDeadline(time.Time{})
	if err := gob.NewDecoder(&unbufferedReader{c}).Decode(&info); err != nil {
		return info, err
	}
	return info, nil
}

// implementing this interface prevents gob.NewDecoder from creating a private buffer
var _ io.ByteReader = (*unbufferedReader)(nil)

type unbufferedReader struct {
	net.Conn
}

func (ur *unbufferedReader) ReadByte() (byte, error) {
	buf := make([]byte, 1)
	_, err := io.ReadFull(ur, buf)
	return buf[0], err
}
