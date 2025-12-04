package messaging

import (
	"encoding/gob"
	"fmt"
	"net"
	"slices"
	"time"
)

type Message int

const (
	MsgNone Message = iota
	MsgPing
	MsgPong
	MsgConnAccepted
	MsgConnRejected // queue full
	MsgActivateConn
	MsgConnActivated
	MsgVerifyConn
	MsgConnVerificationReady
)

type ConnInfo struct {
	KubeIdentifier string
	SvcActToken    string
	ConnectionID   string
}

func Write(c net.Conn, payload any) error {
	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	defer c.SetWriteDeadline(time.Time{})
	enc := gob.NewEncoder(c)
	if err := enc.Encode(payload); err != nil {
		return err
	}
	return nil
}

func Expect(c net.Conn, expectedMsgs ...Message) (Message, error) {
	var msg Message
	defer c.SetReadDeadline(time.Time{})

	deadline := time.Now().Add(5 * time.Second)
	if slices.Contains(expectedMsgs, MsgActivateConn) {
		deadline = time.Now().Add(2 * time.Hour)
	}
	if err := c.SetReadDeadline(deadline); err != nil {
		return msg, err
	}
	if err := gob.NewDecoder(c).Decode(&msg); err != nil {
		return msg, err
	}
	if !slices.Contains(expectedMsgs, msg) {
		return msg, fmt.Errorf("expected one of %v, got: %d", expectedMsgs, msg)
	}
	return msg, nil
}

func ReadConnInfo(c net.Conn) (ConnInfo, error) {
	var info ConnInfo
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return info, err
	}
	defer c.SetReadDeadline(time.Time{})
	dec := gob.NewDecoder(c)
	if err := dec.Decode(&info); err != nil {
		return info, err
	}
	return info, nil
}
