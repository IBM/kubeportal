package hub

import (
	"kubeportal/messaging"
	"log/slog"
	"math"
	"net"
	"time"
)

type StandbyConnStore struct {
	GetConn       chan net.Conn
	ReserveSlot   chan struct{}
	ReleaseSlot   chan struct{}
	FillSlot      chan net.Conn
	borrowConn    chan net.Conn
	returnConn    chan net.Conn
	conns         []net.Conn
	cap           int
	borrowedConns int
	reservedSlots int
	len           int
	head          int
	tail          int
}

func NewStandbyConnStore(capacity int) *StandbyConnStore {
	return &StandbyConnStore{
		GetConn:     make(chan net.Conn),
		ReserveSlot: make(chan struct{}),
		ReleaseSlot: make(chan struct{}),
		FillSlot:    make(chan net.Conn),
		borrowConn:  make(chan net.Conn),
		returnConn:  make(chan net.Conn),
		conns:       make([]net.Conn, capacity),
		cap:         capacity,
		tail:        1,
	}
}

func (sc *StandbyConnStore) Run(kubeIdentifier string) {
	go sc.eventloop()
	go sc.connChecker(kubeIdentifier)
}

func (sc *StandbyConnStore) eventloop() {
	minConnsForHealthCheck := int(math.Max(float64(sc.cap/5), 1))
	for {
		var getChan chan net.Conn
		var reserveChan chan struct{}
		var releaseChan chan struct{}
		var fillChan chan net.Conn
		var borrowChan chan net.Conn
		var returnChan chan net.Conn

		if ((sc.len + sc.borrowedConns + sc.reservedSlots) > sc.cap) || (sc.borrowedConns > 1) {
			panic("unexpected")
		}

		// can get a conn if not empty
		if sc.len > 0 {
			getChan = sc.GetConn
		}
		// can borrow a conn if have a few
		if sc.len >= minConnsForHealthCheck && sc.borrowedConns == 0 {
			borrowChan = sc.borrowConn
		}
		// can reserve a slot if not full
		if (sc.len + sc.borrowedConns + sc.reservedSlots) < sc.cap {
			reserveChan = sc.ReserveSlot
		}
		// can release or fill a slot if reserved
		if sc.reservedSlots > 0 {
			releaseChan = sc.ReleaseSlot
			fillChan = sc.FillSlot
		}
		// can return a conn if borrowed
		if sc.borrowedConns == 1 {
			returnChan = sc.returnConn
		}

		select {
		case getChan <- sc.conns[sc.head]:
			sc.rmHead()
		case reserveChan <- struct{}{}:
			sc.reservedSlots++
		case releaseChan <- struct{}{}:
			sc.reservedSlots--
		case conn := <-fillChan:
			sc.reservedSlots--
			sc.add(conn)
		case borrowChan <- sc.conns[sc.tail]:
			sc.rmTail()
			sc.borrowedConns++
		case conn := <-returnChan:
			if conn != nil {
				sc.add(conn)
			}
			sc.borrowedConns--
		}
	}
}

func (sc *StandbyConnStore) add(conn net.Conn) {
	sc.head = (sc.head + 1) % sc.cap
	sc.conns[sc.head] = conn
	sc.len++
}

func (sc *StandbyConnStore) rmHead() {
	sc.head = (sc.head - 1 + sc.cap) % sc.cap
	sc.len--
}

func (sc *StandbyConnStore) rmTail() {
	sc.tail = (sc.tail + 1) % sc.cap
	sc.len--
}

// Ensure we always have at least one heathy conn per kube
func (sc *StandbyConnStore) connChecker(kubeIdentifier string) {
	log := slog.With("kubeIdentifier", kubeIdentifier)
	for conn := range sc.borrowConn {
		if err := messaging.Write(conn, messaging.MsgPing); err != nil {
			log.With("error", err).Warn("Failed to send ping on agent conn")
			conn.Close()
			conn = nil
		} else if _, err := messaging.Expect(conn, messaging.MsgPong); err != nil {
			log.With("error", err).Warn("Failed to receive pong on agent conn")
			conn.Close()
			conn = nil
		}
		sc.returnConn <- conn
		if conn != nil {
			// sleep only after successful check, short interval to quickly detect agent restarts
			time.Sleep(time.Second * 10)
		}
	}
}
