package core

import (
	"os"
	"net"
	"fmt"
	"time"
	"sync"
	"unsafe"

	"github.com/edgecomllc/eupf/cmd/config"
	"github.com/edgecomllc/eupf/cmd/ebpf"
	"github.com/rs/zerolog/log"
	"github.com/cilium/ebpf/perf"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const RTT_TIME_THRESHOLD 	= 1
const RTT_TIME_QUOTA 		= 2
const RTT_QUOTA_VALIDITY 	= 3

var errClosed error = fmt.Errorf("Report manager already closed")
var errNotExist error = fmt.Errorf("URR Id not found")

type PfcpReportTimer struct {
	next, prev *PfcpReportTimer	// nil for last element of list
	info *PfcpReportInfo		// the info struct that is owning this timer
	rtt   int			// type of timer RTT
	expire int64			// when the timer is due to expire (unix timestamp)
}

type PfcpReportTimerList struct {
	first, last 	*PfcpReportTimer	// points to first and last element of the ordered list
	mtx		*sync.Mutex
}

type PfcpReportInfo struct {
	addr			*net.UDPAddr
	timer			*PfcpReportTimer
	remoteSEID		uint64
	localId			uint32	// session urrId
	globalId		uint32	// global urrId
	seqN			uint32
	reportSent		bool
	urrAcc			ebpf.UrrAcc
	lastTs			time.Time
}

type PfcpReportManager struct {
	reader		*perf.Reader
	urrMap		map[uint32]*PfcpReportInfo
	bpfObjects	*ebpf.BpfObjects
	closing		bool
}

var timerList = PfcpReportTimerList{
	first : nil,
	last : nil,
	mtx : &sync.Mutex{},
}

// number of seconds between 01/01/1900 and 01/01/1970
const NtpOffset = 2208988800

func (l *PfcpReportTimerList) Lock() {
	l.mtx.Lock()
}

func (l *PfcpReportTimerList) Unlock() {
	l.mtx.Unlock()
}

// remove item from linked list, unprotected
func (l *PfcpReportTimerList) _remove(t *PfcpReportTimer) {
	if t.prev == nil {
		l.first = t.next
	} else {
		t.prev.next = t.next
	}
	if t.next == nil {
		l.last = t.prev
	} else {
		t.next.prev = t.prev
	}
	t.next = nil
	t.prev = nil
}

// remove and return first timer of list if expired, nil otherwise, unprotected
func (l *PfcpReportTimerList) _getExpired(ts int64) *PfcpReportTimer {
	if t := l.first; t != nil && t.expire <= ts {
		// first timer in list is expired, remove it and return
		l.first = t.next
		if t.next == nil {
			l.last = nil
		} else {
			t.next.prev = nil
			t.next = nil
		}
		// remove reference so that the timer will be cleaned after processing by calling function
		t.info.timer = nil
		return t
	}
	return nil
}

// stop running timer on info, unprotected
func (l *PfcpReportTimerList) _stop(info *PfcpReportInfo) {
	if t := info.timer; t != nil {
		l._remove(t)
		t.info = nil
		info.timer = nil				
	}
}

func (l *PfcpReportTimerList) _stopAll() {
	for t:= l.first; t != nil; t = l.first {
		t.info.timer = nil
		t.info = nil
		l._remove(t)
	}
}

// stop any running timer, start timer specified in urrInfo, if any, unprotected
func (l *PfcpReportTimerList) _start(info *PfcpReportInfo, urrInfo *ebpf.UrrInfo) {
	var timeout uint32 = 0xFFFFFFFF
	var rtt int = 0
	if urrInfo.TimeThreshold != 0 && urrInfo.TimeThreshold < timeout {
		timeout = urrInfo.TimeThreshold
		rtt = RTT_TIME_THRESHOLD
	} else if urrInfo.TimeQuota != 0 && urrInfo.TimeQuota < timeout {
		timeout = urrInfo.TimeQuota
		rtt = RTT_TIME_QUOTA
	} else if urrInfo.QuotaValidity != 0 && urrInfo.QuotaValidity < timeout {
		timeout = urrInfo.QuotaValidity
		rtt = RTT_QUOTA_VALIDITY
	}
	l._stop(info)
	if rtt == 0 {
		return
	}
	// stop any running timer
	expire := time.Now().Unix()+int64((timeout+500)/1000)
	log.Debug().Msgf("Start URR timer type:%d, expire:%d", rtt, expire)
	t := &PfcpReportTimer{
		next:  nil,
		prev:  nil,
		info:  info,
		rtt:   rtt,
		expire: expire,
	}
	info.timer = t
	// it is quite likely that this new timer will expire after all running timer,
	// => walk through the list from the end to compare with oldest timers.
	for p := l.last; p != nil; p = p.prev {
		// come here only if the list is not emtpy
		if expire >= p.expire {
			// insert t after p
			if p.next == nil {
				// p was the last element -=> t becomes the new last element
				t.prev = p
				p.next = t
				l.last = t
			} else {
				// insert t in the middle
				t.next = p.next
				t.next.prev = t
				p.next = t
				t.prev = p
			}
			return
		}
	}
	// come here when t must be first in the list
	if l.first == nil {
		// the list was empty, this is the first timer
		l.first = t
		l.last = t
	} else {
		t.next = l.first
		t.next.prev = t
		l.first = t
	}
}

func CreatePfcpReportManager(bpfObjects *ebpf.BpfObjects) (*PfcpReportManager, error) {
	log.Info().Msgf("Starting PFCP Usage Report manager")
	reader, err := perf.NewReader(bpfObjects.UrrRepMap, int(config.Conf.UrrBufferSize))
	if err != nil {
		log.Warn().Msgf("failed to create perf reader object")
		return nil, err
	}
	return &PfcpReportManager{
		reader:		reader,
		bpfObjects:	bpfObjects,
		urrMap:		map[uint32]*PfcpReportInfo{},
		closing:	false,
	}, nil
}

type embeddedError interface {
	Unwrap() error
}

func (manager *PfcpReportManager) Run(conn *PfcpConnection) {
	var rec perf.Record
	var rep ebpf.UrrRep
	var acc ebpf.UrrAcc
	var urr ebpf.UrrInfo
	var info *PfcpReportInfo
	var t *PfcpReportTimer
	var ok bool
	var err error
	var rtt int
	var deltaKTimeNowNs uint64
	var addr *net.UDPAddr
	reader := manager.reader
	bpfObjects := manager.bpfObjects
	defer reader.Close()
	tick := time.Second
	now := time.Now()
	reader.SetDeadline(now.Add(tick))
	log.Info().Msgf("Report manager running")
	for {
		// thanks to deadline, this call is garanteed to return at least once per second
		if err = reader.ReadInto(&rec); err != nil {
			if temp, ok := err.(embeddedError); ok {
				err = temp.Unwrap()
			}
			if err != os.ErrDeadlineExceeded {
				log.Info().Msgf("Report manager exiting: %s", err.Error())
				break
			}
			// deadline expired, check pending timers
			now = time.Now()
			// protected section : access to 
			timerList.Lock()
			if t = timerList._getExpired(now.Unix()); t == nil {
				// no timer pending for this tick, advance deadline for next tick
				timerList.Unlock()
				reader.SetDeadline(now.Add(tick))
				continue
			}
			// one timer expired
			info = t.info
			rtt = t.rtt
			// t no longer needed, clean it so that it can go to garbage collector
			t.info = nil
			t = nil
			// Note: access to bpf urr maps must be in critical section as delete can come asynchronously
			// load current accounting
			bpfObjects.UrrAccMap.Lookup(info.globalId, unsafe.Pointer(&acc))
			// update UrrInfoMap to tell eBPF not to send report but restart accounting
			bpfObjects.UrrInfoMap.Lookup(info.globalId, unsafe.Pointer(&urr))
			urr.ReportSent = 2	// magical value, see XDP program
			bpfObjects.UrrInfoMap.Put(info.globalId, unsafe.Pointer(&urr))
			// these fields may be changed outside this go routine, use them in critical section
			addr = info.addr
			info.reportSent = true
			// done with info, leaving critical section
			timerList.Unlock()
			log.Debug().Msgf("URR %d timer expired", info.globalId)
			// mimic XDP program sending a report
			rep.Type = 2	// RT_USAGE_REPORT
			switch (rtt) {
			case RTT_TIME_THRESHOLD:
				rep.UsageTrigger5 = 4	// UT5_TIME_THRESHOLD
				rep.UsageTrigger6 = 0
				rep.UsageTrigger7 = 0
			case RTT_TIME_QUOTA:
				rep.UsageTrigger5 = 0
				rep.UsageTrigger6 = 2	// UT6_TIME_QUOTA
				rep.UsageTrigger7 = 0
			case RTT_QUOTA_VALIDITY:
				rep.UsageTrigger5 = 0
				rep.UsageTrigger6 = 0
				rep.UsageTrigger7 = 8	// UT7_QUOTA_VALIDITY_TIME
			}
			rep.Id = info.globalId
			rep.TotalOctets = acc.TotalOctets
			rep.UlOctets = acc.UlOctets
			rep.DlOctets = acc.DlOctets
			rep.TotalPkts = acc.TotalPkts
			rep.UlPkts = acc.UlPkts
			rep.DlPkts = acc.DlPkts
			rep.KTimeFirstPktNs = acc.KTimeFirstPktNs
			rep.KTimeLastPktNs = acc.KTimeLastPktNs
			// convert Ktimestamp to NTP timestamp 
			if rep.KTimeFirstPktNs == 0 {
				// no accounting packet at all, assume at least one package at the start of the interval
				rep.KTimeFirstPktNs = uint64(info.lastTs.Unix()+NtpOffset)
				rep.KTimeLastPktNs = rep.KTimeFirstPktNs
			} else if deltaKTimeNowNs == 0 {
				// we have no reference to KTime, assume last packet was just received
				rep.KTimeFirstPktNs = (rep.KTimeFirstPktNs+uint64(now.UnixNano())-rep.KTimeLastPktNs)/1000_000_000+NtpOffset
				rep.KTimeLastPktNs = uint64(now.Unix())+NtpOffset
			} else {
				// we have KTime reference, get correct NTP timestamp
				rep.KTimeLastPktNs = (rep.KTimeLastPktNs+deltaKTimeNowNs)/1000_000_000+NtpOffset
				rep.KTimeFirstPktNs = (rep.KTimeFirstPktNs+deltaKTimeNowNs)/1000_000_000+NtpOffset
			}
		} else if len(rec.RawSample) < int(unsafe.Sizeof(rep)) {
			// should not happen
			log.Info().Msgf("Unexpected report size %d", len(rec.RawSample))
			continue
		} else {
			// event received
			// this code assumes that the ebpf program sends report with the exact same format
			rep = *(*ebpf.UrrRep)(unsafe.Pointer(&rec.RawSample[0]))
			log.Debug().Msgf("URR %d report received", rep.Id)
			timerList.Lock()
			if info, ok = manager.urrMap[rep.Id]; !ok {
				// should not happen
				timerList.Unlock()
				log.Info().Msgf("URR info not found")
				continue
			}
			// in case of race condition, do not send report
			if info.reportSent  {
				timerList.Unlock()
				log.Info().Msgf("URR report already sent")
				continue
			}
			// these fields may be changed outside this go routine, use them in critical section
			addr = info.addr
			info.reportSent = true
			// stop timer as we are generating a report
			timerList._stop(info)
			// done with info, leaving critical section
			timerList.Unlock()
			now = time.Now()
			// we know the last packet was just received => calibrate the KTime offet
			deltaKTimeNowNs = uint64(now.UnixNano())-rep.KTimeLastPktNs
			// and convert KTimestamp to NTP timestamp
			rep.KTimeLastPktNs = (rep.KTimeLastPktNs+deltaKTimeNowNs)/1000_000_000+NtpOffset
			rep.KTimeFirstPktNs = (rep.KTimeFirstPktNs+deltaKTimeNowNs)/1000_000_000+NtpOffset
		}
		// build a SRR
		dur := now.Sub(info.lastTs)
		lastRep := &info.urrAcc
		srr := message.NewSessionReportRequest(
			0,	// MP = no message priority
			0,	// FO = only 1 message in UDP
			info.remoteSEID,
			info.seqN,
			0,	// priority
			ie.NewReportType(0, 0, 1, 0),	// usage report
			ie.NewUsageReportWithinSessionReportRequest(
				ie.NewURRID(info.localId),
				ie.NewURSEQN(info.seqN),
				ie.NewUsageReportTrigger(rep.UsageTrigger5, rep.UsageTrigger6, rep.UsageTrigger7),
				ie.NewUint32IE(ie.StartTime, uint32(info.lastTs.Unix()+NtpOffset)),
				ie.NewUint32IE(ie.EndTime, uint32(now.Unix()+NtpOffset)),
				ie.NewVolumeMeasurement(
					0x3F,	// all measurements present
					rep.TotalOctets-lastRep.TotalOctets,
					rep.UlOctets-lastRep.UlOctets,
					rep.DlOctets-lastRep.DlOctets,
					rep.TotalPkts-lastRep.TotalPkts,
					rep.UlPkts-lastRep.UlPkts,
					rep.DlPkts-lastRep.DlPkts),
				ie.NewDurationMeasurement(dur),
				ie.NewUint32IE(ie.TimeOfFirstPacket, uint32(rep.KTimeFirstPktNs)),
				ie.NewUint32IE(ie.TimeOfLastPacket, uint32(rep.KTimeLastPktNs))),
		)
		if err = conn.SendMessage(srr, addr); err != nil {
			log.Info().Msgf("Failed to send Report Request: %s", err.Error())
		} else {
			// update for next report
			log.Debug().Msgf("SRR sent: %+v", rep)
			info.urrAcc = ebpf.UrrAcc{
				TotalOctets :	rep.TotalOctets,
				UlOctets :	rep.UlOctets,
				DlOctets :	rep.DlOctets,
				TotalPkts :	rep.TotalPkts,
				UlPkts :	rep.UlPkts,
				DlPkts :	rep.DlPkts,
			}
			info.lastTs = now
			info.seqN++
		}
		// reset pointers to help garbage collector
		info = nil
		addr = nil
	}
}

func (manager *PfcpReportManager) Close() {
	if reader := manager.reader; reader != nil {
		reader.Close()
		manager.reader = nil
	}
	timerList.Lock()
	defer timerList.Unlock()
	manager.closing = true
	timerList._stopAll()
	for id, info := range manager.urrMap {
		info.addr = nil
		delete(manager.urrMap, id)
		manager.bpfObjects.DeleteUrr(id)
	}
}

// NewUrr(), UpdateUrr(), DeleteUrr() are called from pfcp handler
// => must be thread safe with report manager go routine
func (manager *PfcpReportManager) NewUrr(localId uint32, urrInfo ebpf.UrrInfo, remoteSEID uint64, addrPeer string) (uint32, error) {
	// TBD: addrPeer should also include the port (trimmed in PfcpHandlerMap.Handle)
	var globalId uint32 = 0
	addr, err := net.ResolveUDPAddr("udp", addrPeer+":8805")
	if err == nil {
		timerList.Lock()
		defer timerList.Unlock()
		if manager.closing {
			return 0, errClosed
		}
		urrInfo.ReportSent = 0
		globalId, err = manager.bpfObjects.NewUrr(urrInfo)
		if err == nil {
			info := &PfcpReportInfo{
				addr : addr,
				remoteSEID : remoteSEID,
				localId : localId,
				globalId : globalId,
				seqN : 0,
				reportSent : false,
				urrAcc : ebpf.UrrAcc{},
				lastTs : time.Now(),
			}
			log.Debug().Msgf("URR installed: %+v", *info)
			timerList._start(info, &urrInfo)
			manager.urrMap[globalId] = info;
		}
	} else {
		log.Info().Msgf("Failed resolving %s", addrPeer)
	}
	return globalId, err
}

// update URR in report manager and in eBPF
func (manager *PfcpReportManager) UpdateUrr(globalId uint32, urrInfo ebpf.UrrInfo) error {
	var err error = errNotExist
	timerList.Lock()
	defer timerList.Unlock()
	if manager.closing {
		return errClosed
	}
	if info, ok := manager.urrMap[globalId]; ok {
		// reset ReportSent so that XDP report is pending again
		urrInfo.ReportSent = 0
		info.reportSent = false
		err = manager.bpfObjects.UpdateUrr(globalId, urrInfo, info.urrAcc)
		if err == nil {
			// handle timer
			timerList._start(info, &urrInfo)
		}
	}
	return err
}


func (manager *PfcpReportManager) DeleteUrr(globalId uint32) error {
	var err error = errNotExist
	timerList.Lock()
	defer timerList.Unlock()
	if manager.closing {
		return errClosed
	}
	if info, ok := manager.urrMap[globalId]; ok {
		err = manager.bpfObjects.DeleteUrr(globalId)
		timerList._stop(info)
		delete(manager.urrMap, globalId)
		info.addr = nil
	}
	return err
}
