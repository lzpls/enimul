package core

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"time"

	"github.com/lzpls/enimul/internal/buffer"
	E "github.com/lzpls/enimul/internal/errors"
	"github.com/lzpls/enimul/internal/jsonx"
)

func findLastDotOrMidPos(data []byte, sniStart, sniLen int) int {
	subIdx := bytes.LastIndexByte(data[sniStart:sniStart+sniLen], '.')
	if subIdx == -1 {
		return sniLen/2 + sniStart
	}
	return sniStart + subIdx
}

func sendRecords(conn *net.TCPConn, clientHello []byte, offset, length, records, segments int, minorVersion jsonx.Byte, oob, oobex, waitForAckEnabled bool, interval time.Duration) error {
	if !minorVersion.IsZero() {
		clientHello[2] = minorVersion.Byte()
	}
	if records == 0 {
		records = 1
	}
	if segments == 0 {
		segments = 1
	}

	if records == 1 {
		if oobex {
			if err := sendWithOOB(conn, clientHello[:15], clientHello[15]); err != nil {
				return E.WithStr("oob 1", err)
			}
			if err := sendWithOOB(conn, clientHello[16:35], 0x0); err != nil {
				return E.WithStr("oob 2", err)
			}
			if err := waitForAck(waitForAckEnabled, conn, interval); err != nil {
				return err
			}
			clientHello = clientHello[35:]
			offset -= 35
		}
		if segments == 1 {
			_, err := conn.Write(clientHello)
			if err == nil {
				return nil
			}
			if oobex {
				return E.WithStr("send remaining data", err)
			}
			return E.WithStr("send directly", err)
		}

		cut := findLastDotOrMidPos(clientHello, offset, length)
		i := 0
		sendPacket := func(packet []byte) error {
			if i == 0 && oob {
				if err := sendWithOOB(conn, packet, 0x0); err != nil {
					return E.WithStr("oob", err)
				}
			} else if _, err := conn.Write(packet); err != nil {
				return E.WithStr("write packet "+strconv.Itoa(i+1), err)
			}
			i++
			return waitForAck(waitForAckEnabled, conn, interval)
		}
		leftSegments := segments / 2
		if err := forEachPart(clientHello[:cut], leftSegments, sendPacket); err != nil {
			return err
		}
		return forEachPart(clientHello[cut:], segments-leftSegments, sendPacket)
	}

	leftChunks := records / 2
	rightChunks := records - leftChunks
	cut := findLastDotOrMidPos(clientHello, offset, length)
	header := clientHello[:3]
	left := clientHello[tlsRecordHeaderLen:cut]
	right := clientHello[cut:]

	if segments == -1 {
		maxPayload := max(maxPartLen(len(left), leftChunks), maxPartLen(len(right), rightChunks))
		buf := buffer.Get(tlsRecordHeaderLen + maxPayload)
		defer buffer.Put(buf)
		i := 0
		sendChunk := func(payload []byte) error {
			rec := fillRecord(buf, header, payload)
			switch {
			case i == 0 && oob:
				if err := sendWithOOB(conn, rec, 0x0); err != nil {
					return E.WithStr("oob", err)
				}
			case i == 0 && oobex:
				l := len(rec)
				if err := sendWithOOB(conn, rec[:l-1], rec[l-1]); err != nil {
					return E.WithStr("oob 1", err)
				}
			case i == 1 && oobex:
				if err := sendWithOOB(conn, rec, 0x0); err != nil {
					return E.WithStr("oob 2", err)
				}
			default:
				if _, err := conn.Write(rec); err != nil {
					return E.WithStr("write record "+strconv.Itoa(i+1), err)
				}
			}
			i++
			return waitForAck(waitForAckEnabled, conn, interval)
		}
		if err := forEachPart(left, leftChunks, sendChunk); err != nil {
			return err
		}
		return forEachPart(right, rightChunks, sendChunk)
	}

	size := (partCount(len(left), leftChunks)+partCount(len(right), rightChunks))*tlsRecordHeaderLen + len(left) + len(right)
	buf := buffer.Get(size)
	defer buffer.Put(buf)
	merged := buf[:0]
	appendChunk := func(payload []byte) error {
		merged = append(merged, header...)
		merged = binary.BigEndian.AppendUint16(merged, uint16(len(payload)))
		merged = append(merged, payload...)
		return nil
	}
	if err := forEachPart(left, leftChunks, appendChunk); err != nil {
		return err
	}
	if err := forEachPart(right, rightChunks, appendChunk); err != nil {
		return err
	}

	if oobex {
		if err := sendWithOOB(conn, merged[:15], merged[15]); err != nil {
			return E.WithStr("oob 1", err)
		}
		if err := sendWithOOB(conn, merged[16:35], 0x0); err != nil {
			return E.WithStr("oob 2", err)
		}
		if err := waitForAck(waitForAckEnabled, conn, interval); err != nil {
			return err
		}
		merged = merged[35:]
	}
	if segments == 1 || len(merged) <= segments {
		_, err := conn.Write(merged)
		return err
	}

	base := len(merged) / segments
	for i := range segments {
		start := i * base
		end := start + base
		if i == segments-1 {
			end = len(merged)
		}
		if i == 0 && oob {
			if err := sendWithOOB(conn, merged[start:end], 0x0); err != nil {
				return E.WithStr("oob", err)
			}
		} else if _, err := conn.Write(merged[start:end]); err != nil {
			return E.WithStr("write segment "+strconv.Itoa(i+1), err)
		}
		if err := waitForAck(waitForAckEnabled, conn, interval); err != nil {
			return err
		}
	}
	return nil
}

func forEachPart(data []byte, n int, fn func(part []byte) error) error {
	if n == 1 || len(data) < n {
		return fn(data)
	}
	base := len(data) / n
	for i := range n {
		end := (i + 1) * base
		if i == n-1 {
			end = len(data)
		}
		if err := fn(data[i*base : end]); err != nil {
			return err
		}
	}
	return nil
}

func partCount(dataLen, n int) int {
	if n == 1 || dataLen < n {
		return 1
	}
	return n
}

func maxPartLen(dataLen, n int) int {
	if n == 1 || dataLen < n {
		return dataLen
	}
	return dataLen - (n-1)*(dataLen/n)
}

func fillRecord(dst, header, payload []byte) []byte {
	rec := dst[:tlsRecordHeaderLen+len(payload)]
	copy(rec[:3], header)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(payload)))
	copy(rec[tlsRecordHeaderLen:], payload)
	return rec
}
