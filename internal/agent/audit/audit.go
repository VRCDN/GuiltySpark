// Package audit watches files and exec events on the host.
//
// File changes come from inotify via fsnotify — straightforward enough.
// Exec events are the annoying part: we tap into the kernel audit subsystem over
// NETLINK_AUDIT, which requires root or CAP_AUDIT_READ + CAP_AUDIT_WRITE. If auditd
// is already running and owns the socket we can't get in, so we fall back to tailing
// /var/log/audit/audit.log instead, which is clunky but works.
package audit

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/VRCDN/guiltyspark/internal/common/models"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// Manager runs the file watcher and exec auditor and fans their events into one channel.
type Manager struct {
	agentID    string
	fileWatch  bool
	watchPaths []string
	execAudit  bool
	logger     *slog.Logger
	events     chan models.AuditEvent
}

// New creates an audit Manager. The 8k event buffer is there because the kernel can be
// very chatty during busy periods.
func New(agentID string, fileWatch bool, watchPaths []string, execAudit bool, logger *slog.Logger) *Manager {
	return &Manager{
		agentID:    agentID,
		fileWatch:  fileWatch,
		watchPaths: watchPaths,
		execAudit:  execAudit,
		logger:     logger,
		events:     make(chan models.AuditEvent, 8192),
	}
}

// Events returns the output channel. Keep up with it or events get dropped.
func (m *Manager) Events() <-chan models.AuditEvent {
	return m.events
}

// Run kicks off whichever subsystems are enabled and waits for them both to exit.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup

	if m.fileWatch && len(m.watchPaths) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runFileWatcher(ctx)
		}()
	}

	if m.execAudit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runExecAudit(ctx)
		}()
	}

	wg.Wait()
	close(m.events)
}

// emit queues an event. If the channel is full we drop it — better than blocking the watcher.
func (m *Manager) emit(ev models.AuditEvent) {
	ev.ID = uuid.New().String()
	ev.AgentID = m.agentID
	select {
	case m.events <- ev:
	default:
		m.logger.Warn("audit event queue full, dropping event", "type", ev.Type)
	}
}

// file watcher (inotify via fsnotify)

func (m *Manager) runFileWatcher(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Error("create file watcher", "error", err)
		return
	}
	defer watcher.Close()

	for _, path := range m.watchPaths {
		if err := addRecursive(watcher, path); err != nil {
			m.logger.Warn("watch path", "path", path, "error", err)
		} else {
			m.logger.Info("watching path for audit", "path", path)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			m.handleFileEvent(watcher, event)
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			m.logger.Warn("file watcher error", "error", err)
		}
	}
}

func (m *Manager) handleFileEvent(watcher *fsnotify.Watcher, event fsnotify.Event) {
	ev := models.AuditEvent{
		Timestamp: time.Now().UTC(),
		Path:      event.Name,
	}

	switch {
	case event.Has(fsnotify.Create):
		ev.Type = models.AuditEventFileCreate
		// if a new directory shows up, watch it too
		if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
			_ = addRecursive(watcher, event.Name)
		}
	case event.Has(fsnotify.Write):
		ev.Type = models.AuditEventFileModify
	case event.Has(fsnotify.Remove):
		ev.Type = models.AuditEventFileDelete
	case event.Has(fsnotify.Rename):
		ev.Type = models.AuditEventFileRename
	case event.Has(fsnotify.Chmod):
		ev.Type = models.AuditEventFilePermission
		// grab the new mode since the chmod event itself doesn't include it
		if info, err := os.Stat(event.Name); err == nil {
			ev.Mode = fmt.Sprintf("%04o", info.Mode().Perm())
		}
	default:
		return
	}

	m.emit(ev)
}

// addRecursive walks a directory tree and adds every subdirectory to the watcher.
func addRecursive(watcher *fsnotify.Watcher, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if info.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
}

// exec auditor — NETLINK_AUDIT because that's apparently what you have to do

// netlink + kernel audit constants; none of these are in the Go stdlib so we define them ourselves
const (
	NETLINK_AUDIT    = 9
	AUDIT_GET        = 1000
	AUDIT_SET        = 1001
	AUDIT_ADD_RULE   = 1011
	AUDIT_DEL_RULE   = 1012
	AUDIT_LIST_RULES = 1013
	AUDIT_SYSCALL    = 1300
	AUDIT_PATH       = 1302
	AUDIT_EXECVE     = 1309
	AUDIT_EOE        = 1320 // end of event

	AUDIT_ARCH_X86_64 = 0xc000003e
	NLM_F_REQUEST     = 0x01

	// syscall numbers (x86_64)
	SYSCALL_EXECVE   = 59
	SYSCALL_EXECVEAT = 322
)

// auditRuleData mirrors the kernel's audit_rule_data struct. We have to build this by hand
// because there's no Go binding for it.
type auditRuleData struct {
	flags      uint32
	action     uint32
	fieldCount uint32
	mask       [64]uint32
	fields     [64]uint32
	values     [64]uint32
	fieldFlags [64]uint32
	bufLen     uint32
	buf        [0]byte
}

func (m *Manager) runExecAudit(ctx context.Context) {
	if err := m.runNetlinkAudit(ctx); err != nil {
		m.logger.Warn("netlink audit failed, falling back to audit.log", "error", err)
		m.runAuditLogTail(ctx)
	}
}

func (m *Manager) runNetlinkAudit(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, NETLINK_AUDIT)
	if err != nil {
		return fmt.Errorf("open netlink audit socket: %w", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		return fmt.Errorf("bind netlink: %w", err)
	}

	// tell the kernel we want auditing on
	if err := auditSetEnabled(fd, 1); err != nil {
		return fmt.Errorf("enable audit: %w", err)
	}

	// hook both exec syscalls — execveat is the newer form, we need both
	if err := auditAddExecRule(fd, SYSCALL_EXECVE); err != nil {
		m.logger.Warn("add execve rule", "error", err)
	}
	if err := auditAddExecRule(fd, SYSCALL_EXECVEAT); err != nil {
		m.logger.Warn("add execveat rule", "error", err)
	}

	m.logger.Info("netlink audit active")

	// the kernel sends exec events as multiple records (SYSCALL + EXECVE + PATH) linked by a serial
	// number, so we have to collect the pieces and reassemble them on AUDIT_EOE
	type partialEvent struct {
		syscall string
		execve  string
		path    string
		time    time.Time
	}
	pending := make(map[uint32]*partialEvent)
	buf := make([]byte, 8192)

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// 1s timeout so we can actually notice when ctx is cancelled
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO,
			&unix.Timeval{Sec: 1, Usec: 0})

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n < unix.NLMSG_HDRLEN {
			continue
		}

		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			continue
		}

		for _, msg := range msgs {
			msgType := msg.Header.Type
			serial := msg.Header.Seq
			data := string(msg.Data)

			switch int(msgType) {
			case AUDIT_SYSCALL:
				p := &partialEvent{syscall: data, time: time.Now().UTC()}
				pending[serial] = p
			case AUDIT_EXECVE:
				if p, ok := pending[serial]; ok {
					p.execve = data
				}
			case AUDIT_PATH:
				if p, ok := pending[serial]; ok {
					p.path = data
				}
			case AUDIT_EOE:
				if p, ok := pending[serial]; ok {
					delete(pending, serial)
					if ev, ok2 := parseAuditExecEvent(p.syscall, p.execve, p.path, p.time); ok2 {
						m.emit(*ev)
					}
				}
			}
		}
	}
}

// auditSetEnabled flips auditing on or off via AUDIT_SET. Needs root.
// The struct layout has to match the kernel's exactly — fun.
func auditSetEnabled(fd int, enable uint32) error {
	type auditStatus struct {
		mask                  uint32
		enabled               uint32
		failure               uint32
		pid                   uint32
		rateLimit             uint32
		backlogLimit          uint32
		lost                  uint32
		backlog               uint32
		featureBitmap         uint32
		backlogWaitTime       uint32
		backlogWaitTimeActual uint32
	}
	status := auditStatus{
		mask:    0x01, // AUDIT_STATUS_ENABLED bitmask
		enabled: enable,
	}
	data := (*[unsafe.Sizeof(status)]byte)(unsafe.Pointer(&status))[:]
	return sendNetlinkMsg(fd, uint16(AUDIT_SET), data)
}

// auditAddExecRule tells the kernel to audit a specific syscall. The bit-twiddling is
// unfortunately necessary — the kernel rule uses a bitmask over all 300-odd syscall numbers.
func auditAddExecRule(fd int, syscallNum int) error {
	var rule auditRuleData
	rule.flags = 0x01  // AUDIT_FILTER_EXIT
	rule.action = 0x01 // AUDIT_ALWAYS
	rule.fieldCount = 1
	// set the bit for this specific syscall in the mask array
	rule.mask[syscallNum/32] |= 1 << uint(syscallNum%32)
	rule.fields[0] = 35 // AUDIT_ARCH
	rule.values[0] = AUDIT_ARCH_X86_64
	rule.fieldFlags[0] = 0x80 // AUDIT_EQUAL

	size := 8*4 + 64*4*4 + 4 // close enough — we zero-fill the rest
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data[0:], rule.flags)
	binary.LittleEndian.PutUint32(data[4:], rule.action)
	binary.LittleEndian.PutUint32(data[8:], rule.fieldCount)
	for i := 0; i < 64; i++ {
		binary.LittleEndian.PutUint32(data[12+i*4:], rule.mask[i])
	}
	for i := 0; i < 64; i++ {
		binary.LittleEndian.PutUint32(data[12+64*4+i*4:], rule.fields[i])
	}
	for i := 0; i < 64; i++ {
		binary.LittleEndian.PutUint32(data[12+64*8+i*4:], rule.values[i])
	}
	for i := 0; i < 64; i++ {
		binary.LittleEndian.PutUint32(data[12+64*12+i*4:], rule.fieldFlags[i])
	}
	return sendNetlinkMsg(fd, uint16(AUDIT_ADD_RULE), data)
}

func sendNetlinkMsg(fd int, msgType uint16, data []byte) error {
	hdr := unix.NlMsghdr{
		Len:   uint32(unix.NLMSG_HDRLEN + len(data)),
		Type:  msgType,
		Flags: NLM_F_REQUEST,
		Seq:   uint32(time.Now().UnixNano()),
		Pid:   0,
	}
	msg := make([]byte, hdr.Len)
	binary.LittleEndian.PutUint32(msg[0:], hdr.Len)
	binary.LittleEndian.PutUint16(msg[4:], hdr.Type)
	binary.LittleEndian.PutUint16(msg[6:], hdr.Flags)
	binary.LittleEndian.PutUint32(msg[8:], hdr.Seq)
	binary.LittleEndian.PutUint32(msg[12:], hdr.Pid)
	copy(msg[16:], data)

	return unix.Sendmsg(fd, msg, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0)
}

// auditFieldRE matches key=value pairs from kernel audit messages, handling both quoted and unquoted values.
var auditFieldRE = regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|\S+)`)

func parseAuditRecord(raw string) map[string]string {
	fields := make(map[string]string)
	matches := auditFieldRE.FindAllStringSubmatch(raw, -1)
	for _, m := range matches {
		val := m[2]
		if len(val) >= 2 && val[0] == '"' {
			val = val[1 : len(val)-1]
		}
		fields[m[1]] = val
	}
	return fields
}

func parseAuditExecEvent(syscallRaw, execveRaw, pathRaw string, ts time.Time) (*models.AuditEvent, bool) {
	sf := parseAuditRecord(syscallRaw)
	if sf["syscall"] == "" {
		return nil, false
	}

	ev := &models.AuditEvent{
		Type:      models.AuditEventExec,
		Timestamp: ts,
	}

	if uid, err := strconv.Atoi(sf["uid"]); err == nil {
		ev.UID = uid
	}
	if pid, err := strconv.Atoi(sf["pid"]); err == nil {
		ev.PID = pid
	}
	if ppid, err := strconv.Atoi(sf["ppid"]); err == nil {
		ev.ParentPID = ppid
	}
	ev.Username = sf["auid"]
	if ev.Username == "4294967295" || ev.Username == "-1" {
		ev.Username = sf["uid"]
	}
	ev.ProcessName = sf["comm"]
	ev.Command = sf["exe"]
	ev.ReturnCode, _ = strconv.Atoi(sf["exit"])

	// pull the individual args out — they're named a0, a1, a2...
	if execveRaw != "" {
		ef := parseAuditRecord(execveRaw)
		argc, _ := strconv.Atoi(ef["argc"])
		for i := 0; i < argc && i < 64; i++ {
			if arg, ok := ef[fmt.Sprintf("a%d", i)]; ok {
				ev.Args = append(ev.Args, arg)
			}
		}
	}

	return ev, true
}

// audit.log fallback — used when we can't get the netlink socket (e.g. auditd is already running)

var auditLogExecRE = regexp.MustCompile(`type=EXECVE`)

func (m *Manager) runAuditLogTail(ctx context.Context) {
	const auditLog = "/var/log/audit/audit.log"
	m.logger.Info("tailing audit log as fallback", "path", auditLog)

	f, err := os.Open(auditLog)
	if err != nil {
		m.logger.Warn("cannot open audit log", "path", auditLog, "error", err)
		return
	}
	defer f.Close()

	// jump to the end — we don't want to replay old events
	_, _ = f.Seek(0, 2)
	reader := bufio.NewReader(f)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				line = strings.TrimSpace(line)
				if line != "" && auditLogExecRE.MatchString(line) {
					if ev, ok := parseAuditLogLine(line); ok {
						ev.AgentID = m.agentID
						m.emit(*ev)
					}
				}
				if err != nil {
					break
				}
			}
		}
	}
}

// auditLogLineRE matches a line from /var/log/audit/audit.log.
var auditLogLineRE = regexp.MustCompile(
	`type=(\w+) msg=audit\([\d.]+:(\d+)\): (.+)`)

func parseAuditLogLine(line string) (*models.AuditEvent, bool) {
	m := auditLogLineRE.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	recordType := m[1]
	raw := m[3]

	fields := parseAuditRecord(raw)
	ev := &models.AuditEvent{
		Timestamp: time.Now().UTC(),
	}

	switch recordType {
	case "EXECVE", "SYSCALL":
		ev.Type = models.AuditEventExec
	case "PATH":
		ev.Type = models.AuditEventFileModify
		ev.Path = fields["name"]
	default:
		return nil, false
	}

	if uid, err := strconv.Atoi(fields["uid"]); err == nil {
		ev.UID = uid
	}
	if pid, err := strconv.Atoi(fields["pid"]); err == nil {
		ev.PID = pid
	}
	ev.ProcessName = fields["comm"]
	ev.Command = fields["exe"]

	argc, _ := strconv.Atoi(fields["argc"])
	for i := 0; i < argc && i < 64; i++ {
		if arg, ok := fields[fmt.Sprintf("a%d", i)]; ok {
			ev.Args = append(ev.Args, arg)
		}
	}

	return ev, true
}
