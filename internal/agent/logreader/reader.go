// Package logreader handles tailing log files and streaming Docker container logs.
package logreader

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// LogLine is a single line from a log source with its metadata attached.
type LogLine struct {
	Source string   // file path or "docker:<container_name>"
	Tags   []string // tags inherited from the source config
	Line   string
	Time   time.Time
}

// SourceConfig is one configured log source.
type SourceConfig struct {
	Path string // file path (empty for docker sources)
	Tags []string
	Type string // "file" | "docker"
}

// Manager runs all the log sources and fans their output into one channel.
type Manager struct {
	sources []SourceConfig
	lines   chan LogLine
	logger  *slog.Logger

	dockerSocket     string
	dockerEnabled    bool
	dockerTags       []string
	dockerContainers sync.Map // set of active container IDs — value is always struct{}{}
}

// New creates the log manager.
func New(sources []SourceConfig, dockerEnabled bool, dockerSocket string, dockerTags []string, logger *slog.Logger) *Manager {
	return &Manager{
		sources:       sources,
		lines:         make(chan LogLine, 4096),
		logger:        logger,
		dockerEnabled: dockerEnabled,
		dockerSocket:  dockerSocket,
		dockerTags:    dockerTags,
	}
}

// Lines returns the merged output channel.
func (m *Manager) Lines() <-chan LogLine {
	return m.lines
}

// Run starts tailing all configured files and listening for Docker containers. Blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup

	for _, src := range m.sources {
		if src.Type == "docker" || src.Path == "" {
			continue
		}
		src := src // capture loop variable (pre-Go-1.22 closure requirement)
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.tailFile(ctx, src)
		}()
	}

	if m.dockerEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.runDockerMonitor(ctx)
		}()
	}

	wg.Wait()
	close(m.lines)
}

// file tailing

// tailFile follows a log file and sends new lines downstream. Log rotation is the annoying part:
// we watch the parent directory so we catch the CREATE event when logrotate replaces the file,
// then close the old fd and reopen. The 200ms sleep gives the new file time to appear.
func (m *Manager) tailFile(ctx context.Context, src SourceConfig) {
	m.logger.Info("tailing log file", "path", src.Path, "tags", src.Tags)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		m.logger.Error("create watcher", "error", err)
		return
	}
	defer watcher.Close()

	// watch the directory too — we need the CREATE event to detect log rotation
	dir := filepath.Dir(src.Path)
	if err := watcher.Add(dir); err != nil {
		m.logger.Warn("watch directory failed", "dir", dir, "error", err)
	}

	openFile := func() (*os.File, error) {
		f, err := os.Open(src.Path)
		if err != nil {
			return nil, err
		}
		// seek to the end — we only care about new content, not history
		_, _ = f.Seek(0, io.SeekEnd)
		return f, nil
	}

	f, err := openFile()
	if err != nil {
		m.logger.Warn("open log file (will retry)", "path", src.Path, "error", err)
	}

	reader := func() *bufio.Reader {
		if f == nil {
			return nil
		}
		return bufio.NewReaderSize(f, 65536)
	}

	var rd *bufio.Reader
	if f != nil {
		if err := watcher.Add(src.Path); err != nil {
			m.logger.Warn("watch file failed", "path", src.Path, "error", err)
		}
		rd = bufio.NewReaderSize(f, 65536)
	}

	drainReader := func() {
		if rd == nil {
			return
		}
		for {
			line, err := rd.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				select {
				case m.lines <- LogLine{Source: src.Path, Tags: src.Tags, Line: line, Time: time.Now()}:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				break
			}
		}
	}

	reopenTicker := time.NewTicker(5 * time.Second)
	defer reopenTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// something was written, drain whatever's new
			if event.Has(fsnotify.Write) && event.Name == src.Path {
				drainReader()
			}
			// file got rotated — wait briefly and reopen
			if (event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Create)) &&
				event.Name == src.Path {
				if f != nil {
					f.Close()
				}
				time.Sleep(200 * time.Millisecond) // wait for new file to appear
				f, err = openFile()
				if err != nil {
					m.logger.Warn("reopen after rotation", "path", src.Path, "error", err)
					f = nil
					rd = nil
					continue
				}
				_ = watcher.Add(src.Path)
				rd = reader()
				m.logger.Info("log file rotated, reopened", "path", src.Path)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			m.logger.Warn("watcher error", "error", err)

		case <-reopenTicker.C:
			// retry files that didn't exist when we started
			if f == nil {
				f, err = openFile()
				if err == nil {
					_ = watcher.Add(src.Path)
					rd = reader()
					m.logger.Info("opened previously missing log file", "path", src.Path)
				}
			}
		}
	}
}

// Docker log streaming

// dockerClient talks to the Docker daemon over its Unix socket. The Docker API is HTTP
// but over a Unix socket instead of TCP, which requires this transport dance.
type dockerClient struct {
	socket string
	hc     *http.Client
}

func newDockerClient(socket string) *dockerClient {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &dockerClient{
		socket: socket,
		hc:     &http.Client{Transport: transport, Timeout: 0},
	}
}

func (d *dockerClient) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost"+path, nil)
	if err != nil {
		return nil, err
	}
	return d.hc.Do(req)
}

type dockerContainer struct {
	ID    string `json:"Id"`
	Names []string
}

func (m *Manager) runDockerMonitor(ctx context.Context) {
	dc := newDockerClient(m.dockerSocket)
	m.logger.Info("docker log monitor started", "socket", m.dockerSocket)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	discover := func() {
		resp, err := dc.get(ctx, "/containers/json")
		if err != nil {
			m.logger.Warn("list containers", "error", err)
			return
		}
		defer resp.Body.Close()
		var containers []dockerContainer
		if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
			return
		}
		for _, c := range containers {
			if _, loaded := m.dockerContainers.LoadOrStore(c.ID, struct{}{}); !loaded {
				name := c.ID[:12]
				if len(c.Names) > 0 {
					name = strings.TrimPrefix(c.Names[0], "/")
				}
				go m.streamDockerLogs(ctx, dc, c.ID, name)
			}
		}
	}

	discover()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			discover()
		}
	}
}

func (m *Manager) streamDockerLogs(ctx context.Context, dc *dockerClient, containerID, containerName string) {
	defer m.dockerContainers.Delete(containerID)

	source := "docker:" + containerName
	path := fmt.Sprintf("/containers/%s/logs?follow=true&stdout=true&stderr=true&timestamps=true", url.PathEscape(containerID))

	resp, err := dc.get(ctx, path)
	if err != nil {
		m.logger.Warn("stream docker logs", "container", containerName, "error", err)
		return
	}
	defer resp.Body.Close()

	m.logger.Info("streaming docker logs", "container", containerName)

	// Docker's log stream uses a multiplexed framing format: each frame starts with an 8-byte header.
	// The header is [stream_type(1 byte), 0, 0, 0, frame_size(4 bytes big-endian)]. Stdout=1, stderr=2.
	// This is just how Docker decided to do it.
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(resp.Body, header); err != nil {
			if err != io.EOF && ctx.Err() == nil {
				m.logger.Warn("docker log stream ended", "container", containerName, "error", err)
			}
			return
		}
		// 1=stdout, 2=stderr — we don't care which
		frameSize := binary.BigEndian.Uint32(header[4:8])
		if frameSize == 0 {
			continue
		}
		frame := make([]byte, frameSize)
		if _, err := io.ReadFull(resp.Body, frame); err != nil {
			return
		}
		lines := strings.Split(strings.TrimRight(string(frame), "\n"), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Docker prepends a nanosecond-precision timestamp when timestamps=true — strip it
			if len(line) > 31 && line[30] == ' ' {
				line = line[31:]
			}
			if line == "" {
				continue
			}
			select {
			case m.lines <- LogLine{Source: source, Tags: m.dockerTags, Line: line, Time: time.Now()}:
			case <-ctx.Done():
				return
			}
		}
	}
}
