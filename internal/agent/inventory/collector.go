// Package inventory scrapes system info from /proc, /etc, and command output for periodic upload.
package inventory

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/VRCDN/guiltyspark/internal/common/models"
)

// Collector knows how to pull everything interesting off a Linux machine.
type Collector struct {
	agentID string
	logger  *slog.Logger
}

// New creates an inventory Collector.
func New(agentID string, logger *slog.Logger) *Collector {
	return &Collector{agentID: agentID, logger: logger}
}

// Collect runs all the scrapers and returns the result. Individual failures just leave fields empty.
func (c *Collector) Collect(ctx context.Context) (*models.SystemInventory, error) {
	inv := &models.SystemInventory{
		AgentID:     c.agentID,
		CollectedAt: time.Now().UTC(),
	}

	inv.OS = c.collectOS()
	inv.Hardware = c.collectHardware()
	inv.Network = c.collectNetwork()
	inv.Users = c.collectUsers()
	inv.Packages = c.collectPackages(ctx)
	inv.Services = c.collectServices(ctx)

	return inv, nil
}

// OS

func (c *Collector) collectOS() models.OSInfo {
	info := models.OSInfo{
		Architecture:  runtime.GOARCH,
		Hostname:      hostname(),
		Uptime:        uptime(),
		KernelVersion: kernelVersion(),
	}

	// /etc/os-release is the standard place for distro info on modern Linux
	f, err := os.Open("/etc/os-release")
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
			switch key {
			case "NAME":
				info.Name = val
			case "VERSION":
				info.Version = val
			case "VERSION_ID":
				if info.Version == "" {
					info.Version = val
				}
			case "PRETTY_NAME":
				if info.Name == "" {
					info.Name = val
				}
			}
		}
	}

	if info.Name == "" {
		info.Name = "Linux"
	}
	return info
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func uptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) == 0 {
		return 0
	}
	secs, _ := strconv.ParseFloat(parts[0], 64)
	return int64(secs)
}

func kernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Hardware

func (c *Collector) collectHardware() models.HardwareInfo {
	info := models.HardwareInfo{}

	// /proc/cpuinfo — line-by-line, not pretty, but it's what we've got
	cpuF, err := os.Open("/proc/cpuinfo")
	if err == nil {
		defer cpuF.Close()
		scanner := bufio.NewScanner(cpuF)
		physIDs := make(map[string]struct{})
		for scanner.Scan() {
			line := scanner.Text()
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			switch key {
			case "model name":
				if info.CPUModel == "" {
					info.CPUModel = val
				}
			case "processor":
				info.CPUThreads++
			case "physical id":
				physIDs[val] = struct{}{}
			}
		}
		info.CPUCores = len(physIDs)
		if info.CPUCores == 0 {
			info.CPUCores = info.CPUThreads
		}
	}

	// /proc/meminfo gives us total and available memory
	memF, err := os.Open("/proc/meminfo")
	if err == nil {
		defer memF.Close()
		scanner := bufio.NewScanner(memF)
		for scanner.Scan() {
			line := scanner.Text()
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			// values are in kB, convert to bytes
			var kb int64
			fmt.Sscanf(val, "%d", &kb)
			switch key {
			case "MemTotal":
				info.MemoryTotal = kb * 1024
			case "MemAvailable":
				info.MemoryFree = kb * 1024
			}
		}
	}

	// statfs on / gives us disk total and available space
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err == nil {
		info.DiskTotal = int64(st.Blocks) * st.Bsize
		info.DiskFree = int64(st.Bavail) * st.Bsize
	}

	return info
}

// Network

func (c *Collector) collectNetwork() models.NetworkInfo {
	info := models.NetworkInfo{Hostname: hostname()}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			ni := models.NetworkInterface{
				Name:       iface.Name,
				MACAddress: iface.HardwareAddr.String(),
				IsUp:       iface.Flags&net.FlagUp != 0,
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ni.IPAddresses = append(ni.IPAddresses, addr.String())
			}
			info.Interfaces = append(info.Interfaces, ni)
		}
	}

	// grab DNS servers from /etc/resolv.conf — not foolproof on systems using systemd-resolved, but works most places
	resolvF, err := os.Open("/etc/resolv.conf")
	if err == nil {
		defer resolvF.Close()
		scanner := bufio.NewScanner(resolvF)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "nameserver ") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
				info.DNSServers = append(info.DNSServers, ns)
			}
		}
	}

	return info
}

// Packages

func (c *Collector) collectPackages(ctx context.Context) []models.PackageInfo {
	var pkgs []models.PackageInfo

	// try dpkg first (Debian/Ubuntu)
	if out, err := runCmd(ctx, "dpkg-query", "--show", "--showformat=${Package}\t${Version}\n"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), "\t", 2)
			if len(parts) == 2 && parts[0] != "" {
				pkgs = append(pkgs, models.PackageInfo{Name: parts[0], Version: parts[1], Manager: "apt"})
			}
		}
		if len(pkgs) > 0 {
			return pkgs
		}
	}

	// try rpm if dpkg came up empty
	if out, err := runCmd(ctx, "rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			parts := strings.SplitN(scanner.Text(), "\t", 2)
			if len(parts) == 2 && parts[0] != "" {
				pkgs = append(pkgs, models.PackageInfo{Name: parts[0], Version: parts[1], Manager: "rpm"})
			}
		}
		if len(pkgs) > 0 {
			return pkgs
		}
	}

	// Arch uses pacman — output is just "name version" per line which is refreshingly simple
	if out, err := runCmd(ctx, "pacman", "-Q"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) == 2 {
				pkgs = append(pkgs, models.PackageInfo{Name: parts[0], Version: parts[1], Manager: "pacman"})
			}
		}
		if len(pkgs) > 0 {
			return pkgs
		}
	}

	// Alpine's apk — mashes name and version into one string like "musl-1.2.4", see splitApkLine
	if out, err := runCmd(ctx, "apk", "info", "-v"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			name, ver := splitApkLine(line)
			pkgs = append(pkgs, models.PackageInfo{Name: name, Version: ver, Manager: "apk"})
		}
		if len(pkgs) > 0 {
			return pkgs
		}
	}

	// snap can live alongside any of the above
	if out, err := runCmd(ctx, "snap", "list", "--unicode=never"); err == nil {
		lines := strings.Split(out, "\n")
		for _, line := range lines[1:] { // skip the header row
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pkgs = append(pkgs, models.PackageInfo{Name: fields[0], Version: fields[1], Manager: "snap"})
			}
		}
	}

	// flatpak can also coexist with anything
	if out, err := runCmd(ctx, "flatpak", "list", "--columns=application,version"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) >= 1 {
				ver := ""
				if len(parts) >= 2 {
					ver = parts[1]
				}
				pkgs = append(pkgs, models.PackageInfo{Name: parts[0], Version: ver, Manager: "flatpak"})
			}
		}
	}

	return pkgs
}

// Services

func (c *Collector) collectServices(ctx context.Context) []models.ServiceInfo {
	var services []models.ServiceInfo

	// try systemd first
	out, err := runCmd(ctx, "systemctl", "list-units", "--type=service", "--no-pager", "--no-legend", "--all")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			name := strings.TrimSuffix(fields[0], ".service")
			activeState := fields[2] // "active" or "inactive"
			subState := fields[3]    // "running", "exited", "failed", etc.

			status := subState
			if activeState == "inactive" {
				status = "stopped"
			}

			// separate call per service to check if it's enabled — slow, but there's no bulk option
			enabled := false
			if enOut, err := runCmd(ctx, "systemctl", "is-enabled", fields[0]); err == nil {
				enabled = strings.TrimSpace(enOut) == "enabled"
			}

			services = append(services, models.ServiceInfo{
				Name:    name,
				Status:  status,
				Enabled: enabled,
			})
		}
	}

	if len(services) > 0 {
		return services
	}

	// fall back to OpenRC if systemd wasn't found
	if out, err := runCmd(ctx, "rc-status", "-a", "--nocolor"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			// rc-status output looks like " sshd                      [ started ]"
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "Runlevel:") {
				continue
			}
			// split on whitespace — service names won't have spaces
			parts := strings.Fields(trimmed)
			if len(parts) < 2 {
				continue
			}
			name := parts[0]
			// status sits in brackets at the end: [ started ] / [ stopped ]
			status := strings.Trim(strings.Join(parts[1:], " "), "[] ")
			// rc-update show tells us what's enabled — grep for our service name
			enabled := false
			if enOut, err2 := runCmd(ctx, "rc-update", "show"); err2 == nil {
				for _, l := range strings.Split(enOut, "\n") {
					if strings.Contains(l, name+" ") || strings.HasPrefix(strings.TrimSpace(l), name+" ") {
						enabled = true
						break
					}
				}
			}
			services = append(services, models.ServiceInfo{
				Name:    name,
				Status:  status,
				Enabled: enabled,
			})
		}
	}

	return services
}

// Users

func (c *Collector) collectUsers() []models.UserInfo {
	var users []models.UserInfo

	f, err := os.Open("/etc/passwd")
	if err != nil {
		return users
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		gid, _ := strconv.Atoi(parts[3])
		users = append(users, models.UserInfo{
			Username: parts[0],
			UID:      uid,
			GID:      gid,
			HomeDir:  parts[5],
			Shell:    parts[6],
			IsSystem: uid < 1000 && uid != 0, // 0 = root (special), <1000 = system
		})
	}
	return users
}

// Helpers

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// splitApkLine splits an apk string like "ca-certificates-20240203" into name and version.
// Package names can contain hyphens, so we can't just split on the last one. Instead we find
// the last hyphen immediately followed by a digit, since version numbers always start with one.
// Annoying, but that's apk's format.
func splitApkLine(s string) (name, version string) {
	for i := len(s) - 1; i > 0; i-- {
		if s[i] == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}
