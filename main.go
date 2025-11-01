package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/faiface/beep"
	"github.com/faiface/beep/speaker"
	"github.com/grandcat/zeroconf"
)

var (
	// Catppuccin Mocha color palette
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))            // Green
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa"))            // Blue
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6c7086"))            // Surface2
	userStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#89dceb")).Bold(true) // Sky
	hostStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#cba6f7"))            // Mauve
	messageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#cdd6f4"))            // Text
)

const (
	version     = "0.4.0"
	boopPort    = 9999
	serviceType = "_boop._udp"
)

var (
	speakerInitialized bool
	speakerMutex       sync.Mutex
)

// TailscaleStatus represents the JSON output from tailscale status
type TailscaleStatus struct {
	Self struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		UserID       any      `json:"UserID"`
		UserProfile  struct {
			LoginName   string `json:"LoginName"`
			DisplayName string `json:"DisplayName"`
		} `json:"UserProfile"`
	} `json:"Self"`
	Peer map[string]struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		UserID       any      `json:"UserID"`
		Online       bool     `json:"Online"`
		UserProfile  struct {
			LoginName   string `json:"LoginName"`
			DisplayName string `json:"DisplayName"`
		} `json:"UserProfile"`
	} `json:"Peer"`
	User map[string]struct {
		ID          int    `json:"ID"`
		LoginName   string `json:"LoginName"`
		DisplayName string `json:"DisplayName"`
	} `json:"User"`
}

type TailscaleInfo struct {
	Hostname string
	Name     string
	User     string
	Online   bool
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func getTailscaleStatus() (*TailscaleStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "tailscale", "status", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var status TailscaleStatus
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

func getUserName(status *TailscaleStatus, userID any) string {
	if userID == nil {
		return ""
	}

	// Convert userID to string for map lookup
	userIDStr := ""
	switch v := userID.(type) {
	case float64:
		userIDStr = fmt.Sprintf("%d", int(v))
	case int:
		userIDStr = fmt.Sprintf("%d", v)
	case string:
		userIDStr = v
	default:
		return ""
	}

	if user, ok := status.User[userIDStr]; ok {
		if user.LoginName != "" {
			return user.LoginName
		}
		return user.DisplayName
	}

	return ""
}

func getTailscaleInfo(ipAddress string) *TailscaleInfo {
	status, err := getTailscaleStatus()
	if err != nil {
		return nil
	}

	// Check peers
	for _, peer := range status.Peer {
		for _, ip := range peer.TailscaleIPs {
			if ip == ipAddress {
				name := strings.TrimSuffix(peer.DNSName, ".")
				if name == "" {
					name = peer.HostName
				}
				// Try UserProfile first (regular Tailscale)
				user := peer.UserProfile.LoginName
				if user == "" {
					user = peer.UserProfile.DisplayName
				}
				// Fall back to User map (Headscale)
				if user == "" {
					user = getUserName(status, peer.UserID)
				}
				return &TailscaleInfo{
					Hostname: peer.HostName,
					Name:     name,
					User:     user,
					Online:   peer.Online,
				}
			}
		}
	}

	// Check me
	for _, ip := range status.Self.TailscaleIPs {
		if ip == ipAddress {
			name := strings.TrimSuffix(status.Self.DNSName, ".")
			if name == "" {
				name = status.Self.HostName
			}
			// Try UserProfile first (regular Tailscale)
			user := status.Self.UserProfile.LoginName
			if user == "" {
				user = status.Self.UserProfile.DisplayName
			}
			// Fall back to User map (Headscale)
			if user == "" {
				user = getUserName(status, status.Self.UserID)
			}
			return &TailscaleInfo{
				Hostname: status.Self.HostName,
				Name:     name,
				User:     user,
				Online:   true,
			}
		}
	}

	return nil
}

func resolveTailscaleHost(target string) (string, error) {
	status, err := getTailscaleStatus()
	if err != nil {
		return "", err
	}

	targetLower := strings.ToLower(target)

	// Check me first
	meDNSName := strings.ToLower(strings.TrimSuffix(status.Self.DNSName, "."))
	meHostname := strings.ToLower(status.Self.HostName)
	meMachineName := ""
	if idx := strings.Index(meDNSName, "."); idx != -1 {
		meMachineName = meDNSName[:idx]
	}

	if meDNSName == targetLower || meHostname == targetLower || meMachineName == targetLower {
		if len(status.Self.TailscaleIPs) > 0 {
			return status.Self.TailscaleIPs[0], nil
		}
	}

	// Check peers
	for _, peer := range status.Peer {
		dnsName := strings.ToLower(strings.TrimSuffix(peer.DNSName, "."))
		hostname := strings.ToLower(peer.HostName)
		machineName := ""
		if idx := strings.Index(dnsName, "."); idx != -1 {
			machineName = dnsName[:idx]
		}

		if dnsName == targetLower || hostname == targetLower || machineName == targetLower {
			if len(peer.TailscaleIPs) > 0 {
				return peer.TailscaleIPs[0], nil
			}
		}
	}

	return "", fmt.Errorf("host not found in tailscale status")
}

func playBoopSound() {
	// Initialize speaker once
	speakerMutex.Lock()
	if !speakerInitialized {
		sr := beep.SampleRate(44100)
		speaker.Init(sr, sr.N(time.Millisecond*100))
		speakerInitialized = true
	}
	speakerMutex.Unlock()

	// Generate the boop sound
	sr := beep.SampleRate(44100)
	duration := sr.N(time.Millisecond * 150)

	// Create a frequency sweep from 500Hz to 300Hz
	sweepStreamer := &FrequencySweep{
		SampleRate: sr,
		StartFreq:  500,
		EndFreq:    300,
		Duration:   duration,
		Position:   0,
	}

	// Apply envelope (quick attack, longer decay)
	envelope := &Envelope{
		Streamer:    beep.Take(duration, sweepStreamer),
		AttackTime:  sr.N(time.Millisecond * 10),
		DecayTime:   sr.N(time.Millisecond * 80),
		TotalLength: duration,
		Position:    0,
	}

	// Reduce volume slightly
	volume := &VolumeControl{
		Streamer: envelope,
		Volume:   0.5, // 50% volume
	}

	speaker.Play(volume)
}

// FrequencySweep generates a sine wave that sweeps from one frequency to another
type FrequencySweep struct {
	SampleRate beep.SampleRate
	StartFreq  float64
	EndFreq    float64
	Duration   int
	Position   int
}

func (s *FrequencySweep) Stream(samples [][2]float64) (n int, ok bool) {
	for i := range samples {
		if s.Position >= s.Duration {
			return i, false
		}

		// Calculate current frequency (linear interpolation)
		progress := float64(s.Position) / float64(s.Duration)
		freq := s.StartFreq + (s.EndFreq-s.StartFreq)*progress

		// Generate sine wave at current frequency
		phase := 2 * math.Pi * freq * float64(s.Position) / float64(s.SampleRate)
		sample := math.Sin(phase)

		samples[i][0] = sample
		samples[i][1] = sample
		s.Position++
		n++
	}
	return n, true
}

func (s *FrequencySweep) Err() error {
	return nil
}

// Envelope applies an attack-decay envelope to the audio
type Envelope struct {
	Streamer    beep.Streamer
	AttackTime  int
	DecayTime   int
	TotalLength int
	Position    int
}

func (e *Envelope) Stream(samples [][2]float64) (n int, ok bool) {
	n, ok = e.Streamer.Stream(samples)

	for i := 0; i < n; i++ {
		if e.Position >= e.TotalLength {
			return i, false
		}

		var gain float64
		if e.Position < e.AttackTime {
			// Attack phase - fade in
			gain = float64(e.Position) / float64(e.AttackTime)
		} else if e.Position > e.TotalLength-e.DecayTime {
			// Decay phase - fade out
			remaining := e.TotalLength - e.Position
			gain = float64(remaining) / float64(e.DecayTime)
		} else {
			// Sustain phase
			gain = 1.0
		}

		samples[i][0] *= gain
		samples[i][1] *= gain
		e.Position++
	}

	return n, ok
}

func (e *Envelope) Err() error {
	return e.Streamer.Err()
}

// VolumeControl applies volume control to the audio
type VolumeControl struct {
	Streamer beep.Streamer
	Volume   float64 // 0.0 to 1.0
}

func (v *VolumeControl) Stream(samples [][2]float64) (n int, ok bool) {
	n, ok = v.Streamer.Stream(samples)
	for i := 0; i < n; i++ {
		samples[i][0] *= v.Volume
		samples[i][1] *= v.Volume
	}
	return n, ok
}

func (v *VolumeControl) Err() error {
	return v.Streamer.Err()
}

func listenForBoops() error {
	// Get hostname (preferring Tailscale machine name)
	hostname := getHostname()
	status, err := getTailscaleStatus()
	if err == nil {
		dnsName := strings.TrimSuffix(status.Self.DNSName, ".")
		if dnsName != "" {
			hostname = dnsName
		}
	}

	// Listen on IPv4
	addr4 := &net.UDPAddr{
		Port: boopPort,
		IP:   net.IPv4zero,
	}
	conn4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		return fmt.Errorf("failed to listen on IPv4: %w", err)
	}
	defer conn4.Close()

	// Listen on IPv6
	addr6 := &net.UDPAddr{
		Port: boopPort,
		IP:   net.IPv6zero,
	}
	conn6, err := net.ListenUDP("udp6", addr6)
	if err != nil {
		fmt.Printf("%s %s\n",
			infoStyle.Render("Listening on port"),
			infoStyle.Bold(true).Render(fmt.Sprintf("%d (IPv4 only)", boopPort)))
	} else {
		defer conn6.Close()
		fmt.Printf("%s %s\n",
			infoStyle.Render("Listening on port"),
			infoStyle.Bold(true).Render(fmt.Sprintf("%d (IPv4 and IPv6)", boopPort)))
	}

	// Start mDNS advertisement
	server, err := zeroconf.Register(hostname, serviceType, "local.", boopPort, []string{"txtv=0"}, nil)
	if err != nil {
		fmt.Printf("%s %v\n", mutedStyle.Render("Warning: Could not start mDNS advertisement:"), err)
	} else {
		defer server.Shutdown()
		fmt.Printf("%s %s %s\n",
			infoStyle.Render("Advertising as"),
			hostStyle.Render(hostname),
			mutedStyle.Render("via mDNS"))
	}

	// Channel to coordinate shutdown
	done := make(chan bool)

	// Handle IPv4 packets
	go handleConnection(conn4, done)

	// Handle IPv6 packets if available
	if conn6 != nil {
		go handleConnection(conn6, done)
	}

	// Block forever - let default signal handling kill the process
	select {}
}

func handleConnection(conn *net.UDPConn, done chan bool) {
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	for {
		select {
		case <-done:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			message := strings.TrimSpace(string(buffer[:n]))
			senderIP := addr.IP.String()

			// Normalize IPv6 addresses (remove zone identifier if present)
			if idx := strings.Index(senderIP, "%"); idx != -1 {
				senderIP = senderIP[:idx]
			}

			// Get Tailscale info
			var senderDisplay string
			tsInfo := getTailscaleInfo(senderIP)
			if tsInfo != nil {
				if tsInfo.User != "" {
					senderDisplay = fmt.Sprintf("%s@%s [%s]", tsInfo.User, tsInfo.Name, senderIP)
				} else {
					senderDisplay = fmt.Sprintf("%s [%s]", tsInfo.Name, senderIP)
				}
			} else {
				// Try reverse DNS
				names, err := net.LookupAddr(senderIP)
				if err == nil && len(names) > 0 {
					senderDisplay = fmt.Sprintf("%s [%s]", names[0], senderIP)
				} else {
					senderDisplay = fmt.Sprintf("[%s]", senderIP)
				}
			}

			// Play sound
			go playBoopSound()

			// Display message with styling
			if tsInfo != nil && tsInfo.User != "" {
				fmt.Printf("%s %s%s%s %s\n",
					successStyle.Render("Boop from"),
					userStyle.Render(tsInfo.User),
					mutedStyle.Render("@"),
					hostStyle.Render(tsInfo.Name),
					mutedStyle.Render(fmt.Sprintf("[%s]", senderIP)))
			} else {
				fmt.Printf("%s %s\n",
					successStyle.Render("Boop from"),
					senderDisplay)
			}
			if message != "" {
				fmt.Printf("  %s\n", messageStyle.Render(message))
			}
		}
	}
}

func sendBoop(target, message string) error {
	// Special case: "me" means send to myself
	if strings.ToLower(target) == "me" {
		status, err := getTailscaleStatus()
		if err == nil && len(status.Self.TailscaleIPs) > 0 {
			target = status.Self.TailscaleIPs[0]
		} else {
			target = "localhost"
		}
	}

	// Try DNS resolution first
	addrs, err := net.LookupHost(target)
	if err != nil {
		// DNS failed, try Tailscale resolution
		tailscaleIP, err := resolveTailscaleHost(target)
		if err != nil {
			return fmt.Errorf("Could not resolve host: %s", target)
		}
		addrs = []string{tailscaleIP}
	}

	if len(addrs) == 0 {
		return fmt.Errorf("Could not resolve host: %s", target)
	}

	// Use the first address
	addr := addrs[0]

	// Determine if IPv6 or IPv4
	ip := net.ParseIP(addr)
	var conn *net.UDPConn
	var udpAddr *net.UDPAddr

	if ip.To4() != nil {
		// IPv4
		udpAddr = &net.UDPAddr{
			IP:   ip,
			Port: boopPort,
		}
		conn, err = net.DialUDP("udp4", nil, udpAddr)
	} else {
		// IPv6
		udpAddr = &net.UDPAddr{
			IP:   ip,
			Port: boopPort,
		}
		conn, err = net.DialUDP("udp6", nil, udpAddr)
	}

	if err != nil {
		return fmt.Errorf("Error creating connection: %w", err)
	}
	defer conn.Close()

	// Send the boop
	_, err = conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("Error sending boop: %w", err)
	}

	// Get target info for display
	tsInfo := getTailscaleInfo(addr)

	if tsInfo != nil && tsInfo.User != "" {
		fmt.Printf("%s %s%s%s\n",
			successStyle.Render("Boop sent to"),
			userStyle.Render(tsInfo.User),
			mutedStyle.Render("@"),
			hostStyle.Render(tsInfo.Name))
	} else if tsInfo != nil {
		fmt.Printf("%s %s\n",
			successStyle.Render("Boop sent to"),
			hostStyle.Render(tsInfo.Name))
	} else {
		fmt.Printf("%s %s\n",
			successStyle.Render("Boop sent to"),
			target)
	}

	if message != "" {
		fmt.Printf("  %s\n", messageStyle.Render(message))
	}

	return nil
}

func main() {
	listen := flag.Bool("listen", false, "Listen for incoming boop messages")
	flag.Parse()

	if *listen {
		if err := listenForBoops(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if flag.NArg() > 0 {
		target := flag.Arg(0)
		message := strings.Join(flag.Args()[1:], " ")
		if err := sendBoop(target, message); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  boop --listen              Listen for boop messages\n")
		fmt.Fprintf(os.Stderr, "  boop <host> [message]      Send a boop to a host\n")
		os.Exit(1)
	}
}
