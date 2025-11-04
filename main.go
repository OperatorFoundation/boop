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
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/faiface/beep"
	"github.com/faiface/beep/speaker"
	"github.com/grandcat/zeroconf"
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

var (
	// Catppuccin Mocha color palette
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))            // Green
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#89b4fa"))            // Blue
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6c7086"))            // Surface2
	userStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#89dceb")).Bold(true) // Sky
	hostStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#cba6f7"))            // Mauve
	messageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#cdd6f4"))            // Text
	onlineStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#a6e3a1"))            // Green
	offlineStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#f38ba8"))            // Red
	titleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#cba6f7")).Bold(true)
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

type Machine struct {
	Name   string
	User   string
	IP     string
	Online bool
}

type BoopMessage struct {
	From    string
	Message string
	Time    time.Time
}

type model struct {
	machines []Machine
	boops    []BoopMessage
	hostname string
	myIP     string
	port     int
	err      error
}

type tickMsg time.Time
type boopReceivedMsg BoopMessage
type machinesUpdateMsg []Machine

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

	cmd := "tailscale"
	args := []string{"status", "--json"}

	// Use exec.CommandContext but we need os/exec
	execCmd := exec.Command(cmd, args...)
	execCmd = exec.CommandContext(ctx, cmd, args...)
	output, err := execCmd.Output()
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
		Volume:   0.5,
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
	Volume   float64
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

func initialModel() model {
	return model{
		machines: []Machine{},
		boops:    []BoopMessage{},
		port:     boopPort,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		updateMachinesCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Minute, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func updateMachinesCmd() tea.Cmd {
	return func() tea.Msg {
		status, err := getTailscaleStatus()
		if err != nil {
			return machinesUpdateMsg([]Machine{})
		}

		var machines []Machine

		// Add self
		if status.Self.DNSName != "" || status.Self.HostName != "" {
			name := strings.TrimSuffix(status.Self.DNSName, ".")
			if name == "" {
				name = status.Self.HostName
			}
			user := getUserName(status, status.Self.UserID)
			ip := ""
			if len(status.Self.TailscaleIPs) > 0 {
				ip = status.Self.TailscaleIPs[0]
			}
			machines = append(machines, Machine{
				Name:   name,
				User:   user,
				IP:     ip,
				Online: true,
			})
		}

		// Add peers
		for _, peer := range status.Peer {
			name := strings.TrimSuffix(peer.DNSName, ".")
			if name == "" {
				name = peer.HostName
			}
			user := peer.UserProfile.LoginName
			if user == "" {
				user = peer.UserProfile.DisplayName
			}
			if user == "" {
				user = getUserName(status, peer.UserID)
			}
			ip := ""
			if len(peer.TailscaleIPs) > 0 {
				ip = peer.TailscaleIPs[0]
			}
			machines = append(machines, Machine{
				Name:   name,
				User:   user,
				IP:     ip,
				Online: peer.Online,
			})
		}

		// Sort by name
		sort.Slice(machines, func(i, j int) bool {
			return machines[i].Name < machines[j].Name
		})

		return machinesUpdateMsg(machines)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			os.Exit(0)
		}

	case tickMsg:
		return m, tea.Batch(tickCmd(), updateMachinesCmd())

	case machinesUpdateMsg:
		m.machines = msg
		return m, nil

	case boopReceivedMsg:
		m.boops = append(m.boops, BoopMessage(msg))
		// Keep only last 10 boops
		if len(m.boops) > 10 {
			m.boops = m.boops[len(m.boops)-10:]
		}
		return m, nil

	case error:
		m.err = msg
		return m, nil
	}

	return m, nil
}

func (m model) View() string {
	var s string

	// Machines section
	if len(m.machines) == 0 {
		s += mutedStyle.Render("No machines found...") + "\n"
	} else {
		for _, machine := range m.machines {
			status := "●"
			statusStyle := offlineStyle
			if machine.Online {
				statusStyle = onlineStyle
			}

			// Use blue dot for current user
			if machine.IP == m.myIP {
				statusStyle = infoStyle
			}

			// Extract short hostname (before first dot)
			shortName := machine.Name
			if idx := strings.Index(shortName, "."); idx != -1 {
				shortName = shortName[:idx]
			}

			if machine.User != "" {
				s += fmt.Sprintf("%s %s%s%s\n",
					statusStyle.Render(status),
					userStyle.Render(machine.User),
					mutedStyle.Render("@"),
					hostStyle.Render(shortName))
			} else {
				s += fmt.Sprintf("%s %s\n",
					statusStyle.Render(status),
					hostStyle.Render(shortName))
			}
		}
	}

	// Boops section
	s += "\n" + titleStyle.Render("Recent boops:") + "\n"
	if len(m.boops) == 0 {
		s += mutedStyle.Render("  No boops yet...") + "\n"
	} else {
		for _, boop := range m.boops {
			timeStr := boop.Time.Format("15:04:05")
			s += fmt.Sprintf("  %s %s",
				mutedStyle.Render(timeStr),
				successStyle.Render(boop.From))
			if boop.Message != "" {
				s += fmt.Sprintf(" %s", messageStyle.Render(boop.Message))
			}
			s += "\n"
		}
	}

	s += "\n" + mutedStyle.Render("Press q or ctrl+c to quit")

	return s
}

func listenForBoops() error {
	// Get hostname and my IP
	hostname := getHostname()
	var myIP string
	status, err := getTailscaleStatus()
	if err == nil {
		dnsName := strings.TrimSuffix(status.Self.DNSName, ".")
		if dnsName != "" {
			hostname = dnsName
		}
		if len(status.Self.TailscaleIPs) > 0 {
			myIP = status.Self.TailscaleIPs[0]
		}
	}

	// Start UDP listeners in background
	boopChan := make(chan BoopMessage, 10)
	go startUDPListeners(boopChan)

	// Start mDNS
	server, _ := zeroconf.Register(hostname, serviceType, "local.", boopPort, []string{"txtv=0"}, nil)
	if server != nil {
		defer server.Shutdown()
	}

	// Create TUI model
	m := initialModel()
	m.hostname = hostname
	m.myIP = myIP

	// Start Bubble Tea program with alt screen
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Forward boop messages to the program
	go func() {
		for boop := range boopChan {
			p.Send(boopReceivedMsg(boop))
			go playBoopSound()
		}
	}()

	// Run the program
	p.Run()
	return nil
}

func startUDPListeners(boopChan chan<- BoopMessage) {
	// Listen on IPv4
	addr4 := &net.UDPAddr{
		Port: boopPort,
		IP:   net.IPv4zero,
	}
	conn4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		return
	}
	defer conn4.Close()

	// Listen on IPv6
	addr6 := &net.UDPAddr{
		Port: boopPort,
		IP:   net.IPv6zero,
	}
	conn6, _ := net.ListenUDP("udp6", addr6)
	if conn6 != nil {
		defer conn6.Close()
		go handleUDPConnection(conn6, boopChan)
	}

	handleUDPConnection(conn4, boopChan)
}

func handleUDPConnection(conn *net.UDPConn, boopChan chan<- BoopMessage) {
	buffer := make([]byte, 1024)

	for {
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

		// Normalize IPv6 addresses
		if idx := strings.Index(senderIP, "%"); idx != -1 {
			senderIP = senderIP[:idx]
		}

		// Get Tailscale info
		from := senderIP
		tsInfo := getTailscaleInfo(senderIP)
		if tsInfo != nil {
			if tsInfo.User != "" {
				from = fmt.Sprintf("%s@%s", tsInfo.User, tsInfo.Name)
			} else {
				from = tsInfo.Name
			}
		}

		boopChan <- BoopMessage{
			From:    from,
			Message: message,
			Time:    time.Now(),
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
