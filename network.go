package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/grandcat/zeroconf"
)

const (
	boopPort    = 9999
	serviceType = "_boop._udp"
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

	for _, peer := range status.Peer {
		for _, ip := range peer.TailscaleIPs {
			if ip == ipAddress {
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
				return &TailscaleInfo{
					Hostname: peer.HostName,
					Name:     name,
					User:     user,
					Online:   peer.Online,
				}
			}
		}
	}

	for _, ip := range status.Self.TailscaleIPs {
		if ip == ipAddress {
			name := strings.TrimSuffix(status.Self.DNSName, ".")
			if name == "" {
				name = status.Self.HostName
			}
			user := status.Self.UserProfile.LoginName
			if user == "" {
				user = status.Self.UserProfile.DisplayName
			}
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

func sendBoop(target, message string) error {
	if strings.ToLower(target) == "me" {
		status, err := getTailscaleStatus()
		if err == nil && len(status.Self.TailscaleIPs) > 0 {
			target = status.Self.TailscaleIPs[0]
		} else {
			target = "localhost"
		}
	}

	addrs, err := net.LookupHost(target)
	if err != nil {
		tailscaleIP, err := resolveTailscaleHost(target)
		if err != nil {
			return fmt.Errorf("Could not resolve host: %s", target)
		}
		addrs = []string{tailscaleIP}
	}

	if len(addrs) == 0 {
		return fmt.Errorf("Could not resolve host: %s", target)
	}

	addr := addrs[0]
	ip := net.ParseIP(addr)
	var conn *net.UDPConn
	var udpAddr *net.UDPAddr

	if ip.To4() != nil {
		udpAddr = &net.UDPAddr{IP: ip, Port: boopPort}
		conn, err = net.DialUDP("udp4", nil, udpAddr)
	} else {
		udpAddr = &net.UDPAddr{IP: ip, Port: boopPort}
		conn, err = net.DialUDP("udp6", nil, udpAddr)
	}

	if err != nil {
		return fmt.Errorf("Error creating connection: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("Error sending boop: %w", err)
	}

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

// TUI Model
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

	if len(m.machines) == 0 {
		s += mutedStyle.Render("No machines found...") + "\n"
	} else {
		for _, machine := range m.machines {
			status := "●"
			statusStyle := offlineStyle
			if machine.Online {
				statusStyle = onlineStyle
			}

			if machine.IP == m.myIP {
				statusStyle = infoStyle
			}

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

	boopChan := make(chan BoopMessage, 10)
	go startUDPListeners(boopChan)

	server, _ := zeroconf.Register(hostname, serviceType, "local.", boopPort, []string{"txtv=0"}, nil)
	if server != nil {
		defer server.Shutdown()
	}

	m := initialModel()
	m.hostname = hostname
	m.myIP = myIP

	p := tea.NewProgram(m, tea.WithAltScreen())

	go func() {
		for boop := range boopChan {
			p.Send(boopReceivedMsg(boop))
			go playBoopSound()
		}
	}()

	p.Run()
	return nil
}

func startUDPListeners(boopChan chan<- BoopMessage) {
	addr4 := &net.UDPAddr{Port: boopPort, IP: net.IPv4zero}
	conn4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		return
	}
	defer conn4.Close()

	addr6 := &net.UDPAddr{Port: boopPort, IP: net.IPv6zero}
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

		if idx := strings.Index(senderIP, "%"); idx != -1 {
			senderIP = senderIP[:idx]
		}

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
