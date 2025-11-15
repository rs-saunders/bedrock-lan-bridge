package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

// -------------------------
// CONFIG STRUCT + DEFAULTS
// -------------------------

type Config struct {
	RemoteServerIp        string `json:"remoteServerIp"`
	RemoteServerPort      int    `json:"remoteServerPort"`
	LocalProxyIp          string `json:"localProxyIp"`
	LocalProxyPort        int    `json:"localProxyPort"`
	LanBroadcastPort      int    `json:"lanBroadcastPort"`
	LanBroadcastInterval  int    `json:"lanBroadcastIntervalMs"`
	MotdOverride          string `json:"motdOverride"`
	LogLevel              string `json:"logLevel"`
}

func loadConfig(path string) (Config, error) {
	// Default config
	cfg := Config{
		RemoteServerIp:       "",
		RemoteServerPort:     19132,
		LocalProxyIp:         "0.0.0.0",
		LocalProxyPort:       19134,
		LanBroadcastPort:     19132,
		LanBroadcastInterval: 1000,
		MotdOverride:         "",
		LogLevel:             "info",
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}

	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		return cfg, err
	}

	if cfg.RemoteServerIp == "" {
		return cfg, errors.New("remoteServerIp is required")
	}

	return cfg, nil
}

// -------------------------
// BEDROCK PACKET HELPERS
// -------------------------

// Build a minimal Bedrock LAN beacon packet
func buildLANBeacon(motd, players, max string) []byte {
	msg := fmt.Sprintf(";1;%s;%s;%s;Bedrock_LAN_Bridge;Survival;", motd, players, max)
	b := []byte(msg)

	buf := make([]byte, 2+len(b))
	buf[0] = 0xFE
	buf[1] = 0xFD
	copy(buf[2:], b)

	return buf
}

// Query remote server using Bedrock unconnected ping
func queryRemoteServer(ip string, port int) (motd, players, max string, err error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()

	// Build ping
	ping := make([]byte, 18)
	ping[0] = 0x01
	binary.BigEndian.PutUint64(ping[1:], rand.Uint64())
	copy(ping[9:], []byte{0, 0, 0, 0, 0, 0, 0, 0})

	_, _ = conn.Write(ping)

	// Read response
	buf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return "", "", "", errors.New("no ping response from server")
	}

	parts := splitPing(string(buf[:n]))
	if len(parts) < 6 {
		return "", "", "", errors.New("invalid ping reply structure")
	}

	motd = parts[1]
	players = parts[4]
	max = parts[5]

	return
}

func splitPing(s string) []string {
	out := []string{}
	curr := ""

	for _, c := range s {
		if c == ';' {
			out = append(out, curr)
			curr = ""
		} else {
			curr += string(c)
		}
	}

	out = append(out, curr)
	return out
}

// -------------------------
// UDP PROXY
// -------------------------

func startProxy(cfg Config) {
	localAddr := fmt.Sprintf("%s:%d", cfg.LocalProxyIp, cfg.LocalProxyPort)
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		panic(err)
	}

	raddr, err := net.ResolveUDPAddr("udp",
		fmt.Sprintf("%s:%d", cfg.RemoteServerIp, cfg.RemoteServerPort))
	if err != nil {
		panic(err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[proxy] Listening on %s\n", localAddr)

	go func() {
		defer conn.Close()

		buf := make([]byte, 2048)

		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}

			data := append([]byte(nil), buf[:n]...)

			go func(msg []byte, from *net.UDPAddr) {
				srvConn, err := net.DialUDP("udp", nil, raddr)
				if err != nil {
					return
				}
				defer srvConn.Close()

				srvConn.Write(msg)

				reply := make([]byte, 2048)
				srvConn.SetReadDeadline(time.Now().Add(3 * time.Second))
				n2, _, err := srvConn.ReadFromUDP(reply)
				if err == nil {
					conn.WriteToUDP(reply[:n2], from)
				}
			}(data, clientAddr)
		}
	}()
}

// -------------------------
// LAN BEACON BROADCASTER
// -------------------------

func startBeacon(cfg Config) {
	bcast := &net.UDPAddr{
		IP:   net.IPv4bcast,
		Port: cfg.LanBroadcastPort,
	}

	conn, err := net.DialUDP("udp", nil, bcast)
	if err != nil {
		panic(err)
	}

	interval := time.Duration(cfg.LanBroadcastInterval) * time.Millisecond

	fmt.Println("[beacon] Broadcasting LAN beacons…")

	go func() {
		defer conn.Close()

		for {
			motd, players, max, err := queryRemoteServer(cfg.RemoteServerIp, cfg.RemoteServerPort)
			if err != nil {
				motd = "RemoteServer"
				players = "0"
				max = "10"
			}

			if cfg.MotdOverride != "" {
				motd = cfg.MotdOverride
			}

			beacon := buildLANBeacon(motd, players, max)
			conn.Write(beacon)

			time.Sleep(interval)
		}
	}()
}

// -------------------------
// MAIN
// -------------------------

func main() {
	rand.Seed(time.Now().UnixNano())

	configPath := flag.String("config", "config.json", "Path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Println("[error] Failed to load config:", err)
		os.Exit(1)
	}

	fmt.Println("[init] Starting Bedrock LAN Bridge")
	fmt.Printf("[init] Remote server: %s:%d\n", cfg.RemoteServerIp, cfg.RemoteServerPort)
	fmt.Printf("[init] Local proxy: %s:%d\n", cfg.LocalProxyIp, cfg.LocalProxyPort)
	fmt.Printf("[init] LAN broadcast port: %d\n", cfg.LanBroadcastPort)

	startProxy(cfg)
	startBeacon(cfg)

	select {} // block forever
}
