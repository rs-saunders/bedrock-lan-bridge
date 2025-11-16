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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBeaconEdition         = "MCPE"
	defaultBeaconGameVersion     = "1.21.2"
	defaultBeaconProtocolVersion = 685
	defaultBeaconGameMode        = "Survival"
	defaultBeaconServerName      = "Bedrock LAN Bridge"
	defaultBeaconMaxPlayers      = 8
	defaultBeaconServerGUID      = "0x1122334455667788"
)

var raknetMagic = []byte{
	0x00, 0xff, 0xff, 0x00,
	0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd,
	0x12, 0x34, 0x56, 0x78,
}

type BeaconInfo struct {
	Edition         string
	ServerName      string
	ProtocolVersion int
	GameVersion     string
	Players         int
	MaxPlayers      int
	ServerGUID      uint64
	LevelName       string
	GameMode        string
	Port4           int
	Port6           int
}

type proxySession struct {
	client     *net.UDPAddr
	serverConn *net.UDPConn
	lastSeen   time.Time
}

// -------------------------
// CONFIG STRUCT + DEFAULTS
// -------------------------

type Config struct {
	RemoteServerIp                string `json:"remoteServerIp"`
	RemoteServerPort              int    `json:"remoteServerPort"`
	LocalProxyIp                  string `json:"localProxyIp"`
	LocalProxyPort                int    `json:"localProxyPort"`
	LanBroadcastPort              int    `json:"lanBroadcastPort"`
	LanBroadcastInterval          int    `json:"lanBroadcastIntervalMs"`
	LogLevel                      string `json:"logLevel"`
	BeaconServerNameOverride      string `json:"beaconServerNameOverride"`
	BeaconEditionOverride         string `json:"beaconEditionOverride"`
	BeaconProtocolVersionOverride int    `json:"beaconProtocolVersionOverride"`
	BeaconGameVersionOverride     string `json:"beaconGameVersionOverride"`
	BeaconLevelNameOverride       string `json:"beaconLevelNameOverride"`
	BeaconGameModeOverride        string `json:"beaconGameModeOverride"`
	BeaconServerGuidOverride      string `json:"beaconServerGuidOverride"`
	BeaconMaxPlayersOverride      int    `json:"beaconMaxPlayersOverride"`
	BeaconIPv6PortOverride        int    `json:"beaconIpv6PortOverride"`
}

func loadConfig(path string) (Config, error) {
	// Default config
	cfg := Config{
		RemoteServerIp:                "",
		RemoteServerPort:              19132,
		LocalProxyIp:                  "0.0.0.0",
		LocalProxyPort:                19134,
		LanBroadcastPort:              19132,
		LanBroadcastInterval:          1000,
		BeaconServerNameOverride:      "",
		LogLevel:                      "info",
		BeaconEditionOverride:         "",
		BeaconProtocolVersionOverride: 0,
		BeaconGameVersionOverride:     "",
		BeaconLevelNameOverride:       "",
		BeaconGameModeOverride:        "",
		BeaconServerGuidOverride:      defaultBeaconServerGUID,
		BeaconMaxPlayersOverride:      0,
		BeaconIPv6PortOverride:        0,
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

// Build a Switch-compatible Bedrock "unconnected pong" LAN beacon
func buildBedrockPong(info BeaconInfo) []byte {
	payload := fmt.Sprintf(
		"%s;%s;%d;%s;%d;%d;%d;%s;%s;%d;%d",
		info.Edition,
		info.ServerName,
		info.ProtocolVersion,
		info.GameVersion,
		info.Players,
		info.MaxPlayers,
		info.ServerGUID,
		info.LevelName,
		info.GameMode,
		info.Port4,
		info.Port6,
	)

	fmt.Printf("[beacon]  Built payload: %s\n", payload)
	data := []byte(payload)

	buf := make([]byte, 35+len(data))
	buf[0] = 0x1C // unconnected_pong opcode

	// Ping ID (ignored)
	binary.BigEndian.PutUint64(buf[1:], 0)

	// Server GUID (must match string portion of payload)
	binary.BigEndian.PutUint64(buf[9:], info.ServerGUID)

	// RakNet magic bytes
	copy(buf[17:], raknetMagic)

	// MOTD length + MOTD payload
	binary.BigEndian.PutUint16(buf[33:], uint16(len(data)))
	copy(buf[35:], data)

	return buf
}

func atoiOrDefault(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	if v, err := strconv.Atoi(value); err == nil {
		return v
	}
	return fallback
}

func parseUint10(value string, fallback uint64) uint64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	if v, err := strconv.ParseUint(value, 10, 64); err == nil {
		return v
	}

	return fallback
}

func parseGUIDString(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = defaultBeaconServerGUID
	}

	return strconv.ParseUint(value, 0, 64)
}

func defaultBeaconInfo(cfg Config) BeaconInfo {

	guid, err := parseGUIDString(cfg.BeaconServerGuidOverride)
	if err != nil {
		fmt.Printf("[beacon] invalid beaconServerGuid %q: %v — using default\n", cfg.BeaconServerGuidOverride, err)
		guid, _ = strconv.ParseUint(defaultBeaconServerGUID, 0, 64)
	}

	name := cfg.BeaconServerNameOverride
	if name == "" {
		name = defaultBeaconServerName
	}

	edition := cfg.BeaconEditionOverride
	if edition == "" {
		edition = defaultBeaconEdition
	}

	protocol := cfg.BeaconProtocolVersionOverride
	if protocol == 0 {
		protocol = defaultBeaconProtocolVersion
	}

	gameVersion := cfg.BeaconGameVersionOverride
	if gameVersion == "" {
		gameVersion = defaultBeaconGameVersion
	}

	level := cfg.BeaconLevelNameOverride
	if level == "" {
		level = name
	}

	gameMode := cfg.BeaconGameModeOverride
	if gameMode == "" {
		gameMode = defaultBeaconGameMode
	}

	maxPlayers := cfg.BeaconMaxPlayersOverride
	if maxPlayers == 0 {
		maxPlayers = defaultBeaconMaxPlayers
	}

	ipv6Port := cfg.BeaconIPv6PortOverride
	if ipv6Port == 0 {
		ipv6Port = cfg.LocalProxyPort
	}

	return BeaconInfo{
		Edition:         edition,
		ServerName:      name,
		ProtocolVersion: protocol,
		GameVersion:     gameVersion,
		Players:         0,
		MaxPlayers:      maxPlayers,
		ServerGUID:      guid,
		LevelName:       level,
		GameMode:        gameMode,
		Port4:           cfg.LocalProxyPort,
		Port6:           ipv6Port,
	}
}

// Query remote server using Bedrock unconnected ping
func queryRemoteServer(ip string, port int) (BeaconInfo, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	info := BeaconInfo{}

	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return info, err
	}
	defer conn.Close()

	// Build ping: ID + ping time + magic + client GUID
	ping := make([]byte, 1+8+len(raknetMagic)+8)
	ping[0] = 0x01
	binary.BigEndian.PutUint64(ping[1:], rand.Uint64())
	copy(ping[9:], raknetMagic)
	binary.BigEndian.PutUint64(ping[9+len(raknetMagic):], rand.Uint64())

	_, _ = conn.Write(ping)
	// fmt.Printf("[query] Ping sent to %s with GUID %x\n", addr, binary.BigEndian.Uint64(ping[9+len(raknetMagic):]))

	// Read response
	buf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return info, errors.New("no ping response from server")
	}

	pong, err := parsePongPayload(buf[:n])
	if err != nil {
		return info, err
	}
	// fmt.Printf("[query] Ping response from %s: %s\n", addr, pong)

	parts := splitPing(pong)
	if len(parts) < 6 {
		return info, errors.New("invalid ping reply structure")
	}

	info.Edition = parts[0]
	info.ServerName = parts[1]
	info.ProtocolVersion = atoiOrDefault(parts[2], 0)
	info.GameVersion = parts[3]
	info.Players = atoiOrDefault(parts[4], 0)
	info.MaxPlayers = atoiOrDefault(parts[5], 0)
	if len(parts) > 6 {
		info.ServerGUID = parseUint10(parts[6], 0)
		fmt.Printf("[query] Parsed remote GUID: %d\n", info.ServerGUID)
	}
	if len(parts) > 7 {
		info.LevelName = parts[7]
	}
	if len(parts) > 8 {
		info.GameMode = parts[8]
	}
	if len(parts) > 9 {
		info.Port4 = atoiOrDefault(parts[9], port)
	} else {
		info.Port4 = port
	}
	if len(parts) > 10 {
		info.Port6 = atoiOrDefault(parts[10], port)
	} else {
		info.Port6 = port
	}

	return info, nil
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

func parsePongPayload(buf []byte) (string, error) {
	if len(buf) < 35 {
		return "", errors.New("ping response too short")
	}

	motdLen := int(binary.BigEndian.Uint16(buf[33:35]))
	if 35+motdLen > len(buf) {
		motdLen = len(buf) - 35
	}
	if motdLen < 0 {
		return "", errors.New("invalid MOTD length")
	}

	return string(buf[35 : 35+motdLen]), nil
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

	sessionMu := &sync.Mutex{}
	sessions := make(map[string]*proxySession)
	idleTimeout := 30 * time.Second

	removeSession := func(key string) {
		sessionMu.Lock()
		if sess, ok := sessions[key]; ok {
			sess.serverConn.Close()
			delete(sessions, key)
			fmt.Printf("[proxy] Closed session for %s\n", key)
		}
		sessionMu.Unlock()
	}

	go func() {
		ticker := time.NewTicker(idleTimeout / 2)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			sessionMu.Lock()
			for key, sess := range sessions {
				if now.Sub(sess.lastSeen) > idleTimeout {
					fmt.Printf("[proxy] Session %s idle for %v — cleaning up\n", key, now.Sub(sess.lastSeen))
					sess.serverConn.Close()
					delete(sessions, key)
				}
			}
			sessionMu.Unlock()
		}
	}()

	go func() {
		defer conn.Close()

		buf := make([]byte, 2048)

		for {
			n, clientAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				fmt.Printf("[proxy] Error reading from %s: %v\n", localAddr, err)
				continue
			}

			data := append([]byte(nil), buf[:n]...)
			clientKey := clientAddr.String()

			sessionMu.Lock()
			sess, ok := sessions[clientKey]
			if !ok {
				srvConn, err := net.DialUDP("udp", nil, raddr)
				if err != nil {
					sessionMu.Unlock()
					fmt.Printf("[proxy] Failed to dial remote %s: %v\n", raddr.String(), err)
					continue
				}

				session := &proxySession{
					client:     cloneUDPAddr(clientAddr),
					serverConn: srvConn,
					lastSeen:   time.Now(),
				}

				sessions[clientKey] = session
				sess = session

				go relayServerResponses(conn, clientKey, session, removeSession)
				fmt.Printf("[proxy] New session %s -> %s (guid local)\n", clientKey, raddr.String())
			} else {
				sess.lastSeen = time.Now()
			}
			sessionMu.Unlock()

			if _, err := sess.serverConn.Write(data); err != nil {
				fmt.Printf("[proxy] Failed to forward %d bytes from %s to %s: %v\n", len(data), clientKey, raddr.String(), err)
				removeSession(clientKey)
				continue
			}

			fmt.Printf("[proxy] Relayed %d bytes from %s to %s\n", len(data), clientKey, raddr.String())
		}
	}()
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}

	ipCopy := make(net.IP, len(addr.IP))
	copy(ipCopy, addr.IP)

	return &net.UDPAddr{
		IP:   ipCopy,
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func relayServerResponses(localConn *net.UDPConn, key string, sess *proxySession, cleanup func(string)) {
	buf := make([]byte, 2048)

	for {
		n, _, err := sess.serverConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("[proxy] Error reading reply for %s: %v\n", key, err)
			cleanup(key)
			return
		}

		if n > 0 && buf[0] == 0x1C {
			if payload, err := parsePongPayload(buf[:n]); err == nil {
				fmt.Printf("[proxy] Relaying pong to %s: %s\n", sess.client.String(), payload)
			} else {
				fmt.Printf("[proxy] Failed to parse pong for %s: %v\n", key, err)
			}
		} else if n > 0 {
			fmt.Printf("[proxy] Relaying packet 0x%02X (%d bytes) to %s\n", buf[0], n, sess.client.String())
		}

		if _, err := localConn.WriteToUDP(buf[:n], sess.client); err != nil {
			fmt.Printf("[proxy] Failed sending %d bytes to %s: %v\n", n, sess.client.String(), err)
			cleanup(key)
			return
		}
	}
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

	fallback := defaultBeaconInfo(cfg)

	go func() {
		defer conn.Close()

		for {
			payload := fallback

			info, err := queryRemoteServer(cfg.RemoteServerIp, cfg.RemoteServerPort)
			if err != nil {
				fmt.Printf("[beacon] failed to query remote server: %v\n", err)
				continue
			}

			fmt.Printf("[beacon] Remote payload: %s;%s;%d;%s;%d;%d;%d;%s;%s;%d;%d\n",
				info.Edition,
				info.ServerName,
				info.ProtocolVersion,
				info.GameVersion,
				info.Players,
				info.MaxPlayers,
				info.ServerGUID,
				info.LevelName,
				info.GameMode,
				info.Port4,
				info.Port6,
			)
			if info.Edition != "" {
				payload.Edition = info.Edition
			}
			if info.ServerName != "" {
				payload.ServerName = info.ServerName
			}
			if info.ProtocolVersion != 0 {
				payload.ProtocolVersion = info.ProtocolVersion
			}
			if info.GameVersion != "" {
				payload.GameVersion = info.GameVersion
			}
			payload.Players = info.Players
			if info.MaxPlayers > 0 {
				payload.MaxPlayers = info.MaxPlayers
			}
			if info.LevelName != "" {
				payload.LevelName = info.LevelName
			}
			if info.GameMode != "" {
				payload.GameMode = info.GameMode
			}

			if cfg.BeaconServerNameOverride != "" {
				payload.ServerName = cfg.BeaconServerNameOverride
			}
			if cfg.BeaconEditionOverride != "" {
				payload.Edition = cfg.BeaconEditionOverride
			}
			if cfg.BeaconProtocolVersionOverride > 0 {
				payload.ProtocolVersion = cfg.BeaconProtocolVersionOverride
			}
			if cfg.BeaconGameVersionOverride != "" {
				payload.GameVersion = cfg.BeaconGameVersionOverride
			}
			if cfg.BeaconLevelNameOverride != "" {
				payload.LevelName = cfg.BeaconLevelNameOverride
			}
			if cfg.BeaconGameModeOverride != "" {
				payload.GameMode = cfg.BeaconGameModeOverride
			}
			if cfg.BeaconMaxPlayersOverride > 0 {
				payload.MaxPlayers = cfg.BeaconMaxPlayersOverride
			}

			payload.Port4 = cfg.LocalProxyPort
			ipv6Port := cfg.BeaconIPv6PortOverride
			if ipv6Port == 0 {
				ipv6Port = cfg.LocalProxyPort
			}
			payload.Port6 = ipv6Port

			beacon := buildBedrockPong(payload)
			// fmt.Printf("[beacon] Broadcasting GUID %d, name %q, players %d/%d to ports v4=%d v6=%d\n",
			// 	payload.ServerGUID, payload.ServerName, payload.Players, payload.MaxPlayers, payload.Port4, payload.Port6)
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
