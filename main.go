package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
)

type FetchState struct {
	Bytes   []byte
	Error   error
	Fetched time.Time
	Count   int32
}
type RuntimeState struct {
	Token               []byte
	CACert              []byte
	Jwks                FetchState
	OpenIdConfiguration FetchState
	WeitGroup           sync.WaitGroup
	HttpClient          *http.Client
	Log                 *log.Logger
	Config              *Config
}

type Config struct {
	APIServer          string
	PublicURL          string
	ServiceAccountPath string
	Port               int
}

func getToken(serviceAccountPath string) ([]byte, error) {
	bytes, err := os.ReadFile(serviceAccountPath + "/token")
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(bytes))), nil
}

func getCACert(serviceAccountPath string) ([]byte, error) {
	return os.ReadFile(serviceAccountPath + "/ca.crt")
}

func (rs *RuntimeState) observerLoop(cfg *Config) {
	rs.Log.Printf("Starting observer loop")
	out, _ := json.Marshal(cfg)
	rs.Log.Printf("Config: %s", string(out))
	rs.WeitGroup.Add(1)
	first := true
	for {
		token, err := getToken(cfg.ServiceAccountPath)
		if err != nil {
			rs.Log.Fatalf("Failed to read token: %s", err)
		} else {
			rs.Token = token
		}
		caCert, err := getCACert(cfg.ServiceAccountPath)
		if err != nil {
			rs.Log.Fatalf("Failed to read token: %s", err)
		}
		if !bytes.Equal(caCert, rs.CACert) && rs.Token != nil && caCert != nil {
			rs.CACert = caCert
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			rs.HttpClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: caCertPool,
					},
				},
			}
			rs.Log.Printf("Token and CA cert updated, restarting observer loop")
			if first {
				rs.WeitGroup.Done()
				first = false
			}
		}
		if rs.Jwks.Fetched.Add(time.Minute).After(time.Now()) {
			rs.Log.Printf("Jwsks fetched %d", rs.Jwks.Count)
			rs.Jwks.Count = 0
			rs.Jwks.Bytes = nil
			rs.Jwks.Fetched = time.Time{}
		}
		if rs.OpenIdConfiguration.Fetched.Add(time.Minute).After(time.Now()) {
			rs.Log.Printf("OpenIdConfiguration fetched %d", rs.OpenIdConfiguration.Count)
			rs.OpenIdConfiguration.Count = 0
			rs.OpenIdConfiguration.Bytes = nil
			rs.OpenIdConfiguration.Fetched = time.Time{}
		}
		time.Sleep(time.Minute)
	}
}

func (rs *RuntimeState) k8sApiGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(rs.Token)))
	return rs.HttpClient.Do(req)
}

func (rs *RuntimeState) getJson(url string) (map[string]interface{}, error) {
	res, err := rs.k8sApiGet(url)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Failed to fetch openid configuration: %s", res.Status)
	}
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var val map[string]interface{}
	err = json.Unmarshal(bytes, &val)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func (rs *RuntimeState) fetchOpenIDConfiguration() ([]byte, error) {
	if rs.OpenIdConfiguration.Bytes == nil {
		val, err := rs.getJson(fmt.Sprintf("%s/.well-known/openid-configuration", rs.Config.APIServer))
		if err != nil {
			return nil, err
		}
		purl, err := url.Parse(rs.Config.PublicURL)
		if err != nil {
			return nil, err
		}
		val["issuer"] = purl.String()
		purl.Path = "/openid/v1/jwks"
		val["jwks_uri"] = purl.String()
		rs.OpenIdConfiguration.Bytes, rs.OpenIdConfiguration.Error = json.Marshal(val)
		rs.Jwks.Fetched = time.Now()
	}
	return rs.OpenIdConfiguration.Bytes, rs.OpenIdConfiguration.Error
}

func (rs *RuntimeState) fetchJwks() ([]byte, error) {
	if rs.Jwks.Bytes == nil {
		val, err := rs.getJson(fmt.Sprintf("%s/openid/v1/jwks", rs.Config.APIServer))
		if err != nil {
			return nil, err
		}
		rs.Jwks.Bytes, rs.Jwks.Error = json.Marshal(val)
		rs.Jwks.Fetched = time.Now()
	}
	return rs.Jwks.Bytes, rs.Jwks.Error
}

func openidConfigurationHandler(rs *RuntimeState) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := rs.fetchOpenIDConfiguration()
		if err != nil {
			log.Printf("Failed to fetch openid configuration: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Failed to fetch openid configuration"))
			return
		}
		w.Write(bytes)
		rs.OpenIdConfiguration.Count++
	}
}

func jwksHandler(rs *RuntimeState) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := rs.fetchJwks()
		if err != nil {
			log.Printf("Failed to fetch jwks: %s", err)
			w.WriteHeader(500)
			w.Write([]byte("Failed to fetch jwks configuration"))
			return
		}
		w.Write(bytes)
		rs.Jwks.Count++
	}
}

func main() {
	cfg := Config{}
	rs := RuntimeState{
		Log:    log.New(os.Stdout, "expose-oic", log.Lshortfile),
		Config: &cfg,
	}
	pflag.StringVar(&cfg.APIServer, "apiserver", "https://kubernetes.default.svc", "apiserver url")
	pflag.StringVar(&cfg.PublicURL, "publicUrl", "https://auth.mydomain.io", "public url of the auth server")
	pflag.StringVar(&cfg.ServiceAccountPath, "serviceAccountPath", "/var/run/secrets/kubernetes.io/serviceaccount", "base path of service account configuration")
	pflag.IntVar(&cfg.Port, "port", 80, "port to listen on")
	pflag.Parse()
	envPortStr, is := os.LookupEnv("PORT")
	if is {
		val, err := strconv.ParseInt(envPortStr, 10, 32)
		if err == nil {
			cfg.Port = int(val)
		} else {
			panic(fmt.Errorf("Invalid port in PORT environment variable"))
		}
	}
	go rs.observerLoop(&cfg)
	rs.WeitGroup.Wait()

	http.HandleFunc("/.well-known/openid-configuration", openidConfigurationHandler(&rs))
	http.HandleFunc("/openid/v1/jwks", jwksHandler(&rs))

	http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil)
}
