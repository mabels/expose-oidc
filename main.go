package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	APIServer          string
	PublicURL          string
	ServiceAccountPath string
	Port               int
}

func (c *Config) getToken() ([]byte, error) {
	bytes, err := os.ReadFile(c.ServiceAccountPath + "/token")
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(bytes))), nil
}

func (c *Config) getCACert() ([]byte, error) {
	return os.ReadFile(c.ServiceAccountPath + "/ca.crt")
}

func (c *Config) k8sApiGet(url string) (*http.Response, error) {
	token, err := c.getToken()
	if err != nil {
		return nil, err
	}
	caCert, err := c.getCACert()
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", string(token)))
	return client.Do(req)
}

func (c *Config) getJson(url string) (map[string]interface{}, error) {
	res, err := c.k8sApiGet(url)
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

func (c *Config) fetchOpenIDConfiguration() ([]byte, error) {
	val, err := c.getJson(fmt.Sprintf("%s/.well-known/openid-configuration", c.APIServer))
	if err != nil {
		return nil, err
	}
	purl, err := url.Parse(c.PublicURL)
	if err != nil {
		return nil, err
	}
	val["issuer"] = purl.String()
	purl.Path = "/openid/v1/jwks"
	val["jwks_uri"] = purl.String()
	return json.Marshal(val)
}

func (c *Config) fetchJwks() ([]byte, error) {
	val, err := c.getJson(fmt.Sprintf("%s/openid/v1/jwks", c.APIServer))
	if err != nil {
		return nil, err
	}

	return json.Marshal(val)
}

func openidConfigurationHandler(cfg *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := cfg.fetchOpenIDConfiguration()
		if err != nil {
			w.WriteHeader(500)
			fmt.Printf("Failed to fetch openid configuration: %s", err)
			w.Write([]byte("Failed to fetch openid configuration"))
			return
		}
		w.Write(bytes)
	}
}

func jwksHandler(cfg *Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		bytes, err := cfg.fetchJwks()
		if err != nil {
			w.WriteHeader(500)
			fmt.Printf("Failed to fetch jwks: %s", err)
			w.Write([]byte("Failed to fetch jwks configuration"))
			return
		}
		w.Write(bytes)
	}
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.APIServer, "apiserver", "https://kubernetes.default.svc", "apiserver url")
	flag.StringVar(&cfg.PublicURL, "publicUrl", "https://auth.mydomain.io", "public url of the auth server")
	flag.StringVar(&cfg.ServiceAccountPath, "serviceAccountPath", "/var/run/secrets/kubernetes.io/serviceaccount", "base path of service account configuration")
	flag.IntVar(&cfg.Port, "port", 80, "port to listen on")
	flag.Parse()
	envPortStr, is := os.LookupEnv("PORT")
	if is {
		val, err := strconv.ParseInt(envPortStr, 10, 32)
		if err == nil {
			cfg.Port = int(val)
		} else {
			panic(fmt.Errorf("Invalid port in PORT environment variable"))
		}
	}
	http.HandleFunc("/.well-known/openid-configuration", openidConfigurationHandler(&cfg))
	http.HandleFunc("/openid/v1/jwks", jwksHandler(&cfg))

	http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), nil)
}
