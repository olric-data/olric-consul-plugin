// Copyright 2020-2025 The Olric Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/Jeffail/gabs/v2"
	"github.com/hashicorp/go-sockaddr"
	"github.com/mitchellh/mapstructure"
)

var errRequiredField = errors.New("required field not found")

type Config struct {
	Provider              string
	Path                  string
	Address               string
	Payload               string
	Token                 string
	PassingOnly           bool
	ReplaceExistingChecks bool
	InsecureSkipVerify    bool
}

type ConsulDiscovery struct {
	Config  *Config
	service string
	id      string
	log     *log.Logger
	client  *http.Client
}

func getPrivateIP() (string, error) {
	// if we're not bound to a specific IP, let's use a suitable private IP address.
	ipStr, err := sockaddr.GetPrivateIP()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %w", err)
	}
	if ipStr == "" {
		return "", fmt.Errorf("no private IP address found, and explicit IP not provided")
	}

	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return "", fmt.Errorf("failed to parse private IP address: %q", ipStr)
	}
	return parsed.String(), nil
}

func (s *ConsulDiscovery) checkErrors() error {
	if s.Config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	if s.log == nil {
		return fmt.Errorf("logger cannot be nil")
	}
	return nil
}

// SetConfig registers plugin configuration
func (s *ConsulDiscovery) SetConfig(c map[string]interface{}) error {
	var cfg Config
	err := mapstructure.Decode(c, &cfg)
	if err != nil {
		return err
	}
	s.Config = &cfg
	return nil
}

// SetLogger sets an appropriate
func (s *ConsulDiscovery) SetLogger(l *log.Logger) {
	s.log = l
}

// Initialize initializes the plugin: registers some internal data structures, clients etc.
func (s *ConsulDiscovery) Initialize() error {
	if err := s.checkErrors(); err != nil {
		return err
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: s.Config.InsecureSkipVerify},
	}
	s.client = &http.Client{Transport: tr}
	s.log.Printf("[INFO] Service discovery plugin is enabled, provider: %s", s.Config.Provider)
	return nil
}

func (s *ConsulDiscovery) processPayload() error {
	payload := make(map[string]interface{})
	if err := json.Unmarshal([]byte(s.Config.Payload), &payload); err != nil {
		return err
	}
	name, ok := payload["Name"]
	if !ok {
		return fmt.Errorf("%w: Name", errRequiredField)
	}
	s.service = name.(string)

	port, ok := payload["Port"]
	if !ok {
		return fmt.Errorf("%w: Port", errRequiredField)
	}

	_, ok = payload["Address"]
	if !ok {
		privateIP, err := getPrivateIP()
		if err != nil {
			return err
		}
		payload["Address"] = privateIP
	}

	_, ok = payload["ID"]
	if !ok {
		payload["ID"] = payload["Address"]
	}
	s.id = payload["ID"].(string)

	_, ok = payload["Check"]
	if !ok {
		return fmt.Errorf("%w: Check", errRequiredField)
	}
	check := payload["Check"].(map[string]interface{})
	_, ok = check["TCP"]
	if !ok {
		addr := payload["Address"].(string)
		check["TCP"] = net.JoinHostPort(addr, strconv.Itoa(int(port.(float64))))
		check["Name"] = fmt.Sprintf("Check Olric node on %v", check["TCP"])
	}

	tmp, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	s.Config.Payload = string(tmp)
	return nil
}

func (s *ConsulDiscovery) doRequest(op string, req *http.Request) error {
	if s.Config.Token != "" {
		req.Header.Set("X-Consul-Token", s.Config.Token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", op, string(data))
	}
	return nil
}

// Register registers this node to a service discovery directory.
func (s *ConsulDiscovery) Register() error {
	if err := s.checkErrors(); err != nil {
		return err
	}
	u, err := url.Parse(s.Config.Address)
	if err != nil {
		return nil
	}
	u.Path = path.Join(u.Path, "/v1/agent/service/register")
	if s.Config.ReplaceExistingChecks {
		q := u.Query()
		q.Set("replace-existing-checks", "true")
		u.RawQuery = q.Encode()
	}

	if err := s.processPayload(); err != nil {
		return err
	}

	buf := bytes.NewBuffer([]byte(s.Config.Payload))
	req, err := http.NewRequest(http.MethodPut, u.String(), buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return s.doRequest("register", req)
}

// Deregister removes this node from a service discovery directory.
func (s *ConsulDiscovery) Deregister() error {
	u, err := url.Parse(s.Config.Address)
	if err != nil {
		return nil
	}
	u.Path = path.Join(u.Path, "/v1/agent/service/deregister", s.id)
	req, err := http.NewRequest(http.MethodPut, u.String(), nil)
	if err != nil {
		return err
	}
	return s.doRequest("deregister", req)
}

// DiscoverPeers returns a list of known Olric nodes.
func (s *ConsulDiscovery) DiscoverPeers() ([]string, error) {
	if err := s.checkErrors(); err != nil {
		return nil, err
	}

	u, err := url.Parse(s.Config.Address)
	if err != nil {
		return nil, nil
	}
	u.Path = path.Join(u.Path, "/v1/health/service", s.service)
	if s.Config.PassingOnly {
		q := u.Query()
		q.Set("passing", "1")
		u.RawQuery = q.Encode()
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	parsed, err := gabs.ParseJSONBuffer(resp.Body)
	if err != nil {
		return nil, err
	}
	var peers []string
	for _, node := range parsed.Children() {
		id, ok := node.Path("Service.ID").Data().(string)
		if !ok {
			continue
		}
		if id == s.id {
			continue
		}

		addr, ok := node.Path("Service.Address").Data().(string)
		if !ok {
			continue
		}
		port, ok := node.Path("Service.Port").Data().(float64)
		if !ok {
			continue
		}
		peer := net.JoinHostPort(addr, fmt.Sprintf("%v", port))
		peers = append(peers, peer)
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers found")
	}
	return peers, nil
}

// Close stops underlying goroutines, if there is any. It should be a blocking call.
func (s *ConsulDiscovery) Close() error {
	// Dummy implementation
	return nil
}
