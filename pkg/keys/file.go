package keys

import (
	"fmt"
	"os"
	"time"

	"sigs.k8s.io/yaml"
)

// FileConfig is the format of the optional keys file, for running outside Kubernetes or in tests.
//
//	clients:
//	  - name: team-a
//	    keyEnv: TEAM_A_API_KEY
//	    hosts: ["api.example.com"]
//	    pathPrefixes: ["/v1/"]
//	    methods: ["GET", "HEAD"]
//	    groups: ["read-only"]
//	    expiresAt: 2027-01-31T00:00:00Z
type FileConfig struct {
	Clients []struct {
		Name         string    `json:"name"`
		Key          string    `json:"key"`
		KeyEnv       string    `json:"keyEnv"`
		Hosts        []string  `json:"hosts"`
		PathPrefixes []string  `json:"pathPrefixes"`
		Methods      []string  `json:"methods"`
		Groups       []string  `json:"groups"`
		ExpiresAt    time.Time `json:"expiresAt"`
	} `json:"clients"`
}

// LoadFile reads a keys file into store under the source name "file".
func LoadFile(path string, store *Store) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg FileConfig
	if err := yaml.UnmarshalStrict(raw, &cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	keys := map[string]Client{}
	for i, c := range cfg.Clients {
		key := c.Key
		if c.KeyEnv != "" {
			key = os.Getenv(c.KeyEnv)
		}
		if c.Name == "" || key == "" {
			return fmt.Errorf("%s: client %d needs a name and a key or keyEnv that is set", path, i)
		}
		keys[key] = Client{Name: c.Name, Hosts: c.Hosts, PathPrefixes: c.PathPrefixes, Methods: c.Methods, Groups: c.Groups,
			ExpiresAt: c.ExpiresAt}
	}
	store.Set("file", keys)
	return nil
}
