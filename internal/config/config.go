// Package config loads and validates Batesian configuration from a batesian.yaml file.
// Values from the file serve as defaults that CLI flags override.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// defaultFilenames are the config file names searched for in order.
var defaultFilenames = []string{
	"batesian.yaml",
	"batesian.yml",
	".batesian.yaml",
	".batesian.yml",
}

// Config holds the full configuration loaded from a batesian.yaml file.
// All fields are optional; zero values mean "use CLI defaults".
type Config struct {
	// Target is the base URL of the agent or MCP server to scan.
	Target string `yaml:"target"`

	// Protocol filters rules by protocol: "a2a", "mcp", or "" for all.
	Protocol string `yaml:"protocol"`

	// Token is the bearer token used for authenticated requests.
	Token string `yaml:"token"`

	// Output is the output format: "table", "json", "sarif".
	Output string `yaml:"output"`

	// TimeoutSeconds is the per-request HTTP timeout.
	TimeoutSeconds int `yaml:"timeout"`

	// SkipTLS disables TLS certificate verification.
	SkipTLS bool `yaml:"skip_tls"`

	// RuleIDs is an explicit list of rule IDs to run.
	RuleIDs []string `yaml:"rule_ids"`

	// Tags filters rules by tag.
	Tags []string `yaml:"tags"`

	// Severities filters rules by severity.
	Severities []string `yaml:"severities"`

	// RulesDir is an additional directory containing custom rule YAML files.
	RulesDir string `yaml:"rules_dir"`

	// OOB enables the local out-of-band listener for SSRF detection.
	OOB bool `yaml:"oob"`

	// OOBURL is the URL of a pre-configured external OOB listener.
	OOBURL string `yaml:"oob_url"`
}

// Load reads a config file from path. If path is empty, it searches
// for a config file in the current working directory and its parents,
// trying each name in defaultFilenames. Returns an empty Config (not an error)
// if no file is found.
func Load(path string) (*Config, error) {
	if path == "" {
		var err error
		path, err = findConfigFile()
		if err != nil || path == "" {
			return &Config{}, nil // No config file found; use flag defaults.
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	return &cfg, nil
}

// findConfigFile searches cwd and parent directories for a config file.
func findConfigFile() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		for _, name := range defaultFilenames {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // Reached filesystem root.
		}
		dir = parent
	}

	return "", nil
}

// Example writes an annotated example batesian.yaml to the given path.
func Example() string {
	return `# batesian.yaml -- Batesian configuration file
# All fields are optional. CLI flags override values set here.
# Place this file in your project root or any parent directory.

# Target agent or MCP server URL.
# target: https://agent.example.com

# Protocol filter: "a2a", "mcp", or omit for all protocols.
# protocol: mcp

# Bearer token for authenticated A2A/MCP endpoints.
# Prefer environment variable BATESIAN_TOKEN over committing secrets here.
# token: ""

# Output format: table (default), json, sarif
# output: sarif

# Per-request HTTP timeout in seconds (default: 10).
# timeout: 30

# Disable TLS certificate verification (not recommended for production).
# skip_tls: false

# Run only these specific rule IDs (comma-separated in CLI, list here).
# rule_ids:
#   - a2a-push-ssrf-001
#   - mcp-tool-poison-001

# Filter rules by tag.
# tags:
#   - injection
#   - auth

# Filter rules by minimum severity.
# severities:
#   - critical
#   - high

# Additional directory containing custom YAML rule files.
# rules_dir: ./custom-rules

# Enable local OOB listener for SSRF detection (a2a-push-ssrf-001).
# oob: true

# External OOB listener URL (overrides oob: true).
# oob_url: https://your-collaborator.net/token
`
}
