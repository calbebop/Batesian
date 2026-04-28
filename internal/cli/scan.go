package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	batesian "github.com/calvin-mcdowell/batesian"
	attackpkg "github.com/calvin-mcdowell/batesian/internal/attack"
	"github.com/calvin-mcdowell/batesian/internal/auth"
	"github.com/calvin-mcdowell/batesian/internal/config"
	"github.com/calvin-mcdowell/batesian/internal/engine"
	"github.com/calvin-mcdowell/batesian/internal/report"
	"github.com/calvin-mcdowell/batesian/internal/rules"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run attack rules against a target agent endpoint",
	Long: `Scan executes Batesian attack rules against a target A2A or MCP endpoint.

Each rule performs an active attack and evaluates assertions against
the responses. Confirmed findings are output as a table, JSON, or
SARIF for GitHub Security tab integration.

Rules are loaded from the built-in rules directory. Use --rules-dir to
specify an additional directory, or --rule-ids to run specific rules.`,
	Example: `  # Scan an A2A agent with all applicable rules
  batesian scan --target https://agent.example.com

  # Scan with specific rule IDs
  batesian scan --target https://agent.example.com --rule-ids a2a-extcard-unauth-001

  # Scan with SARIF output for GitHub Security tab
  batesian scan --target https://agent.example.com --output sarif > results.sarif

  # Scan with a local OOB listener (for push-SSRF detection)
  batesian scan --target https://agent.example.com --oob

  # Scan MCP only
  batesian scan --target https://mcp-server.example.com --protocol mcp`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("protocol", "p", "", "Filter rules by protocol: a2a, mcp (default: all)")
	scanCmd.Flags().StringSlice("rule-ids", nil, "Run only these rule IDs (comma-separated)")
	scanCmd.Flags().StringSlice("severity", nil, "Filter by severity: critical,high,medium,low,info")
	scanCmd.Flags().StringSlice("tags", nil, "Filter by rule tags (comma-separated)")
	scanCmd.Flags().String("rules-dir", "", "Additional rules directory (supplements built-in rules)")
	scanCmd.Flags().String("token", "", "Bearer token for authenticated requests")
	scanCmd.Flags().Int("timeout", 10, "Request timeout in seconds")
	scanCmd.Flags().Bool("skip-tls", false, "Skip TLS certificate verification")
	scanCmd.Flags().Bool("oob", false, "Enable local OOB listener for SSRF callback detection")
	scanCmd.Flags().String("oob-url", "", "External OOB server URL (overrides --oob local listener)")
	scanCmd.Flags().String("config", "", "Path to batesian.yaml config file (default: auto-discover)")
	// OAuth 2.0 flags for automatic token acquisition.
	scanCmd.Flags().String("token-url", "", "OAuth 2.0 token endpoint URL for client credentials flow")
	scanCmd.Flags().String("client-id", "", "OAuth 2.0 client ID (used with --token-url)")
	scanCmd.Flags().String("client-secret", "", "OAuth 2.0 client secret (used with --token-url)")
	scanCmd.Flags().StringSlice("oauth-scopes", nil, "OAuth 2.0 scopes to request (comma-separated)")
	scanCmd.Flags().String("oauth-audience", "", "OAuth 2.0 audience (used with --token-url; for Auth0/Okta)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Load config file first; CLI flags override config values.
	configPath, _ := cmd.Flags().GetString("config")
	cfg, cfgErr := config.Load(configPath)
	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load config file: %v\n", cfgErr)
		cfg = &config.Config{}
	}

	target, _ := cmd.Flags().GetString("target")
	outputFmt, _ := cmd.Flags().GetString("output")
	verbose, _ := cmd.Flags().GetBool("verbose")
	protocol, _ := cmd.Flags().GetString("protocol")
	ruleIDs, _ := cmd.Flags().GetStringSlice("rule-ids")
	severities, _ := cmd.Flags().GetStringSlice("severity")
	tags, _ := cmd.Flags().GetStringSlice("tags")
	rulesDir, _ := cmd.Flags().GetString("rules-dir")
	token, _ := cmd.Flags().GetString("token")
	timeoutSecs, _ := cmd.Flags().GetInt("timeout")
	skipTLS, _ := cmd.Flags().GetBool("skip-tls")
	oobEnabled, _ := cmd.Flags().GetBool("oob")
	oobURL, _ := cmd.Flags().GetString("oob-url")

	// Apply config file defaults for unset flags.
	if target == "" {
		target = cfg.Target
	}
	if outputFmt == "" {
		outputFmt = cfg.Output
	}
	if protocol == "" {
		protocol = cfg.Protocol
	}
	if len(ruleIDs) == 0 {
		ruleIDs = cfg.RuleIDs
	}
	if len(severities) == 0 {
		severities = cfg.Severities
	}
	if len(tags) == 0 {
		tags = cfg.Tags
	}
	if rulesDir == "" {
		rulesDir = cfg.RulesDir
	}
	if token == "" {
		// Also check environment variable BATESIAN_TOKEN.
		token = firstNonEmpty(cfg.Token, os.Getenv("BATESIAN_TOKEN"))
	}
	if timeoutSecs == 10 && cfg.TimeoutSeconds > 0 {
		timeoutSecs = cfg.TimeoutSeconds
	}
	if !skipTLS {
		skipTLS = cfg.SkipTLS
	}
	if !oobEnabled {
		oobEnabled = cfg.OOB
	}
	if oobURL == "" {
		oobURL = cfg.OOBURL
	}

	if target == "" {
		return fmt.Errorf("--target is required")
	}

	// If OAuth flags are provided and no token is set, acquire one automatically.
	if token == "" {
		tokenURL, _ := cmd.Flags().GetString("token-url")
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		oauthScopes, _ := cmd.Flags().GetStringSlice("oauth-scopes")
		oauthAudience, _ := cmd.Flags().GetString("oauth-audience")

		if clientID != "" && tokenURL != "" {
			tok, err := fetchOAuthToken(context.Background(), tokenURL, clientID, clientSecret, oauthScopes, oauthAudience)
			if err != nil {
				return fmt.Errorf("OAuth token acquisition failed: %w", err)
			}
			token = tok
		}
	}

	format := report.ParseFormat(outputFmt)
	statusOut := os.Stdout
	if format == report.FormatJSON || format == report.FormatSARIF {
		statusOut = os.Stderr
	}
	printer := report.New(statusOut, verbose)
	printer.Banner()
	printer.ProbeHeader(target, coalesceProtocol(protocol))

	// Load rules.
	loaded, warns, err := loadRules(rulesDir)
	if err != nil {
		printer.Error("Failed to load rules: " + err.Error())
		return err
	}
	for _, w := range warns {
		printer.Warn(fmt.Sprintf("Skipping malformed rule %s: %v", w.Path, w.Err))
	}

	// Apply filters.
	filter := &rules.Filter{
		Protocols:  splitProtocols(protocol),
		Severities: severities,
		Tags:       tags,
		IDs:        ruleIDs,
	}
	filtered := filter.Apply(loaded)

	if len(filtered) == 0 {
		printer.Warn("No rules matched the current filters. Check --protocol, --rule-ids, --severity, --tags.")
		return nil
	}
	printer.Info(fmt.Sprintf("Running %d rule(s) against %s", len(filtered), target))
	if verbose {
		for _, r := range filtered {
			printer.Verbose(fmt.Sprintf("  [%s] %s", r.Info.Severity, r.ID))
		}
	}

	// Configure OOB.
	if oobURL == "" && oobEnabled {
		// OOB listener is started inside the push-ssrf executor per target.
		// Setting an empty OOBListenerURL triggers the auto-start behavior.
		oobURL = ""
	}

	// Build execution options.
	opts := attackpkg.Options{
		OOBListenerURL: oobURL,
		Token:          token,
		TimeoutSeconds: timeoutSecs,
		SkipTLS:        skipTLS,
		Verbose:        verbose,
	}

	// Run the scan.
	eng := engine.New(opts)
	ctx := context.Background()
	results := eng.Run(ctx, target, filtered)

	// Output results.
	switch format {
	case report.FormatSARIF:
		return report.WriteSARIF(os.Stdout, target, results, "dev")
	case report.FormatJSON:
		return printer.PrintJSON(buildScanJSON(target, results))
	default:
		printer.PrintScanSummary(results)
	}
	return nil
}

// loadRules loads built-in rules from the embedded filesystem, with an optional
// override from a local directory on disk (--rules-dir flag).
func loadRules(extraDir string) ([]*rules.Rule, []rules.LoadWarning, error) {
	// Always load the embedded built-in rules first.
	loaded, warns, err := rules.LoadFS(batesian.RulesFS())
	if err != nil {
		return nil, warns, fmt.Errorf("loading built-in rules: %w", err)
	}

	// Append any user-supplied extra rules from disk.
	if extraDir != "" {
		extra, extraWarns, extraErr := rules.LoadDir(extraDir)
		warns = append(warns, extraWarns...)
		if extraErr != nil {
			return loaded, warns, fmt.Errorf("loading extra rules from %s: %w", extraDir, extraErr)
		}
		loaded = append(loaded, extra...)
	}

	return loaded, warns, nil
}

// coalesceProtocol returns "a2a/mcp" when protocol is empty.
func coalesceProtocol(p string) string {
	if p == "" {
		return "a2a + mcp"
	}
	return p
}

// splitProtocols splits a comma or space-separated protocol string into a slice.
func splitProtocols(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(strings.ToLower(p), ",")
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// fetchOAuthToken acquires a bearer token via client credentials grant.
func fetchOAuthToken(ctx context.Context, tokenURL, clientID, clientSecret string, scopes []string, audience string) (string, error) {
	tok, err := auth.FetchClientCredentialsToken(ctx, auth.ClientCredentialsConfig{
		TokenURL:     tokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Audience:     audience,
	})
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// buildScanJSON creates the JSON representation of scan results.
func buildScanJSON(target string, results []engine.RunResult) map[string]interface{} {
	type jsonFinding struct {
		RuleID      string `json:"rule_id"`
		RuleName    string `json:"rule_name"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Evidence    string `json:"evidence,omitempty"`
		Remediation string `json:"remediation,omitempty"`
		TargetURL   string `json:"target_url"`
	}

	findings := make([]jsonFinding, 0)
	skipped := make([]map[string]string, 0)

	for _, r := range results {
		for _, f := range r.Findings {
			findings = append(findings, jsonFinding{
				RuleID:      f.RuleID,
				RuleName:    f.RuleName,
				Severity:    f.Severity,
				Title:       f.Title,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: f.Remediation,
				TargetURL:   f.TargetURL,
			})
		}
		if r.Skipped {
			skipped = append(skipped, map[string]string{
				"rule_id": r.Rule.ID,
				"reason":  r.SkipMsg,
			})
		}
	}

	return map[string]interface{}{
		"target":   target,
		"findings": findings,
		"skipped":  skipped,
		"summary": map[string]int{
			"total":    engine.TotalFindings(results),
			"critical": len(engine.FindingsBySeverity(results)["critical"]),
			"high":     len(engine.FindingsBySeverity(results)["high"]),
			"medium":   len(engine.FindingsBySeverity(results)["medium"]),
			"low":      len(engine.FindingsBySeverity(results)["low"]),
			"info":     len(engine.FindingsBySeverity(results)["info"]),
		},
	}
}
