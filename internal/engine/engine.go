// Package engine orchestrates rule loading and attack execution for the scan command.
// It imports both the rules and attack packages, sitting above both in the dependency graph.
package engine

import (
	"context"
	"fmt"

	attackpkg "github.com/calvin-mcdowell/batesian/internal/attack"
	a2aattack "github.com/calvin-mcdowell/batesian/internal/attack/a2a"
	mcpattack "github.com/calvin-mcdowell/batesian/internal/attack/mcp"
	"github.com/calvin-mcdowell/batesian/internal/rules"
)

// RunResult holds the findings and any error from executing a single rule.
type RunResult struct {
	Rule     *rules.Rule
	Findings []attackpkg.Finding
	Err      error
	Skipped  bool
	SkipMsg  string
}

// Engine executes rules against a target.
type Engine struct {
	opts attackpkg.Options
}

// New creates an Engine with the given execution options.
func New(opts attackpkg.Options) *Engine {
	return &Engine{opts: opts}
}

// Run executes a slice of rules against target and returns all results.
// Errors from individual rules are captured in RunResult.Err rather than
// aborting the entire scan.
func (e *Engine) Run(ctx context.Context, target string, rs []*rules.Rule) []RunResult {
	results := make([]RunResult, 0, len(rs))
	for _, r := range rs {
		result := e.runOne(ctx, target, r)
		results = append(results, result)
	}
	return results
}

// runOne executes a single rule and returns its RunResult.
func (e *Engine) runOne(ctx context.Context, target string, r *rules.Rule) RunResult {
	executor, err := resolveExecutor(r)
	if err != nil {
		return RunResult{
			Rule:    r,
			Skipped: true,
			SkipMsg: fmt.Sprintf("no executor for attack type %q: %v", r.Attack.Type, err),
		}
	}

	findings, err := executor.Execute(ctx, target, e.opts)
	return RunResult{
		Rule:     r,
		Findings: findings,
		Err:      err,
	}
}

// resolveExecutor maps a rule's attack type to the corresponding Executor.
// It converts rules.Rule into attack.RuleContext to avoid import cycles between
// the rules and attack packages.
func resolveExecutor(r *rules.Rule) (attackpkg.Executor, error) {
	rc := attackpkg.RuleContext{
		ID:          r.ID,
		Name:        r.Info.Name,
		Severity:    r.Info.Severity,
		Remediation: r.Remediation,
	}
	switch r.Attack.Type {
	// A2A attack types
	case "extcard-unauth-disclosure":
		return a2aattack.NewExtCardExecutor(rc), nil
	case "push-notification-ssrf":
		return a2aattack.NewPushSSRFExecutor(rc), nil
	case "agent-role-injection":
		return a2aattack.NewSessionSmuggleExecutor(rc), nil
	case "agent-card-jws-algconf":
		return a2aattack.NewJWSAlgConfExecutor(rc), nil
	case "a2a-task-idor":
		return a2aattack.NewTaskIDORExecutor(rc), nil
	case "a2a-context-orphan":
		return a2aattack.NewContextOrphanExecutor(rc), nil
	// MCP attack types
	case "oauth-dcr-scope-escalation":
		return mcpattack.NewOAuthDCRExecutor(rc), nil
	case "mcp-tool-poisoning":
		return mcpattack.NewToolPoisonExecutor(rc), nil
	case "mcp-resources-unauth":
		return mcpattack.NewResourcesUnauthExecutor(rc), nil
	case "mcp-sampling-inject":
		return mcpattack.NewSamplingInjectExecutor(rc), nil
	default:
		return nil, fmt.Errorf("unknown attack type %q", r.Attack.Type)
	}
}

// TotalFindings counts the total number of findings across all results.
func TotalFindings(results []RunResult) int {
	n := 0
	for _, r := range results {
		n += len(r.Findings)
	}
	return n
}

// FindingsBySeverity groups findings by severity level.
func FindingsBySeverity(results []RunResult) map[string][]attackpkg.Finding {
	out := make(map[string][]attackpkg.Finding)
	for _, r := range results {
		for _, f := range r.Findings {
			out[f.Severity] = append(out[f.Severity], f)
		}
	}
	return out
}
