package report_test

import (
	"testing"

	"github.com/calvin-mcdowell/batesian/internal/report"
)

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    report.Format
		wantErr bool
	}{
		{input: "", want: report.FormatTable, wantErr: false},
		{input: "table", want: report.FormatTable, wantErr: false},
		{input: "TABLE", want: report.FormatTable, wantErr: false},
		{input: "json", want: report.FormatJSON, wantErr: false},
		{input: "JSON", want: report.FormatJSON, wantErr: false},
		{input: "sarif", want: report.FormatSARIF, wantErr: false},
		{input: "SARIF", want: report.FormatSARIF, wantErr: false},
		{input: "markdown", want: report.FormatTable, wantErr: true},
		{input: "md", want: report.FormatTable, wantErr: true},
		{input: "jsno", want: report.FormatTable, wantErr: true},
		{input: "xml", want: report.FormatTable, wantErr: true},
		{input: "csv", want: report.FormatTable, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := report.ParseFormat(tc.input)
			if tc.wantErr && err == nil {
				t.Errorf("ParseFormat(%q) expected error, got nil", tc.input)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ParseFormat(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
