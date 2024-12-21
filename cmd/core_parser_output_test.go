// File: cmd/core_parser_output_test.go
package cmd

import (
	"encoding/json"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveAnalysis(t *testing.T) {
	// Create temporary directory for test output
	tmpDir, err := os.MkdirTemp("", "analysis_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Store original outputDir and formatFlag
	originalOutputDir := outputDir
	originalFormatFlag := formatFlag
	defer func() {
		outputDir = originalOutputDir
		formatFlag = originalFormatFlag
	}()

	// Set test output directory
	outputDir = tmpDir

	testAnalysis := CoreAnalysis{
		Timestamp: time.Now().Format(time.RFC3339),
		CoreFile:  "/tmp/core.1234",
		FileInfo: FileInfo{
			Size:    12345,
			Created: time.Now().Format(time.RFC3339),
			FileOutput: "core file from 'postgres'",
		},
		BasicInfo: map[string]string{
			"description": "Query Executor",
			"database_id": "5",
			"segment_id":  "1",
		},
		PostgresInfo: PostgresInfo{
			Version:   "PostgreSQL 14.2",
			GPVersion: "Cloudberry 1.0.0",
		},
		SignalInfo: SignalInfo{
			SignalName:   "SIGSEGV",
			SignalNumber: 11,
			SignalCode:   1,
		},
		Threads: []ThreadInfo{
			{
				ThreadID:  "1",
				IsCrashed: true,
				Name:      "Query Executor",
				Backtrace: []StackFrame{
					{
						FrameNum: "0",
						Function: "processQuery",
						Module:   "postgres",
					},
				},
			},
		},
	}

	tests := []struct {
		name         string
		format       string
		validateFunc func(t *testing.T, filename string)
	}{
		{
			name:   "JSON output",
			format: "json",
			validateFunc: func(t *testing.T, filename string) {
				// Read the JSON file
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatalf("Failed to read JSON file: %v", err)
				}

				// Try to parse it
				var analysis CoreAnalysis
				if err := json.Unmarshal(data, &analysis); err != nil {
					t.Errorf("Failed to parse JSON: %v", err)
				}

				// Validate key fields
				if analysis.CoreFile != testAnalysis.CoreFile {
					t.Errorf("CoreFile = %s, want %s", analysis.CoreFile, testAnalysis.CoreFile)
				}
				if analysis.PostgresInfo.Version != testAnalysis.PostgresInfo.Version {
					t.Errorf("Version = %s, want %s", 
						analysis.PostgresInfo.Version, testAnalysis.PostgresInfo.Version)
				}
			},
		},
		{
			name:   "YAML output",
			format: "yaml",
			validateFunc: func(t *testing.T, filename string) {
				// Read the YAML file
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatalf("Failed to read YAML file: %v", err)
				}

				// Try to parse it
				var analysis CoreAnalysis
				if err := yaml.Unmarshal(data, &analysis); err != nil {
					t.Errorf("Failed to parse YAML: %v", err)
				}

				// Validate key fields
				if analysis.CoreFile != testAnalysis.CoreFile {
					t.Errorf("CoreFile = %s, want %s", analysis.CoreFile, testAnalysis.CoreFile)
				}
				if analysis.PostgresInfo.Version != testAnalysis.PostgresInfo.Version {
					t.Errorf("Version = %s, want %s", 
						analysis.PostgresInfo.Version, testAnalysis.PostgresInfo.Version)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatFlag = tt.format

			// Save the analysis
			if err := saveAnalysis(testAnalysis); err != nil {
				t.Fatalf("saveAnalysis() error = %v", err)
			}

			// Find the created file
			files, err := os.ReadDir(tmpDir)
			if err != nil {
				t.Fatal(err)
			}

			var analysisFile string
			for _, f := range files {
				if strings.HasPrefix(f.Name(), "core_analysis_") && 
					strings.HasSuffix(f.Name(), "."+tt.format) {
					analysisFile = filepath.Join(tmpDir, f.Name())
					break
				}
			}

			if analysisFile == "" {
				t.Fatal("No analysis file was created")
			}

			// Validate the file
			tt.validateFunc(t, analysisFile)
		})
	}
}

func TestSaveComparison(t *testing.T) {
	// Create temporary directory for test output
	tmpDir, err := os.MkdirTemp("", "comparison_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Store original outputDir and formatFlag
	originalOutputDir := outputDir
	originalFormatFlag := formatFlag
	defer func() {
		outputDir = originalOutputDir
		formatFlag = originalFormatFlag
	}()

	// Set test output directory
	outputDir = tmpDir

	testComparison := CoreComparison{
		TotalCores: 2,
		CommonSignals: map[string]int{
			"SIGSEGV": 2,
		},
		CommonFunctions: map[string]int{
			"processQuery": 2,
		},
		CrashPatterns: []CrashPattern{
			{
				Signal:          "SIGSEGV",
				StackSignature:  []string{"processQuery"},
				OccurrenceCount: 2,
				AffectedCoreFiles: []string{
					"core.1234",
					"core.5678",
				},
			},
		},
		TimeRange: map[string]string{
			"first": time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			"last":  time.Now().Format(time.RFC3339),
		},
	}

	tests := []struct {
		name         string
		format       string
		validateFunc func(t *testing.T, filename string)
	}{
		{
			name:   "JSON comparison",
			format: "json",
			validateFunc: func(t *testing.T, filename string) {
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatalf("Failed to read JSON file: %v", err)
				}

				var comparison CoreComparison
				if err := json.Unmarshal(data, &comparison); err != nil {
					t.Errorf("Failed to parse JSON: %v", err)
				}

				if comparison.TotalCores != testComparison.TotalCores {
					t.Errorf("TotalCores = %d, want %d", 
						comparison.TotalCores, testComparison.TotalCores)
				}
			},
		},
		{
			name:   "YAML comparison",
			format: "yaml",
			validateFunc: func(t *testing.T, filename string) {
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatalf("Failed to read YAML file: %v", err)
				}

				var comparison CoreComparison
				if err := yaml.Unmarshal(data, &comparison); err != nil {
					t.Errorf("Failed to parse YAML: %v", err)
				}

				if comparison.TotalCores != testComparison.TotalCores {
					t.Errorf("TotalCores = %d, want %d", 
						comparison.TotalCores, testComparison.TotalCores)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			formatFlag = tt.format

			if err := saveComparison(testComparison); err != nil {
				t.Fatalf("saveComparison() error = %v", err)
			}

			// Find the created file
			files, err := os.ReadDir(tmpDir)
			if err != nil {
				t.Fatal(err)
			}

			var comparisonFile string
			for _, f := range files {
				if strings.HasPrefix(f.Name(), "core_comparison_") && 
					strings.HasSuffix(f.Name(), "."+tt.format) {
					comparisonFile = filepath.Join(tmpDir, f.Name())
					break
				}
			}

			if comparisonFile == "" {
				t.Fatal("No comparison file was created")
			}

			tt.validateFunc(t, comparisonFile)
		})
	}
}
