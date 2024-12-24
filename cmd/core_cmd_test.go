// File: cmd/core_cmd_test.go
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreCommand(t *testing.T) {
	// Create temporary test directory
	tmpDir, err := os.MkdirTemp("", "core_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create mock GPHOME directory structure
	mockGPHOME := filepath.Join(tmpDir, "gphome")
	mockBinDir := filepath.Join(mockGPHOME, "bin")
	if err := os.MkdirAll(mockBinDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock postgres binary
	mockPostgres := filepath.Join(mockBinDir, "postgres")
	if err := os.WriteFile(mockPostgres, []byte("mock postgres binary"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock core file
	mockCorePath := filepath.Join(tmpDir, "core.1234")
	if err := os.WriteFile(mockCorePath, []byte("mock core file"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create mock output directory
	mockOutputDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(mockOutputDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Store original values
	origOutputDir := outputDir
	origGPHOME := os.Getenv("GPHOME")
	origFormat := formatFlag

	// Restore original values after test
	defer func() {
		outputDir = origOutputDir
		os.Setenv("GPHOME", origGPHOME)
		formatFlag = origFormat
	}()

	tests := []struct {
		name        string
		args        []string
		envVars     map[string]string
		outputDir   string
		format      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "no args",
			args:        []string{"core"},
			envVars:     map[string]string{"GPHOME": ""},
			outputDir:   mockOutputDir,
			format:      "yaml",
			expectError: true,
			errorMsg:    "please specify a core file or directory",
		},
		{
			name:        "missing GPHOME",
			args:        []string{"core", mockCorePath},
			envVars:     map[string]string{"GPHOME": ""},
			outputDir:   mockOutputDir,
			format:      "yaml",
			expectError: true,
			errorMsg:    "GPHOME environment variable must be set",
		},
		{
			name:        "valid args with GPHOME",
			args:        []string{"core", mockCorePath},
			envVars:     map[string]string{"GPHOME": mockGPHOME},
			outputDir:   mockOutputDir,
			format:      "yaml",
			expectError: false,
		},
		{
			name:        "invalid format flag",
			args:        []string{"core", "--format", "invalid", mockCorePath},
			envVars:     map[string]string{"GPHOME": mockGPHOME},
			outputDir:   mockOutputDir,
			format:      "invalid",
			expectError: true,
			errorMsg:    "invalid format",
		},
		{
			name:        "non-existent core file",
			args:        []string{"core", filepath.Join(tmpDir, "nonexistent.core")},
			envVars:     map[string]string{"GPHOME": mockGPHOME},
			outputDir:   mockOutputDir,
			format:      "yaml",
			expectError: true,
			errorMsg:    "no such file or directory",
		},
		{
			name:        "invalid output directory",
			args:        []string{"core", mockCorePath},
			envVars:     map[string]string{"GPHOME": mockGPHOME},
			outputDir:   "/nonexistent/dir",
			format:      "yaml",
			expectError: true,
			errorMsg:    "failed to create output directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up test environment
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}
			outputDir = tt.outputDir
			formatFlag = tt.format

			// Create a new command for testing
			rootCmd.SetArgs(tt.args)
			err := rootCmd.Execute()

			// Verify error conditions
			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("error message = %q, want to contain %q", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Verify output file was created for successful cases
				if !tt.expectError {
					files, err := os.ReadDir(tt.outputDir)
					if err != nil {
						t.Errorf("failed to read output directory: %v", err)
					}
					if len(files) == 0 {
						t.Error("no output files were created")
					}
				}
			}
		})
	}
}
