// File: cmd/core_test.go
package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFindCoreFiles(t *testing.T) {
	// Create temporary test directory
	tmpDir, err := os.MkdirTemp("", "core_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	testFiles := []string{
		"core.12345",
		"program.core",
		"core",
		"core-worker-2024-01-01-00-00",
		filepath.Join("subdir", "core.67890"),
	}

	// Create subdirectory
	if err := os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create all test files
	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		dir := filepath.Dir(path)
		if dir != tmpDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, []byte("test core file"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create some non-core files
	nonCoreFiles := []string{
		"test.txt",
		"program.log",
	}
	for _, f := range nonCoreFiles {
		if err := os.WriteFile(filepath.Join(tmpDir, f), []byte("not a core file"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name          string
		path          string
		expectCount   int
		expectError   bool
		expectContain string // A file that should be in the results
	}{
		{
			name:          "directory with multiple cores",
			path:          tmpDir,
			expectCount:   len(testFiles),
			expectContain: "core.12345",
		},
		{
			name:          "single core file",
			path:          filepath.Join(tmpDir, "core.12345"),
			expectCount:   1,
			expectContain: "core.12345",
		},
		{
			name:        "non-existent path",
			path:        "/nonexistent/path",
			expectError: true,
		},
		{
			name:          "subdirectory core file",
			path:          filepath.Join(tmpDir, "subdir"),
			expectCount:   1,
			expectContain: "core.67890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := findCoreFiles(tt.path)

			// Check error condition
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check number of files found
			if len(files) != tt.expectCount {
				t.Errorf("found %d files, want %d", len(files), tt.expectCount)
			}

			// Check if expected file is in results
			if tt.expectContain != "" {
				found := false
				for _, f := range files {
					if filepath.Base(f) == tt.expectContain {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("did not find expected file %s in results", tt.expectContain)
				}
			}
		})
	}
}

func TestCompareCores(t *testing.T) {
	tests := []struct {
		name     string
		analyses []CoreAnalysis
		expected CoreComparison
	}{
		{
			name: "multiple similar crashes",
			analyses: []CoreAnalysis{
				{
					CoreFile: "core.1",
					SignalInfo: SignalInfo{
						SignalNumber: 11,
						SignalName:   "SIGSEGV",
					},
					StackTrace: []StackFrame{
						{Function: "processQuery"},
						{Function: "execMain"},
					},
				},
				{
					CoreFile: "core.2",
					SignalInfo: SignalInfo{
						SignalNumber: 11,
						SignalName:   "SIGSEGV",
					},
					StackTrace: []StackFrame{
						{Function: "processQuery"},
						{Function: "execMain"},
					},
				},
			},
			expected: CoreComparison{
				TotalCores: 2,
				CommonSignals: map[string]int{
					"SIGSEGV": 2,
				},
				CommonFunctions: map[string]int{
					"processQuery": 2,
					"execMain":     2,
				},
				CrashPatterns: []CrashPattern{
					{
						Signal:          "SIGSEGV",
						StackSignature:  []string{"processQuery", "execMain"},
						OccurrenceCount: 2,
						AffectedCoreFiles: []string{
							"core.1",
							"core.2",
						},
					},
				},
			},
		},
		{
			name: "different crashes",
			analyses: []CoreAnalysis{
				{
					CoreFile: "core.1",
					SignalInfo: SignalInfo{
						SignalNumber: 11,
						SignalName:   "SIGSEGV",
					},
					StackTrace: []StackFrame{
						{Function: "processQuery"},
					},
				},
				{
					CoreFile: "core.2",
					SignalInfo: SignalInfo{
						SignalNumber: 6,
						SignalName:   "SIGABRT",
					},
					StackTrace: []StackFrame{
						{Function: "Assert"},
					},
				},
			},
			expected: CoreComparison{
				TotalCores: 2,
				CommonSignals: map[string]int{
					"SIGSEGV": 1,
					"SIGABRT": 1,
				},
				CommonFunctions: map[string]int{
					"processQuery": 1,
					"Assert":      1,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareCores(tt.analyses)

			// Check basic counts
			if result.TotalCores != tt.expected.TotalCores {
				t.Errorf("TotalCores = %d, want %d", result.TotalCores, tt.expected.TotalCores)
			}

			// Check signal distribution
			if !reflect.DeepEqual(result.CommonSignals, tt.expected.CommonSignals) {
				t.Errorf("CommonSignals = %v, want %v", result.CommonSignals, tt.expected.CommonSignals)
			}

			// Check function distribution
			if !reflect.DeepEqual(result.CommonFunctions, tt.expected.CommonFunctions) {
				t.Errorf("CommonFunctions = %v, want %v", result.CommonFunctions, tt.expected.CommonFunctions)
			}

			// Check crash patterns if expected
			if len(tt.expected.CrashPatterns) > 0 {
				if len(result.CrashPatterns) != len(tt.expected.CrashPatterns) {
					t.Errorf("got %d crash patterns, want %d", 
						len(result.CrashPatterns), len(tt.expected.CrashPatterns))
				} else {
					for i, pattern := range tt.expected.CrashPatterns {
						if result.CrashPatterns[i].Signal != pattern.Signal {
							t.Errorf("Pattern[%d].Signal = %s, want %s", 
								i, result.CrashPatterns[i].Signal, pattern.Signal)
						}
						if result.CrashPatterns[i].OccurrenceCount != pattern.OccurrenceCount {
							t.Errorf("Pattern[%d].OccurrenceCount = %d, want %d",
								i, result.CrashPatterns[i].OccurrenceCount, pattern.OccurrenceCount)
						}
					}
				}
			}
		})
	}
}

func TestRunCoreAnalysis(t *testing.T) {
	// Create temporary test environment
	tmpDir, err := os.MkdirTemp("", "core_analysis_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create mock GPHOME environment
	gphome := filepath.Join(tmpDir, "gphome")
	if err := os.MkdirAll(filepath.Join(gphome, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gphome, "bin", "postgres"), []byte("mock binary"), 0755); err != nil {
		t.Fatal(err)
	}

	// Create test core file
	coreFile := filepath.Join(tmpDir, "core.12345")
	if err := os.WriteFile(coreFile, []byte("test core file"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set up test environment
	oldGPHOME := os.Getenv("GPHOME")
	os.Setenv("GPHOME", gphome)
	defer os.Setenv("GPHOME", oldGPHOME)

	// Create output directory
	outputDir = filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		path        string
		compareFlag bool
		expectError bool
		mockOutputs []string
		mockErrors  []error
	}{
		{
			name:        "single core file",
			path:        coreFile,
			compareFlag: false,
			expectError: false,
			mockOutputs: []string{
				"core file",         // file command output
				"PostgreSQL 14.2",   // postgres --version
				"Cloudberry 1.0.0",  // postgres --gp-version
				"--with-openssl",    // pg_config output
				"Thread 1",          // gdb output
			},
			mockErrors: []error{nil, nil, nil, nil, nil},
		},
		{
			name:        "directory with core file",
			path:        tmpDir,
			compareFlag: true,
			expectError: false,
			mockOutputs: []string{
				"core file",         // file command output
				"PostgreSQL 14.2",   // postgres --version
				"Cloudberry 1.0.0",  // postgres --gp-version
				"--with-openssl",    // pg_config output
				"Thread 1",          // gdb output
			},
			mockErrors: []error{nil, nil, nil, nil, nil},
		},
		{
			name:        "non-existent path",
			path:        "/nonexistent/path",
			compareFlag: false,
			expectError: true,
			mockOutputs: nil,
			mockErrors:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize MockCommander for each test case
			mockCommander := &MockCommander{
				Outputs: tt.mockOutputs,
				Errors:  tt.mockErrors,
			}
			SetCommander(mockCommander)
			defer SetCommander(RealCommander{}) // Restore the real commander after the test

			// Set compare flag
			compareFlag = tt.compareFlag

			// Run analysis
			err := runCoreAnalysis(tt.path)

			// Check error condition
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}

				// Check if output files were created
				files, err := os.ReadDir(outputDir)
				if err != nil {
					t.Fatal(err)
				}
				if len(files) == 0 {
					t.Error("no output files were created")
				}
			}
		})
	}
}

