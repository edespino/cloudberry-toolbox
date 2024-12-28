// File: cmd/core_gdb_test.go
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Mock command executor for testing
type MockCommander struct {
	Outputs []string
	Errors  []error
	index   int
	cmds    []string
}

func (m *MockCommander) Execute(name string, args ...string) ([]byte, error) {
	// Record the command
	m.cmds = append(m.cmds, name+" "+strings.Join(args, " "))
	
	if m.index >= len(m.Outputs) {
		return nil, m.Errors[m.index]
	}
	output := m.Outputs[m.index]
	err := m.Errors[m.index]
	m.index++
	return []byte(output), err
}

func (m *MockCommander) GetCommands() []string {
	return m.cmds
}

func TestAnalyzeCoreFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "core_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a mock core file
	corePath := filepath.Join(tmpDir, "core.1234")
	if err := os.WriteFile(corePath, []byte("mock core file"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create mock GPHOME directory structure
	gphome := filepath.Join(tmpDir, "gphome")
	binDir := filepath.Join(gphome, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock postgres binary
	postgresPath := filepath.Join(binDir, "postgres")
	if err := os.WriteFile(postgresPath, []byte("mock postgres binary"), 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		mockOutputs    []string
		mockErrors     []error
		expectedError  bool
		expectedResult CoreAnalysis
	}{
		{
			name: "successful analysis",
			mockOutputs: []string{
				// file command output
				"core file from 'postgres' (signal 11)",
				// postgres --version output
				"postgres (PostgreSQL) 14.2",
				// postgres --gp-version output
				"postgres (Cloudberry Database) 1.0.0",
				// pg_config output
				"--with-openssl --with-python",
				// gdb output
				`Thread 1 (LWP 1234):
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6
#1  0x00007f8b4c37dc05 in abort () from /lib64/libc.so.6

Program received signal SIGSEGV
si_signo = 11
si_code = 1
_sigfault = {si_addr = 0x0}`,
			},
			mockErrors: []error{nil, nil, nil, nil, nil},
			expectedResult: CoreAnalysis{
				CoreFile: corePath,
				PostgresInfo: PostgresInfo{
					Version:   "postgres (PostgreSQL) 14.2",
					GPVersion: "postgres (Cloudberry Database) 1.0.0",
				},
				SignalInfo: SignalInfo{
					SignalNumber: 11,
					SignalCode:   1,
					SignalName:   "SIGSEGV",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock commander
			mock := &MockCommander{
				Outputs: tt.mockOutputs,
				Errors:  tt.mockErrors,
			}
			oldCmdExecutor := cmdExecutor
			SetCommander(mock)
			defer SetCommander(oldCmdExecutor)

			// Run analysis
			result, err := analyzeCoreFile(corePath, gphome)

			// Check error
			if tt.expectedError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// If no error expected, check results
			if !tt.expectedError {
				// Check core file path
				if result.CoreFile != tt.expectedResult.CoreFile {
					t.Errorf("CoreFile = %s, want %s", result.CoreFile, tt.expectedResult.CoreFile)
				}

				// Check PostgreSQL info
				if result.PostgresInfo.Version != tt.expectedResult.PostgresInfo.Version {
					t.Errorf("PostgresInfo.Version = %s, want %s",
						result.PostgresInfo.Version, tt.expectedResult.PostgresInfo.Version)
				}

				// Check signal info
				if result.SignalInfo.SignalNumber != tt.expectedResult.SignalInfo.SignalNumber {
					t.Errorf("SignalInfo.SignalNumber = %d, want %d",
						result.SignalInfo.SignalNumber, tt.expectedResult.SignalInfo.SignalNumber)
				}
			}

			// Check that expected commands were executed
			commands := mock.GetCommands()
			if len(commands) == 0 {
				t.Error("no commands were executed")
			}
		})
	}
}

func TestGDBAnalysis(t *testing.T) {
	tests := []struct {
		name          string
		gdbOutput     string
		expectedError bool
		checkFields   func(*testing.T, *CoreAnalysis)
	}{
		{
			name: "successful analysis",
			gdbOutput: `Thread 1 (LWP 1234):
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6
#1  0x00007f8b4c37dc05 in abort () from /lib64/libc.so.6

Program received signal SIGSEGV
si_signo = 11
si_code = 1
_sigfault = {si_addr = 0x0}

0x00007ffff7dd7000 0x00007ffff7dd8000 Yes /lib64/libc.so.6`,
			expectedError: false,
			checkFields: func(t *testing.T, analysis *CoreAnalysis) {
				if len(analysis.Threads) == 0 {
					t.Error("no threads parsed")
				}
				if analysis.SignalInfo.SignalNumber != 11 {
					t.Errorf("SignalNumber = %d, want 11", analysis.SignalInfo.SignalNumber)
				}
				if len(analysis.Libraries) == 0 {
					t.Error("no libraries parsed")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock commander
			mock := &MockCommander{
				Outputs: []string{tt.gdbOutput},
				Errors:  []error{nil},
			}
			oldCmdExecutor := cmdExecutor
			SetCommander(mock)
			defer SetCommander(oldCmdExecutor)

			// Create analysis object
			analysis := &CoreAnalysis{}

			// Run GDB analysis
			err := gdbAnalysis(analysis, "/mock/path/postgres")

			// Check error
			if tt.expectedError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// Run custom checks
			if tt.checkFields != nil {
				tt.checkFields(t, analysis)
			}
		})
	}
}
