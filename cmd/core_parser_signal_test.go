// File: cmd/core_parser_signal_test.go
package cmd

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSignalInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected SignalInfo
	}{
		{
			name: "SIGSEGV basic",
			input: `si_signo = 11
si_code = 1
si_addr = 0x0000000000000000`,
			expected: SignalInfo{
				SignalNumber:      11,
				SignalCode:        1,
				SignalName:        "SIGSEGV",
				SignalDescription: "Segmentation fault - SEGV_MAPERR (Address not mapped to object)",
			},
		},
		{
			name: "SIGABRT with fault info",
			input: `si_signo = 6
si_code = 0
_sigfault = {si_addr = 0x00007f8b4c37c425}`,
			expected: SignalInfo{
				SignalNumber:      6,
				SignalCode:        0,
				SignalName:        "SIGABRT",
				SignalDescription: "Process abort signal (possibly assertion failure)",
				FaultInfo: &SignalFault{
					Address: "0x00007f8b4c37c425",
				},
			},
		},
		{
			name: "SIGBUS with code",
			input: `si_signo = 7
si_code = 2
_sigfault = {si_addr = 0x00007ffff7ff1000}`,
			expected: SignalInfo{
				SignalNumber:      7,
				SignalCode:        2,
				SignalName:        "SIGBUS",
				SignalDescription: "Bus error - BUS_ADRERR (Nonexistent physical address)",
				FaultInfo: &SignalFault{
					Address: "0x00007ffff7ff1000",
				},
			},
		},
		{
			name: "Empty input",
			input: "",
			expected: SignalInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSignalInfo(tt.input)
			
			// Compare relevant fields
			if result.SignalNumber != tt.expected.SignalNumber {
				t.Errorf("SignalNumber = %d, want %d", result.SignalNumber, tt.expected.SignalNumber)
			}
			if result.SignalCode != tt.expected.SignalCode {
				t.Errorf("SignalCode = %d, want %d", result.SignalCode, tt.expected.SignalCode)
			}
			if result.SignalName != tt.expected.SignalName {
				t.Errorf("SignalName = %s, want %s", result.SignalName, tt.expected.SignalName)
			}
			if !strings.Contains(result.SignalDescription, tt.expected.SignalDescription) {
				t.Errorf("SignalDescription = %s, should contain %s", 
					result.SignalDescription, tt.expected.SignalDescription)
			}
		})
	}
}

func TestGetSignalName(t *testing.T) {
	tests := []struct {
		name     string
		signo    int
		expected string
	}{
		{"SIGHUP", 1, "SIGHUP"},
		{"SIGINT", 2, "SIGINT"},
		{"SIGQUIT", 3, "SIGQUIT"},
		{"SIGILL", 4, "SIGILL"},
		{"SIGABRT", 6, "SIGABRT"},
		{"SIGBUS", 7, "SIGBUS"},
		{"SIGFPE", 8, "SIGFPE"},
		{"SIGSEGV", 11, "SIGSEGV"},
		{"Unknown signal", 99, "SIGNAL_99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSignalName(tt.signo)
			if result != tt.expected {
				t.Errorf("getSignalName(%d) = %s, want %s", tt.signo, result, tt.expected)
			}
		})
	}
}

func TestGetSignalDescription(t *testing.T) {
	tests := []struct {
		name     string
		signo    int
		code     int
		expected string
	}{
		{
			name:     "SIGSEGV with SEGV_MAPERR",
			signo:    11,
			code:     1,
			expected: "Segmentation fault - SEGV_MAPERR (Address not mapped to object)",
		},
		{
			name:     "SIGABRT basic",
			signo:    6,
			code:     0,
			expected: "Process abort signal (possibly assertion failure)",
		},
		{
			name:     "SIGBUS with BUS_ADRALN",
			signo:    7,
			code:     1,
			expected: "Bus error - BUS_ADRALN (Invalid address alignment)",
		},
		{
			name:     "SIGFPE with FPE_INTDIV",
			signo:    8,
			code:     1,
			expected: "Floating point exception - FPE_INTDIV (Integer divide by zero)",
		},
		{
			name:     "Unknown signal",
			signo:    99,
			code:     0,
			expected: "Signal 99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSignalDescription(tt.signo, tt.code)
			if !strings.Contains(result, tt.expected) {
				t.Errorf("getSignalDescription(%d, %d) = %s, should contain %s", 
					tt.signo, tt.code, result, tt.expected)
			}
		})
	}
}

func TestParseFaultInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *SignalFault
	}{
		{
			name: "Valid fault info",
			input: "_sigfault = {si_addr = 0x0000000000000000}",
			expected: &SignalFault{
				Address: "0x0000000000000000",
			},
		},
		{
			name: "Complex fault info",
			input: "_sigfault = {si_addr = 0x00007f8b4c37c425, addr_lsb = 3}",
			expected: &SignalFault{
				Address: "0x00007f8b4c37c425",
			},
		},
		{
			name:     "No fault info",
			input:    "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFaultInfo(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %+v", result)
				}
				return
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseFaultInfo(%s) = %+v, want %+v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDetectSignalFromStack(t *testing.T) {
	tests := []struct {
		name     string
		analysis *CoreAnalysis
		expected SignalInfo
	}{
		{
			name: "SIGSEGV in thread",
			analysis: &CoreAnalysis{
				Threads: []ThreadInfo{
					{
						IsCrashed: true,
						Backtrace: []StackFrame{
							{Function: "SigillSigsegvSigbus"},
						},
					},
					{
						Name: "Query Worker",
						Backtrace: []StackFrame{
							{Function: "processQuery"},
						},
					},
				},
			},
			expected: SignalInfo{
				SignalNumber:      11,
				SignalName:        "SIGSEGV",
				SignalDescription: "Segmentation fault in processQuery (thread: Query Worker)",
			},
		},
		{
			name: "No signal handler in stack",
			analysis: &CoreAnalysis{
				Threads: []ThreadInfo{
					{
						Backtrace: []StackFrame{
							{Function: "main"},
						},
					},
				},
			},
			expected: SignalInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectSignalFromStack(tt.analysis)
			if tt.analysis.SignalInfo.SignalNumber != tt.expected.SignalNumber {
				t.Errorf("SignalNumber = %d, want %d", 
					tt.analysis.SignalInfo.SignalNumber, tt.expected.SignalNumber)
			}
			if tt.analysis.SignalInfo.SignalName != tt.expected.SignalName {
				t.Errorf("SignalName = %s, want %s", 
					tt.analysis.SignalInfo.SignalName, tt.expected.SignalName)
			}
			if tt.expected.SignalDescription != "" &&
				!strings.Contains(tt.analysis.SignalInfo.SignalDescription, tt.expected.SignalDescription) {
				t.Errorf("SignalDescription = %s, should contain %s",
					tt.analysis.SignalInfo.SignalDescription, tt.expected.SignalDescription)
			}
		})
	}
}
