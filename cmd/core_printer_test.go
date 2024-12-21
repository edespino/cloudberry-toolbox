// File: cmd/core_printer_test.go
package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// captureOutput captures stdout during test execution
func capturePrinterOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintGDBStyle(t *testing.T) {
	tests := []struct {
		name     string
		analysis CoreAnalysis
		wants    []string // Strings that should appear in output
		nots     []string // Strings that should not appear in output
	}{
		{
			name: "basic analysis output",
			analysis: CoreAnalysis{
				Timestamp: time.Now().Format(time.RFC3339),
				CoreFile:  "/tmp/core.1234",
				BasicInfo: map[string]string{
					"description": "Coordinator Write Process, DB 5, segment 1",
				},
				PostgresInfo: PostgresInfo{
					Version:   "PostgreSQL 14.2",
					GPVersion: "Cloudberry 1.0.0",
				},
				SignalInfo: SignalInfo{
					SignalName:        "SIGSEGV",
					SignalNumber:      11,
					SignalDescription: "Segmentation fault",
				},
				Threads: []ThreadInfo{
					{
						ThreadID:  "1",
						LWPID:     "1234",
						IsCrashed: true,
						Name:      "Query Executor",
						Backtrace: []StackFrame{
							{
								FrameNum:  "0",
								Function:  "raise",
								Location:  "0x7fff1234",
								Module:    "libc.so.6",
							},
						},
					},
				},
			},
			wants: []string{
				"Cloudberry Database Core Analysis",
				"Coordinator Write Process",
				"PostgreSQL 14.2",
				"Cloudberry 1.0.0",
				"SIGSEGV",
				"Thread 1 [LWP 1234] (Query Executor) (Crashed)",
				"#0  0x7fff1234 in raise",
			},
			nots: []string{
				"unknown thread",
				"invalid signal",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(func() {
				err := printGDBStyle(tt.analysis)
				if err != nil {
					t.Errorf("printGDBStyle() error = %v", err)
				}
			})

			// Check for required strings
			for _, want := range tt.wants {
				if !strings.Contains(output, want) {
					t.Errorf("output missing expected string %q", want)
				}
			}

			// Check for strings that shouldn't appear
			for _, not := range tt.nots {
				if strings.Contains(output, not) {
					t.Errorf("output contains unexpected string %q", not)
				}
			}
		})
	}
}

func TestPrintThreads(t *testing.T) {
	tests := []struct {
		name     string
		analysis CoreAnalysis
		wants    []string
		nots     []string
	}{
		{
			name: "multiple threads with crash",
			analysis: CoreAnalysis{
				Threads: []ThreadInfo{
					{
						ThreadID:  "1",
						LWPID:     "1234",
						IsCrashed: true,
						Name:      "Query Executor",
						Backtrace: []StackFrame{
							{
								FrameNum:  "0",
								Function:  "raise",
								Location:  "0x7fff1234",
								Module:    "libc.so.6",
							},
						},
					},
					{
						ThreadID: "2",
						LWPID:    "1235",
						Name:     "Background Writer",
						Backtrace: []StackFrame{
							{
								FrameNum:  "0",
								Function:  "write",
								Location:  "0x7fff5678",
								Module:    "libc.so.6",
							},
						},
					},
				},
			},
			wants: []string{
				"Thread Information",
				"Thread 1 (Query Executor) (Crashed)",
				"Thread 2 (Background Writer)",
				"#0  0x7fff1234 in raise",
				"#0  0x7fff5678 in write",
			},
			nots: []string{
				"unknown thread",
				"invalid frame",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(func() {
				printThreads(tt.analysis)
			})

			for _, want := range tt.wants {
				if !strings.Contains(output, want) {
					t.Errorf("output missing expected string %q", want)
				}
			}

			for _, not := range tt.nots {
				if strings.Contains(output, not) {
					t.Errorf("output contains unexpected string %q", not)
				}
			}
		})
	}
}

func TestPrintRegisters(t *testing.T) {
	tests := []struct {
		name     string
		analysis CoreAnalysis
		wants    []string
		nots     []string
	}{
		{
			name: "x86_64 registers",
			analysis: CoreAnalysis{
				Registers: map[string]string{
					"rax": "0x0000000000000042",
					"rbx": "0x0000000000000001",
					"rcx": "0x0000000000000000",
					"rip": "0x00007fff1234abcd",
					"rsp": "0x00007fffffffea48",
					"rbp": "0x00007fffffffea60",
				},
			},
			wants: []string{
				"Register State",
				"rax:",
				"0x0000000000000042",
				"rip:",
				"0x00007fff1234abcd",
			},
			nots: []string{
				"invalid register",
				"unknown value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(func() {
				printRegisters(tt.analysis)
			})

			for _, want := range tt.wants {
				if !strings.Contains(output, want) {
					t.Errorf("output missing expected string %q", want)
				}
			}

			for _, not := range tt.nots {
				if strings.Contains(output, not) {
					t.Errorf("output contains unexpected string %q", not)
				}
			}
		})
	}
}

func TestPrintLibrarySummary(t *testing.T) {
    tests := []struct {
        name     string
        analysis CoreAnalysis
        wants    []string
    }{
        {
            name: "mixed libraries",
            analysis: CoreAnalysis{
                Libraries: []LibraryInfo{
                    {
                        Name:     "libpostgres.so.5.1",
                        Type:     "Core",
                        Version:  "5.1",
                        IsLoaded: true,
                    },
                    {
                        Name:     "libssl.so.1.1",
                        Type:     "Security",
                        Version:  "1.1",
                        IsLoaded: true,
                    },
                    {
                        Name:     "libpython3.so",
                        Type:     "Extension",
                        IsLoaded: false,
                    },
                },
            },
            wants: []string{
                "Shared Library Summary",
                "Cloudberry Core:",
                "libpostgres.so",
                "Security Libraries:",
                "libssl.so",
                "Unloaded Libraries:",
                "libpython3.so",
                "Library Statistics:",
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            output := capturePrinterOutput(func() {
                printLibrarySummary(tt.analysis)
            })

            for _, want := range tt.wants {
                if !strings.Contains(output, want) {
                    t.Errorf("output missing expected string %q", want)
                }
            }
        })
    }
}
