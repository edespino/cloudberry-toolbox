// File: cmd/core_parser_threads_test.go
package cmd

import (
	"reflect"
	"testing"
)

func TestParseThreads(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []ThreadInfo
	}{
		{
			name: "single thread",
			input: `Thread 1 (LWP 12345):
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6
#1  0x00007f8b4c37dc05 in abort () from /lib64/libc.so.6`,
			expected: []ThreadInfo{
				{
					ThreadID: "1",
					LWPID:    "12345",
					Backtrace: []StackFrame{
						{
							FrameNum:  "0",
							Location:  "0x00007f8b4c37c425",
							Function:  "raise",
							Module:    "libc.so.6",
						},
						{
							FrameNum:  "1",
							Location:  "0x00007f8b4c37dc05",
							Function:  "abort",
							Module:    "libc.so.6",
						},
					},
				},
			},
		},
		{
			name: "multiple threads with crash",
			input: `Thread 1 (LWP 12345):
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6

* Thread 2 (LWP 12346):
#0  0x00007f8b4c37c425 in SigillSigsegvSigbus () from /lib64/libc.so.6
#1  0x00007f8b4c37dc05 in processQuery () at query.c:123`,
			expected: []ThreadInfo{
				{
					ThreadID: "1",
					LWPID:    "12345",
					Backtrace: []StackFrame{
						{
							FrameNum:  "0",
							Location:  "0x00007f8b4c37c425",
							Function:  "raise",
							Module:    "libc.so.6",
						},
					},
				},
				{
					ThreadID:  "2",
					LWPID:     "12346",
					IsCrashed: true,
					Name:      "Signal Handler", // Should be set by determineThreadRole
					Backtrace: []StackFrame{
						{
							FrameNum:  "0",
							Location:  "0x00007f8b4c37c425",
							Function:  "SigillSigsegvSigbus",
							Module:    "libc.so.6",
						},
						{
							FrameNum:   "1",
							Location:   "0x00007f8b4c37dc05",
							Function:   "processQuery",
							SourceFile: "query.c",
							LineNumber: 123,
						},
					},
				},
			},
		},
		{
			name: "interconnect threads",
			input: `Thread 1 (LWP 12345):
#0  0x00007f8b4c37c425 in rxThreadFunc () at interconnect.c:100

Thread 2 (LWP 12346):
#0  0x00007f8b4c37c425 in txThreadFunc () at interconnect.c:200`,
			expected: []ThreadInfo{
				{
					ThreadID: "1",
					LWPID:    "12345",
					Name:     "Interconnect RX",
					Backtrace: []StackFrame{
						{
							FrameNum:   "0",
							Location:   "0x00007f8b4c37c425",
							Function:   "rxThreadFunc",
							SourceFile: "interconnect.c",
							LineNumber: 100,
						},
					},
				},
				{
					ThreadID: "2",
					LWPID:    "12346",
					Name:     "Interconnect TX",
					Backtrace: []StackFrame{
						{
							FrameNum:   "0",
							Location:   "0x00007f8b4c37c425",
							Function:   "txThreadFunc",
							SourceFile: "interconnect.c",
							LineNumber: 200,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseThreads(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("got %d threads, want %d", len(result), len(tt.expected))
			}

			for i, expectedThread := range tt.expected {
				resultThread := result[i]
				if resultThread.ThreadID != expectedThread.ThreadID {
					t.Errorf("thread %d: ThreadID = %s, want %s", 
						i, resultThread.ThreadID, expectedThread.ThreadID)
				}
				if resultThread.LWPID != expectedThread.LWPID {
					t.Errorf("thread %d: LWPID = %s, want %s", 
						i, resultThread.LWPID, expectedThread.LWPID)
				}
				if resultThread.IsCrashed != expectedThread.IsCrashed {
					t.Errorf("thread %d: IsCrashed = %v, want %v", 
						i, resultThread.IsCrashed, expectedThread.IsCrashed)
				}
				if resultThread.Name != expectedThread.Name {
					t.Errorf("thread %d: Name = %s, want %s", 
						i, resultThread.Name, expectedThread.Name)
				}
				compareBacktraces(t, resultThread.Backtrace, expectedThread.Backtrace)
			}
		})
	}
}

func TestDetermineThreadRole(t *testing.T) {
	tests := []struct {
		name      string
		backtrace []StackFrame
		expected  string
	}{
		{
			name: "signal handler thread",
			backtrace: []StackFrame{
				{Function: "SigillSigsegvSigbus"},
				{Function: "processQuery"},
			},
			expected: "Signal Handler",
		},
		{
			name: "interconnect rx thread",
			backtrace: []StackFrame{
				{Function: "rxThreadFunc"},
				{Function: "thread_start"},
			},
			expected: "Interconnect RX",
		},
		{
			name: "interconnect tx thread",
			backtrace: []StackFrame{
				{Function: "txThreadFunc"},
				{Function: "thread_start"},
			},
			expected: "Interconnect TX",
		},
		{
			name: "empty backtrace",
			backtrace: []StackFrame{},
			expected: "",
		},
		{
			name: "unrecognized thread",
			backtrace: []StackFrame{
				{Function: "unknown_function"},
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineThreadRole(tt.backtrace)
			if result != tt.expected {
				t.Errorf("determineThreadRole() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGetThreadSummary(t *testing.T) {
	tests := []struct {
		name     string
		threads  []ThreadInfo
		expected map[string]int
	}{
		{
			name: "mixed threads",
			threads: []ThreadInfo{
				{Name: "Interconnect RX"},
				{Name: "Interconnect RX"},
				{Name: "Interconnect TX"},
				{Name: "Signal Handler"},
				{
					Name: "Unknown",
					Backtrace: []StackFrame{
						{Function: "processQuery"},
					},
				},
			},
			expected: map[string]int{
				"Interconnect RX":           2,
				"Interconnect TX":           1,
				"Signal Handler":            1,
				"Unknown (processQuery)":    1,
			},
		},
		{
			name: "empty thread list",
			threads: []ThreadInfo{},
			expected: map[string]int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getThreadSummary(tt.threads)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("getThreadSummary() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function to compare backtraces
func compareBacktraces(t *testing.T, got, want []StackFrame) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d frames, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Function != want[i].Function {
			t.Errorf("frame %d: Function = %s, want %s", i, got[i].Function, want[i].Function)
		}
		if got[i].Module != want[i].Module {
			t.Errorf("frame %d: Module = %s, want %s", i, got[i].Module, want[i].Module)
		}
		if got[i].SourceFile != want[i].SourceFile {
			t.Errorf("frame %d: SourceFile = %s, want %s", i, got[i].SourceFile, want[i].SourceFile)
		}
		if got[i].LineNumber != want[i].LineNumber {
			t.Errorf("frame %d: LineNumber = %d, want %d", i, got[i].LineNumber, want[i].LineNumber)
		}
	}
}
