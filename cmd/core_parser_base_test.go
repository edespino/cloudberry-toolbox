// File: cmd/core_parser_base_test.go
package cmd

import (
	"testing"
	"reflect"
)

func TestParseLocals(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:  "single key-value pair",
			input: "x=42",
			expected: map[string]string{
				"x": "42",
			},
		},
		{
			name:  "multiple key-value pairs",
			input: "x=42, y=hello, z=true",
			expected: map[string]string{
				"x": "42",
				"y": "hello",
				"z": "true",
			},
		},
		{
			name:  "pairs with whitespace",
			input: "  x = 42 ,  y = hello  ",
			expected: map[string]string{
				"x": "42",
				"y": "hello",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLocals(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseLocals(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseRegisters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty input",
			input:    "",
			expected: map[string]string{},
		},
		{
			name: "single register",
			input: "rax 0x0000000000000042",
			expected: map[string]string{
				"rax": "0x0000000000000042",
			},
		},
		{
			name: "multiple registers",
			input: `rax 0x0000000000000042
rbx 0x0000000000000001
rcx 0x0000000000000000`,
			expected: map[string]string{
				"rax": "0x0000000000000042",
				"rbx": "0x0000000000000001",
				"rcx": "0x0000000000000000",
			},
		},
		{
			name: "mixed register types",
			input: `rax 0x0000000000000042
eax 0x00000042
r8  0x0000000000000100`,
			expected: map[string]string{
				"rax": "0x0000000000000042",
				"eax": "0x00000042",
				"r8":  "0x0000000000000100",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRegisters(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseRegisters(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseStackTrace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []StackFrame
	}{
		{
			name:     "empty input",
			input:    "",
			expected: nil,
		},
		{
			name: "single frame",
			input: `Thread 1:
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6`,
			expected: []StackFrame{
				{
					FrameNum:  "0",
					Location:  "0x00007f8b4c37c425",
					Function:  "raise",
					Module:    "libc.so.6",
				},
			},
		},
		{
			name: "multiple frames with source info",
			input: `Thread 1:
#0  0x00007f8b4c37c425 in raise () from /lib64/libc.so.6
#1  0x00005555555f6789 in ErrorHandler (code=11) at error.c:123
#2  0x00005555555f6790 in main (argc=1, argv=0x7fffffffea48) at main.c:456`,
			expected: []StackFrame{
				{
					FrameNum:  "0",
					Location:  "0x00007f8b4c37c425",
					Function:  "raise",
					Module:    "libc.so.6",
				},
				{
					FrameNum:   "1",
					Location:   "0x00005555555f6789",
					Function:   "ErrorHandler",
					Arguments: "code=11",
					SourceFile: "error.c",
					LineNumber: 123,
				},
				{
					FrameNum:   "2",
					Location:   "0x00005555555f6790",
					Function:   "main",
					Arguments: "argc=1, argv=0x7fffffffea48",
					SourceFile: "main.c",
					LineNumber: 456,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStackTrace(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseStackTrace(%q) =\n%+v\nwant:\n%+v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		haystack string
		needles  []string
		expected bool
	}{
		{
			name:     "empty haystack and needles",
			haystack: "",
			needles:  []string{},
			expected: false,
		},
		{
			name:     "single needle found",
			haystack: "hello world",
			needles:  []string{"world"},
			expected: true,
		},
		{
			name:     "multiple needles, one found",
			haystack: "hello world",
			needles:  []string{"foo", "world", "bar"},
			expected: true,
		},
		{
			name:     "no needles found",
			haystack: "hello world",
			needles:  []string{"foo", "bar"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAny(tt.haystack, tt.needles)
			if result != tt.expected {
				t.Errorf("containsAny(%q, %v) = %v, want %v", 
					tt.haystack, tt.needles, result, tt.expected)
			}
		})
	}
}

func TestIsSystemFunction(t *testing.T) {
	tests := []struct {
		name     string
		funcName string
		expected bool
	}{
		{
			name:     "standard library function",
			funcName: "std::vector",
			expected: true,
		},
		{
			name:     "internal function",
			funcName: "__libc_start",
			expected: true,
		},
		{
			name:     "system function",
			funcName: "clone",
			expected: true,
		},
		{
			name:     "user function",
			funcName: "processQuery",
			expected: false,
		},
		{
			name:     "empty function name",
			funcName: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSystemFunction(tt.funcName)
			if result != tt.expected {
				t.Errorf("isSystemFunction(%q) = %v, want %v", 
					tt.funcName, result, tt.expected)
			}
		})
	}
}
