// File: cmd/core_types.go
package cmd

// CoreAnalysis represents the complete analysis results for a core file
type CoreAnalysis struct {
	Timestamp    string            `json:"timestamp" yaml:"timestamp"`
	CoreFile     string            `json:"core_file" yaml:"core_file"`
	FileInfo     FileInfo          `json:"file_info" yaml:"file_info"`
	BasicInfo    map[string]string `json:"basic_info" yaml:"basic_info"`
	StackTrace   []StackFrame      `json:"stack_trace" yaml:"stack_trace"`
	Threads      []ThreadInfo      `json:"threads" yaml:"threads"`
	Registers    map[string]string `json:"registers" yaml:"registers"`
	SignalInfo   SignalInfo        `json:"signal_info" yaml:"signal_info"`
	Libraries    []LibraryInfo     `json:"shared_libraries" yaml:"shared_libraries"`
	PostgresInfo PostgresInfo      `json:"postgres_info" yaml:"postgres_info"`
}

// FileInfo contains basic information about the core file
type FileInfo struct {
	FileOutput string `json:"file_output" yaml:"file_output"`
	Size       int64  `json:"size" yaml:"size"`
	Created    string `json:"created" yaml:"created"`
}

// StackFrame represents a single frame in a stack trace
type StackFrame struct {
	FrameNum    string            `json:"frame_num" yaml:"frame_num"`
	Location    string            `json:"location" yaml:"location"`
	Function    string            `json:"function" yaml:"function"`
	Arguments   string            `json:"args" yaml:"args"`
	SourceFile  string            `json:"source_file,omitempty" yaml:"source_file,omitempty"`
	LineNumber  int               `json:"line_number,omitempty" yaml:"line_number,omitempty"`
	Module      string            `json:"module,omitempty" yaml:"module,omitempty"`
	Locals      map[string]string `json:"locals,omitempty" yaml:"locals,omitempty"`
}

// ThreadInfo contains information about a thread in the core file
type ThreadInfo struct {
	ThreadID   string       `json:"thread_id" yaml:"thread_id"`
	LWPID      string       `json:"lwp_id" yaml:"lwp_id"`
	Name       string       `json:"name,omitempty" yaml:"name,omitempty"`
	State      string       `json:"state,omitempty" yaml:"state,omitempty"`
	IsCrashed  bool         `json:"is_crashed,omitempty" yaml:"is_crashed,omitempty"`
	Backtrace  []StackFrame `json:"backtrace" yaml:"backtrace"`
}

// SignalInfo contains information about the signal that caused the core dump
type SignalInfo struct {
	SignalNumber      int    `json:"signal_number" yaml:"signal_number"`
	SignalCode        int    `json:"signal_code" yaml:"signal_code"`
	SignalName        string `json:"signal_name" yaml:"signal_name"`
	SignalDescription string `json:"signal_description" yaml:"signal_description"`
	FaultAddress      string `json:"fault_address,omitempty" yaml:"fault_address,omitempty"`
}

// LibraryInfo contains information about a shared library in the core file
type LibraryInfo struct {
	Name      string `json:"name" yaml:"name"`
	StartAddr string `json:"start_addr" yaml:"start_addr"`
	EndAddr   string `json:"end_addr" yaml:"end_addr"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
	Type      string `json:"type,omitempty" yaml:"type,omitempty"`
	IsLoaded  bool   `json:"is_loaded" yaml:"is_loaded"`
	TextStart string `json:"text_start,omitempty" yaml:"text_start,omitempty"`
	TextEnd   string `json:"text_end,omitempty" yaml:"text_end,omitempty"`
}

// PostgresInfo contains PostgreSQL-specific information
type PostgresInfo struct {
	BinaryPath   string   `json:"binary_path" yaml:"binary_path"`
	Version      string   `json:"version" yaml:"version"`
	GPVersion    string   `json:"gp_version" yaml:"gp_version"`
	BuildOptions []string `json:"build_options" yaml:"build_options"`
}

// CrashPattern represents a common crash pattern across core files
type CrashPattern struct {
	Signal            string   `json:"signal" yaml:"signal"`
	StackSignature    []string `json:"stack_signature" yaml:"stack_signature"`
	OccurrenceCount   int      `json:"occurrence_count" yaml:"occurrence_count"`
	AffectedCoreFiles []string `json:"core_files" yaml:"core_files"`
}

// CoreComparison represents the comparison results between multiple core files
type CoreComparison struct {
	TotalCores      int               `json:"total_cores" yaml:"total_cores"`
	CommonSignals   map[string]int    `json:"signal_distribution" yaml:"signal_distribution"`
	CommonFunctions map[string]int    `json:"function_distribution" yaml:"function_distribution"`
	CrashPatterns   []CrashPattern   `json:"crash_patterns" yaml:"crash_patterns"`
	TimeRange       map[string]string `json:"time_range" yaml:"time_range"`
}
