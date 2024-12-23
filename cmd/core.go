// File: cmd/core.go
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"sync"
	"strconv"
	"sort"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// CoreAnalysis represents the analysis results for a core file
type CoreAnalysis struct {
	Timestamp     string            `json:"timestamp" yaml:"timestamp"`
	CoreFile      string            `json:"core_file" yaml:"core_file"`
	FileInfo      FileInfo          `json:"file_info" yaml:"file_info"`
	BasicInfo     map[string]string `json:"basic_info" yaml:"basic_info"`
	StackTrace    []StackFrame      `json:"stack_trace" yaml:"stack_trace"`
	Threads       []ThreadInfo      `json:"threads" yaml:"threads"`
	Registers     map[string]string `json:"registers" yaml:"registers"`
	SignalInfo    SignalInfo        `json:"signal_info" yaml:"signal_info"`
	Libraries     []LibraryInfo     `json:"shared_libraries" yaml:"shared_libraries"`
	PostgresInfo  PostgresInfo      `json:"postgres_info" yaml:"postgres_info"`
}

type FileInfo struct {
	FileOutput string `json:"file_output" yaml:"file_output"`
	Size       int64  `json:"size" yaml:"size"`
	Created    string `json:"created" yaml:"created"`
}

type StackFrame struct {
	FrameNum  string `json:"frame_num" yaml:"frame_num"`
	Location  string `json:"location" yaml:"location"`
	Function  string `json:"function" yaml:"function"`
	Arguments string `json:"args" yaml:"args"`
}

type ThreadInfo struct {
	ThreadID  string       `json:"thread_id" yaml:"thread_id"`
	LWPID     string       `json:"lwp_id" yaml:"lwp_id"`
	Backtrace []StackFrame `json:"backtrace" yaml:"backtrace"`
}

type SignalInfo struct {
	SignalNumber      int    `json:"signal_number" yaml:"signal_number"`
	SignalCode        int    `json:"signal_code" yaml:"signal_code"`
	SignalName        string `json:"signal_name" yaml:"signal_name"`
	SignalDescription string `json:"signal_description" yaml:"signal_description"`
	FaultAddress      string `json:"fault_address,omitempty" yaml:"fault_address,omitempty"`
}

type LibraryInfo struct {
	Name      string `json:"name" yaml:"name"`
	StartAddr string `json:"start_addr" yaml:"start_addr"`
	EndAddr   string `json:"end_addr" yaml:"end_addr"`
}

type PostgresInfo struct {
	BinaryPath   string   `json:"binary_path" yaml:"binary_path"`
	Version      string   `json:"version" yaml:"version"`
	GPVersion    string   `json:"gp_version" yaml:"gp_version"`
	BuildOptions []string `json:"build_options" yaml:"build_options"`
}

var (
	formatFlag  string
	outputDir   string
	maxCores    int
	compareFlag bool
)

// coreCmd represents the core analysis command
var coreCmd = &cobra.Command{
	Use:   "core [core_file_or_directory]",
	Short: "Analyze PostgreSQL core files",
	Long: `Analyze PostgreSQL core files from Apache CloudBerry (Incubating).
This tool provides detailed analysis of core dumps including stack traces,
thread information, signal analysis, and shared library information.

It can analyze a single core file or multiple core files in a directory:
  cbtoolbox core /path/to/core.1234
  cbtoolbox core /var/lib/postgres/cores/ --max-cores=5

Features:
- Stack trace analysis
- Thread inspection
- Register state examination
- Signal information
- Shared library mapping
- Core file comparison for pattern detection`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("please specify a core file or directory")
		}
		return runCoreAnalysis(args[0])
	},
}

func init() {
	rootCmd.AddCommand(coreCmd)
	coreCmd.Flags().StringVar(&formatFlag, "format", "yaml", "Output format: yaml or json")
	coreCmd.Flags().StringVar(&outputDir, "output-dir", "/var/log/postgres_cores", "Directory to store analysis results")
	coreCmd.Flags().IntVar(&maxCores, "max-cores", 0, "Maximum number of core files to analyze")
	coreCmd.Flags().BoolVar(&compareFlag, "compare", false, "Compare core files and identify patterns")
}

// runCoreAnalysis is the main entry point for core file analysis
func runCoreAnalysis(path string) error {
	if err := validateFormat(formatFlag); err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Find PostgreSQL binary
	gphome := os.Getenv("GPHOME")
	if gphome == "" {
		return fmt.Errorf("GPHOME environment variable must be set")
	}

	// Find core files
	coreFiles, err := findCoreFiles(path)
	if err != nil {
		return err
	}

	if len(coreFiles) == 0 {
		return fmt.Errorf("no core files found in %s", path)
	}

	if maxCores > 0 && len(coreFiles) > maxCores {
		fmt.Printf("Limiting analysis to %d most recent core files\n", maxCores)
		coreFiles = coreFiles[:maxCores]
	}

	var analyses []CoreAnalysis
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Process each core file
	for _, coreFile := range coreFiles {
		wg.Add(1)
		go func(cf string) {
			defer wg.Done()
			analysis, err := analyzeCoreFile(cf, gphome)
			if err != nil {
				fmt.Printf("Error analyzing %s: %v\n", cf, err)
				return
			}

			mu.Lock()
			analyses = append(analyses, analysis)
			mu.Unlock()

			// Save individual analysis
			if err := saveAnalysis(analysis); err != nil {
				fmt.Printf("Error saving analysis for %s: %v\n", cf, err)
			}
		}(coreFile)
	}

	wg.Wait()

	if len(analyses) == 0 {
		return fmt.Errorf("no core files were analyzed successfully")
	}

	// Compare core files if requested
	if compareFlag && len(analyses) > 1 {
		comparison := compareCores(analyses)
		if err := saveComparison(comparison); err != nil {
			fmt.Printf("Error saving comparison results: %v\n", err)
		}
	}

	return nil
}

// findCoreFiles locates core files in the specified path
func findCoreFiles(path string) ([]string, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fileInfo.IsDir() {
		return []string{path}, nil
	}

	var coreFiles []string
	patterns := []string{
		"core.*",
		"*.core",
		"core",
		"core-*",
		"**/core-*-*-*-*-*",
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(path, pattern))
		if err != nil {
			continue
		}
		coreFiles = append(coreFiles, matches...)
	}

	return coreFiles, nil
}

// analyzeCoreFile performs detailed analysis of a single core file
func analyzeCoreFile(corePath string, gphome string) (CoreAnalysis, error) {
	analysis := CoreAnalysis{
		Timestamp: time.Now().Format(time.RFC3339),
		CoreFile:  corePath,
	}

	// Get basic file information
	fileInfo, err := os.Stat(corePath)
	if err != nil {
		return analysis, err
	}

	analysis.FileInfo = FileInfo{
		Size:    fileInfo.Size(),
		Created: fileInfo.ModTime().Format(time.RFC3339),
	}

	// Get file type information
	cmd := exec.Command("file", corePath)
	output, err := cmd.Output()
	if err != nil {
		return analysis, fmt.Errorf("failed to get file info: %w", err)
	}
	analysis.FileInfo.FileOutput = strings.TrimSpace(string(output))

	// Find PostgreSQL binary
	postgresPath := filepath.Join(gphome, "bin", "postgres")
	if _, err := os.Stat(postgresPath); err != nil {
		return analysis, fmt.Errorf("postgres binary not found at %s", postgresPath)
	}

	// Get PostgreSQL information
	pgInfo, err := getPostgresInfo(postgresPath)
	if err != nil {
		return analysis, err
	}
	analysis.PostgresInfo = pgInfo

	// Run GDB analysis
	if err := gdbAnalysis(&analysis, postgresPath); err != nil {
		return analysis, err
	}

	return analysis, nil
}

// getPostgresInfo collects PostgreSQL binary information
func getPostgresInfo(binaryPath string) (PostgresInfo, error) {
	info := PostgresInfo{
		BinaryPath: binaryPath,
	}

	// Get PostgreSQL version
	cmd := exec.Command(binaryPath, "--version")
	output, err := cmd.Output()
	if err == nil {
		info.Version = strings.TrimSpace(string(output))
	}

	// Get CloudBerry version
	cmd = exec.Command(binaryPath, "--gp-version")
	output, err = cmd.Output()
	if err == nil {
		info.GPVersion = strings.TrimSpace(string(output))
	}

	// Get build options
	pgConfigPath := filepath.Join(filepath.Dir(binaryPath), "pg_config")
	cmd = exec.Command(pgConfigPath, "--configure")
	output, err = cmd.Output()
	if err == nil {
		info.BuildOptions = strings.Fields(strings.TrimSpace(string(output)))
	}

	return info, nil
}

// gdbAnalysis performs detailed analysis using GDB
func gdbAnalysis(analysis *CoreAnalysis, binaryPath string) error {
	gdbCmds := []string{
		"set pagination off",
		"set print pretty on",
		"set print object on",
		"info threads",
		"thread apply all bt full",
		"info registers all",
		"info signal SIGABRT",
		"info signal SIGSEGV",
		"info signal SIGBUS",
		"print $_siginfo",
		"info sharedlibrary",
		"x/1i $pc",
		"quit",
	}

	args := []string{"-nx", "--batch"}
	for _, cmd := range gdbCmds {
		args = append(args, "-ex", cmd)
	}
	args = append(args, binaryPath, analysis.CoreFile)

	cmd := exec.Command("gdb", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("GDB analysis failed: %w", err)
	}

	// Parse GDB output
	parseGDBOutput(string(output), analysis)
	return nil
}

// parseGDBOutput processes GDB output and updates the analysis structure
func parseGDBOutput(output string, analysis *CoreAnalysis) {
	// Parse stack trace
	analysis.StackTrace = parseStackTrace(output)

	// Parse threads
	analysis.Threads = parseThreads(output)

	// Parse registers
	analysis.Registers = parseRegisters(output)

	// Parse signal information
	analysis.SignalInfo = parseSignalInfo(output)

	// Parse shared libraries
	analysis.Libraries = parseSharedLibraries(output)
}

// parseStackTrace extracts stack trace information from GDB output
func parseStackTrace(output string) []StackFrame {
	var frames []StackFrame
	stackRE := regexp.MustCompile(`#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)`)

	for _, line := range strings.Split(output, "\n") {
		if matches := stackRE.FindStringSubmatch(line); matches != nil {
			frames = append(frames, StackFrame{
				FrameNum:  matches[1],
				Location:  strings.TrimSpace(matches[2]),
				Function:  matches[3],
				Arguments: matches[4],
			})
		}
	}

	return frames
}

// parseThreads extracts thread information from GDB output
func parseThreads(output string) []ThreadInfo {
	var threads []ThreadInfo
	var currentThread *ThreadInfo
	threadRE := regexp.MustCompile(`Thread\s+(\d+)\s+\(.*?(?:LWP\s+(\d+)|Thread[^)]+)\)`)

	for _, line := range strings.Split(output, "\n") {
		if matches := threadRE.FindStringSubmatch(line); matches != nil {
			if currentThread != nil {
				threads = append(threads, *currentThread)
			}
			currentThread = &ThreadInfo{
				ThreadID: matches[1],
				LWPID:    matches[2],
			}
		} else if currentThread != nil && strings.HasPrefix(line, "#") {
			frame := parseStackFrame(line)
			if frame != nil {
				currentThread.Backtrace = append(currentThread.Backtrace, *frame)
			}
		}
	}

	if currentThread != nil {
		threads = append(threads, *currentThread)
	}

	return threads
}

// parseStackFrame parses a single stack frame line
func parseStackFrame(line string) *StackFrame {
	frameRE := regexp.MustCompile(`#(\d+)\s+([^in]+)in\s+(\S+)\s*\(([^)]*)\)`)
	if matches := frameRE.FindStringSubmatch(line); matches != nil {
		return &StackFrame{
			FrameNum:  matches[1],
			Location:  strings.TrimSpace(matches[2]),
			Function:  matches[3],
			Arguments: matches[4],
		}
	}
	return nil
}

// parseRegisters extracts register information from GDB output
func parseRegisters(output string) map[string]string {
	registers := make(map[string]string)
	regRE := regexp.MustCompile(`^([re][a-z][a-z]|r\d+|[cdefgs]s|[re]ip|[re]flags)\s+(.+)`)

	for _, line := range strings.Split(output, "\n") {
		if matches := regRE.FindStringSubmatch(line); matches != nil {
			registers[matches[1]] = strings.TrimSpace(matches[2])
		}
	}
	return registers
}

// parseSignalInfo extracts signal information from GDB output
func parseSignalInfo(output string) SignalInfo {
	info := SignalInfo{}
	siginfoRE := regexp.MustCompile(`si_signo = (\d+).*?si_code = (\d+)`)
	addrRE := regexp.MustCompile(`si_addr = (0x[0-9a-fA-F]+)`)
	signalRE := regexp.MustCompile(`Signal\s+(\d+)\s+\(([A-Z]+)\)`)

	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "$_siginfo =") {
			if matches := siginfoRE.FindStringSubmatch(line); matches != nil {
				info.SignalNumber = parseInt(matches[1])
				info.SignalCode = parseInt(matches[2])
				info.SignalName = getSignalName(info.SignalNumber)
				info.SignalDescription = getSignalDescription(info.SignalNumber, info.SignalCode)
			}
			if matches := addrRE.FindStringSubmatch(line); matches != nil {
				info.FaultAddress = matches[1]
			}
		} else if matches := signalRE.FindStringSubmatch(line); matches != nil && info.SignalName == "" {
			info.SignalNumber = parseInt(matches[1])
			info.SignalName = matches[2]
			info.SignalDescription = getSignalDescription(info.SignalNumber, 0)
		}
	}

	return info
}

// parseInt safely converts string to int
func parseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// getSignalName converts signal number to name
func getSignalName(signo int) string {
	signals := map[int]string{
		1:  "SIGHUP",
		2:  "SIGINT",
		3:  "SIGQUIT",
		4:  "SIGILL",
		6:  "SIGABRT",
		8:  "SIGFPE",
		9:  "SIGKILL",
		11: "SIGSEGV",
		13: "SIGPIPE",
		14: "SIGALRM",
		15: "SIGTERM",
	}
	if name, ok := signals[signo]; ok {
		return name
	}
	return fmt.Sprintf("SIGNAL_%d", signo)
}

// getSignalDescription returns human-readable signal description
func getSignalDescription(signo, code int) string {
	switch signo {
	case 11: // SIGSEGV
		codes := map[int]string{
			1: "SEGV_MAPERR (Address not mapped to object)",
			2: "SEGV_ACCERR (Invalid permissions for mapped object)",
			3: "SEGV_BNDERR (Failed address bound checks)",
			4: "SEGV_PKUERR (Access was denied by memory protection keys)",
		}
		if desc, ok := codes[code]; ok {
			return desc
		}
		return fmt.Sprintf("SIGSEGV with code %d", code)

	case 6: // SIGABRT
		return "Process abort signal (possibly assertion failure)"

	case 7: // SIGBUS
		codes := map[int]string{
			1: "BUS_ADRALN (Invalid address alignment)",
			2: "BUS_ADRERR (Nonexistent physical address)",
			3: "BUS_OBJERR (Object-specific hardware error)",
		}
		if desc, ok := codes[code]; ok {
			return desc
		}
		return fmt.Sprintf("SIGBUS with code %d", code)

	case 8: // SIGFPE
		codes := map[int]string{
			1: "FPE_INTDIV (Integer divide by zero)",
			2: "FPE_INTOVF (Integer overflow)",
			3: "FPE_FLTDIV (Floating point divide by zero)",
			4: "FPE_FLTOVF (Floating point overflow)",
			5: "FPE_FLTUND (Floating point underflow)",
			6: "FPE_FLTRES (Floating point inexact result)",
			7: "FPE_FLTINV (Invalid floating point operation)",
			8: "FPE_FLTSUB (Subscript out of range)",
		}
		if desc, ok := codes[code]; ok {
			return desc
		}
		return fmt.Sprintf("SIGFPE with code %d", code)
	}

	return fmt.Sprintf("Signal %d with code %d", signo, code)
}

// parseSharedLibraries extracts shared library information from GDB output
func parseSharedLibraries(output string) []LibraryInfo {
	var libraries []LibraryInfo
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "0x") && strings.HasSuffix(line, ".so") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				libraries = append(libraries, LibraryInfo{
					Name:      fields[len(fields)-1],
					StartAddr: fields[0],
					EndAddr:   fields[1],
				})
			}
		}
	}
	return libraries
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
	TotalCores      int                    `json:"total_cores" yaml:"total_cores"`
	CommonSignals   map[string]int         `json:"signal_distribution" yaml:"signal_distribution"`
	CommonFunctions map[string]int         `json:"function_distribution" yaml:"function_distribution"`
	CrashPatterns   []CrashPattern        `json:"crash_patterns" yaml:"crash_patterns"`
	TimeRange       map[string]string      `json:"time_range" yaml:"time_range"`
}

// saveAnalysis saves analysis results to a file
func saveAnalysis(analysis CoreAnalysis) error {
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("core_analysis_%s.%s", timestamp, formatFlag))

	var data []byte
	var err error
	if formatFlag == "json" {
		data, err = json.MarshalIndent(analysis, "", "  ")
	} else {
		data, err = yaml.Marshal(analysis)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write analysis file: %w", err)
	}

	fmt.Printf("Analysis saved to: %s\n", filename)
	return nil
}

// compareCores analyzes multiple core files to identify patterns
func compareCores(analyses []CoreAnalysis) CoreComparison {
	comparison := CoreComparison{
		TotalCores:      len(analyses),
		CommonSignals:   make(map[string]int),
		CommonFunctions: make(map[string]int),
		TimeRange:       make(map[string]string),
	}

	// Track time range
	var firstTime, lastTime time.Time
	for i, analysis := range analyses {
		t, _ := time.Parse(time.RFC3339, analysis.Timestamp)
		if i == 0 || t.Before(firstTime) {
			firstTime = t
		}
		if i == 0 || t.After(lastTime) {
			lastTime = t
		}
	}
	comparison.TimeRange["first"] = firstTime.Format(time.RFC3339)
	comparison.TimeRange["last"] = lastTime.Format(time.RFC3339)

	// Collect signal and function distributions
	crashGroups := make(map[string][]CoreAnalysis)
	for _, analysis := range analyses {
		signal := analysis.SignalInfo.SignalName
		comparison.CommonSignals[signal]++

		// Count functions in stack traces
		for _, frame := range analysis.StackTrace {
			comparison.CommonFunctions[frame.Function]++
		}

		// Create crash signature
		var signature strings.Builder
		signature.WriteString(signal)
		for i, frame := range analysis.StackTrace {
			if i < 3 { // Use top 3 frames for signature
				signature.WriteString("|" + frame.Function)
			}
		}
		crashGroups[signature.String()] = append(crashGroups[signature.String()], analysis)
	}

	// Generate crash patterns
	for signature, group := range crashGroups {
		if len(group) > 1 { // Only include patterns that occur multiple times
			parts := strings.Split(signature, "|")
			pattern := CrashPattern{
				Signal:         parts[0],
				StackSignature: parts[1:],
				OccurrenceCount: len(group),
			}
			for _, analysis := range group {
				pattern.AffectedCoreFiles = append(pattern.AffectedCoreFiles, analysis.CoreFile)
			}
			comparison.CrashPatterns = append(comparison.CrashPatterns, pattern)
		}
	}

	// Sort patterns by occurrence count
	sort.Slice(comparison.CrashPatterns, func(i, j int) bool {
		return comparison.CrashPatterns[i].OccurrenceCount > comparison.CrashPatterns[j].OccurrenceCount
	})

	return comparison
}

// saveComparison saves comparison results to a file
func saveComparison(comparison CoreComparison) error {
	timestamp := time.Now().Format("20060102_150405")
	filename := filepath.Join(outputDir, fmt.Sprintf("core_comparison_%s.%s", timestamp, formatFlag))

	var data []byte
	var err error
	if formatFlag == "json" {
		data, err = json.MarshalIndent(comparison, "", "  ")
	} else {
		data, err = yaml.Marshal(comparison)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal comparison: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write comparison file: %w", err)
	}

	fmt.Printf("Comparison results saved to: %s\n", filename)
	return nil
}
