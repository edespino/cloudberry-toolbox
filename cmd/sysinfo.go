// Description:
// This file is part of the Cloudberry toolbox. It implements the `sysinfo` command
// to gather and display detailed system and database environment information.
//
// Features:
// - Concurrent data collection for performance optimization.
// - Flexible output formats: YAML and JSON.
// - System information such as OS, kernel, memory, CPUs, and environment variables.
// - Database information:
//   * GPHOME environment validation
//   * PostgreSQL build configuration from pg_config --configure
//   * PostgreSQL server version from postgres --version
//   * Cloudberry Database version from postgres --gp-version
//
// Usage:
// - Run the `sysinfo` command to gather system diagnostics.
// - Example: `cloudberry-toolbox sysinfo --format=json`
//
// Output includes:
// - System:
//   * Operating System and version
//   * Architecture
//   * Kernel version
//   * Hostname
//   * CPU count
//   * Memory statistics (Total, Free, Available, Cached, Buffers)
// - Database:
//   * GPHOME path
//   * PostgreSQL build configuration
//   * PostgreSQL server version
//   * Cloudberry Database version
//
// Note:
// - Designed for Linux-like systems with utilities such as `uname` and `/proc/meminfo`.
// - Requires GPHOME to be set and accessible for database-specific information.
// - Handles errors gracefully and provides a summary of issues if any occur.
//

// Package cmd provides command-line interface functionality for the Cloudberry toolbox.
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// procMeminfo defines the path to the system's memory information file.
var procMeminfo = "/proc/meminfo"

// SysInfo contains system and environment information collected by the sysinfo command.
type SysInfo struct {
    // OS is the operating system name.
    OS string `json:"os" yaml:"os"`
    
    // Architecture is the system's CPU architecture.
    Architecture string `json:"architecture" yaml:"architecture"`
    
    // Hostname is the system's network name.
    Hostname string `json:"hostname" yaml:"hostname"`
    
    // Kernel is the Linux kernel version.
    Kernel string `json:"kernel" yaml:"kernel"`
    
    // OSVersion is the detailed operating system version information.
    OSVersion string `json:"os_version" yaml:"os_version"`
    
    // CPUs is the number of CPU cores available in the system.
    CPUs int `json:"cpus" yaml:"cpus"`
    
    // MemoryStats contains memory-related statistics including total, free,
    // available, cached, and buffer memory in human-readable format.
    MemoryStats map[string]string `json:"memory_stats" yaml:"memory_stats"`
    
    // GPHOME is the installation directory path for Cloudberry Database.
    // This field is omitted if GPHOME is not set.
    GPHOME string `json:"GPHOME,omitempty" yaml:"GPHOME,omitempty"`
    
    // PGConfigConfigure contains PostgreSQL build configuration options.
    // This field is omitted if GPHOME is not set.
    PGConfigConfigure []string `json:"pg_config_configure,omitempty" yaml:"pg_config_configure,omitempty"`
    
    // PostgresVersion is the PostgreSQL server version string.
    // This field is omitted if GPHOME is not set.
    PostgresVersion string `json:"postgres_version,omitempty" yaml:"postgres_version,omitempty"`
    
    // GPVersion is the Cloudberry Database version string.
    // This field is omitted if GPHOME is not set.
    GPVersion string `json:"gp_version,omitempty" yaml:"gp_version,omitempty"`
}

// sysinfoCmd represents the sysinfo command that gathers and displays system information.
// It supports output in either YAML (default) or JSON format via the --format flag.
var sysinfoCmd = &cobra.Command{
    Use:   "sysinfo",
    Short: "Display system information",
    Long:  `Gather and display detailed system and database environment information.`,
    RunE: func(cmd *cobra.Command, args []string) error {
        return RunSysInfo(cmd, args)
    },
}

// getOS returns the operating system name using runtime information.
func getOS() string {
	return runtime.GOOS
}

// getArchitecture returns the system's CPU architecture using runtime information.
func getArchitecture() string {
	return runtime.GOARCH
}

// getHostname returns the system's network hostname.
// Returns an error if the hostname cannot be retrieved.
func getHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: failed to retrieve hostname: %w", err)
	}
	return hostname, nil
}

// getKernelVersion returns the Linux kernel version by executing 'uname -r'.
// The returned string is prefixed with "Linux " for consistency.
// Returns an error if the uname command fails.
func getKernelVersion() (string, error) {
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "", fmt.Errorf("kernel: failed to retrieve version: %w", err)
	}
	return "Linux " + strings.TrimSpace(string(output)), nil
}

// getOSVersion returns the operating system version from /etc/os-release.
// It extracts the PRETTY_NAME field from the file.
// Returns "unknown" if the PRETTY_NAME field is not found.
// Returns an error if the file cannot be read.
func getOSVersion() (string, error) {
	output, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", fmt.Errorf("os-release: failed to read file: %w", err)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.Split(line, "=")[1], `"`), nil
		}
	}
	return "unknown", nil
}

// getCPUCount returns the number of CPU cores available to the system
// using runtime information.
func getCPUCount() int {
	return runtime.NumCPU()
}

// getReadableMemoryStats returns memory statistics from /proc/meminfo in a human-readable format.
// The returned map includes MemTotal, MemFree, MemAvailable, Cached, and Buffers,
// with values converted to appropriate units (KiB, MiB, GiB).
// Returns an error if the meminfo file cannot be read or parsed.
func getReadableMemoryStats() (map[string]string, error) {
	output, err := os.ReadFile(procMeminfo)
	if err != nil {
		return nil, fmt.Errorf("meminfo: failed to read file: %w", err)
	}
	
	lines := strings.Split(string(output), "\n")
	memoryStats := make(map[string]string)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value := fields[1] // Raw value in kB
		if key == "MemTotal" || key == "MemFree" || key == "MemAvailable" || key == "Cached" || key == "Buffers" {
			converted := humanizeSize(value)
			memoryStats[key] = converted
		}
	}
	return memoryStats, nil
}

// humanizeSize converts a memory size from kilobytes to a human-readable string.
// Input is a string representing kilobytes.
// Output format is:
// - For values >= 1024*1024 KB: X.X GiB
// - For values >= 1024 KB: X.X MiB
// - For values < 1024 KB: X KiB
// Returns the input string unchanged if it cannot be parsed as an integer.
func humanizeSize(kb string) string {
	kbInt, err := strconv.Atoi(kb)
	if err != nil {
		return kb
	}
	switch {
	case kbInt >= 1024*1024:
		return fmt.Sprintf("%.1f GiB", float64(kbInt)/(1024*1024))
	case kbInt >= 1024:
		return fmt.Sprintf("%.1f MiB", float64(kbInt)/1024)
	default:
		return fmt.Sprintf("%d KiB", kbInt)
	}
}

// getGPHOME returns the value of the GPHOME environment variable and validates the path.
// Returns an error if:
// - GPHOME environment variable is not set
// - GPHOME directory does not exist
func getGPHOME() (string, error) {
	gphome := os.Getenv("GPHOME")
	if gphome == "" {
		return "", fmt.Errorf("GPHOME: environment variable not set")
	}
	if _, err := os.Stat(gphome); os.IsNotExist(err) {
		return gphome, fmt.Errorf("GPHOME: directory does not exist: %s", gphome)
	}
	return gphome, nil
}

// getPGConfigConfigure returns PostgreSQL build configuration options by executing 'pg_config --configure'.
// Requires a valid GPHOME path as input.
// Returns an error if:
// - pg_config executable is not found in GPHOME/bin
// - pg_config command execution fails
func getPGConfigConfigure(gphome string) ([]string, error) {
	pgConfigPath := filepath.Join(gphome, "bin", "pg_config")
	if _, err := os.Stat(pgConfigPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("pg_config: file not found at %s", pgConfigPath)
	}

	cmd := exec.Command(pgConfigPath, "--configure")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pg_config: failed to execute: %w", err)
	}
	config := strings.ReplaceAll(strings.TrimSpace(string(output)), "'", "")
	return strings.Fields(config), nil
}

// getPostgresVersion returns the PostgreSQL server version by executing 'postgres --version'.
// Requires a valid GPHOME path as input.
// Returns an error if:
// - postgres executable is not found in GPHOME/bin
// - postgres command execution fails
func getPostgresVersion(gphome string) (string, error) {
    postgresPath := filepath.Join(gphome, "bin", "postgres")
    if _, err := os.Stat(postgresPath); os.IsNotExist(err) {
        return "", fmt.Errorf("postgres: executable not found at %s", postgresPath)
    }

    cmd := exec.Command(postgresPath, "--version")
    output, err := cmd.Output()
    if err != nil {
        return "", fmt.Errorf("postgres: failed to execute version check: %w", err)
    }
    return strings.TrimSpace(string(output)), nil
}

// getGPVersion returns the Cloudberry Database version by executing 'postgres --gp-version'.
// Requires a valid GPHOME path as input.
// Returns an error if:
// - postgres executable is not found in GPHOME/bin
// - postgres command execution fails
func getGPVersion(gphome string) (string, error) {
    postgresPath := filepath.Join(gphome, "bin", "postgres")
    if _, err := os.Stat(postgresPath); os.IsNotExist(err) {
        return "", fmt.Errorf("postgres: executable not found at %s", postgresPath)
    }

    cmd := exec.Command(postgresPath, "--gp-version")
    output, err := cmd.Output()
    if err != nil {
        return "", fmt.Errorf("postgres: failed to execute gp-version check: %w", err)
    }
    return strings.TrimSpace(string(output)), nil
}

// gatherGPHOMEInfo collects all database-related information.
// Returns:
// - string: GPHOME path if valid
// - []string: PostgreSQL build configuration options
// - string: PostgreSQL server version
// - string: Cloudberry Database version
// - []error: Collection of any errors encountered during information gathering
// If GPHOME is not set or invalid, returns appropriate error messages for each
// component that could not be checked.
func gatherGPHOMEInfo() (string, []string, string, string, []error) {
    gphome, gphomeErr := getGPHOME()
    var pgConfig []string
    var postgresVersion string
    var gpVersion string
    var errs []error

    if gphomeErr != nil {
        errs = append(errs, fmt.Errorf("GPHOME error: %w", gphomeErr))
    }

    if gphome != "" {
        // Get pg_config info
        config, err := getPGConfigConfigure(gphome)
        if err != nil {
            errs = append(errs, fmt.Errorf("pg_config error: %w", err))
        } else {
            pgConfig = config
        }

        // Get postgres version
        version, err := getPostgresVersion(gphome)
        if err != nil {
            errs = append(errs, fmt.Errorf("postgres version error: %w", err))
        } else {
            postgresVersion = version
        }

        // Get GP version
        gpVer, err := getGPVersion(gphome)
        if err != nil {
            errs = append(errs, fmt.Errorf("gp version error: %w", err))
        } else {
            gpVersion = gpVer
        }
    } else {
        errs = append(errs, fmt.Errorf("pg_config_configure: cannot check as GPHOME is invalid"))
        errs = append(errs, fmt.Errorf("postgres_version: cannot check as GPHOME is invalid"))
        errs = append(errs, fmt.Errorf("gp_version: cannot check as GPHOME is invalid"))
    }

    return gphome, pgConfig, postgresVersion, gpVersion, errs
}

// RunSysInfo gathers and displays system and database information.
// Performs concurrent collection of system information and sequential collection
// of database information if GPHOME is properly configured.
//
// System information collected:
// - Operating system and version
// - System architecture
// - Hostname
// - Kernel version
// - CPU count
// - Memory statistics
//
// Database information collected (when GPHOME is set):
// - PostgreSQL build configuration
// - PostgreSQL server version
// - Cloudberry Database version
//
// The output format is determined by the global formatFlag ("yaml" or "json").
// Any errors encountered during collection are displayed in a summary before
// the output. Returns an error if:
// - The format is invalid
// - Required system information cannot be collected
// - Database information cannot be collected when GPHOME is set
func RunSysInfo(cmd *cobra.Command, args []string) error {
    if err := validateFormat(formatFlag); err != nil {
        return err
    }

    var wg sync.WaitGroup
    var mu sync.Mutex

    info := SysInfo{}
    errs := make([]error, 0)

    // Concurrent data collection
    wg.Add(7)
    go func() { defer wg.Done(); info.OS = getOS() }()
    go func() { defer wg.Done(); info.Architecture = getArchitecture() }()
    go func() { defer wg.Done(); if hostname, err := getHostname(); err == nil { info.Hostname = hostname } else { mu.Lock(); errs = append(errs, err); mu.Unlock() } }()
    go func() { defer wg.Done(); if kernel, err := getKernelVersion(); err == nil { info.Kernel = kernel } else { mu.Lock(); errs = append(errs, err); mu.Unlock() } }()
    go func() { defer wg.Done(); if osVersion, err := getOSVersion(); err == nil { info.OSVersion = osVersion } else { mu.Lock(); errs = append(errs, err); mu.Unlock() } }()
    go func() { defer wg.Done(); info.CPUs = getCPUCount() }()
    go func() { 
        defer wg.Done()
        if memStats, err := getReadableMemoryStats(); err == nil {
            mu.Lock()
            info.MemoryStats = memStats
            mu.Unlock()
        } else {
            mu.Lock()
            info.MemoryStats = map[string]string{"error": err.Error()}
            errs = append(errs, err)
            mu.Unlock()
        }
    }()

    // Collect optional GPHOME info
    gphome, pgConfig, postgresVersion, gpVersion, gphomeErrs := gatherGPHOMEInfo()
    if gphome != "" {
        info.GPHOME = gphome
        info.PGConfigConfigure = pgConfig
        info.PostgresVersion = postgresVersion
        info.GPVersion = gpVersion
    }
    
    wg.Wait()

    // Log errors but don't fail if they're only from optional components
    if len(errs) > 0 || len(gphomeErrs) > 0 {
        fmt.Println("\nSummary of errors:")
        for _, err := range errs {
            fmt.Println("-", err)
        }
        for _, err := range gphomeErrs {
            fmt.Println("-", err)
        }
        
        // Only fail if we have errors from required components
        if len(errs) > 0 || len(gphomeErrs) > 0 {
            return fmt.Errorf("errors occurred during system info collection")
        }
    }

    var output []byte
    var err error
    if formatFlag == "json" {
        output, err = json.MarshalIndent(info, "", "  ")
    } else {
        output, err = yaml.Marshal(info)
    }
    if err != nil {
        return fmt.Errorf("output: failed to generate: %w", err)
    }

    fmt.Println(string(output))
    return nil
}

// init initializes the sysinfo command and its flags.
// Sets up the following:
// - Adds sysinfo command to the root command
// - Initializes the format flag with default value "yaml"
func init() {
    // Initialize the sysinfo command with a format flag
    sysinfoCmd.Flags().StringVar(&formatFlag, "format", "yaml", "Output format: yaml or json")
    rootCmd.AddCommand(sysinfoCmd)
}
