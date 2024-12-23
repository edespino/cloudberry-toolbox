// File: cmd/flags.go
package cmd

import (
	"fmt"
)

// Shared command flags
var (
	formatFlag string // Common flag for output format (yaml/json)
)

// validateFormat checks if the provided format is either "json" or "yaml"
func validateFormat(format string) error {
	if format != "json" && format != "yaml" {
		return fmt.Errorf("invalid format: %s. Valid options are 'json' or 'yaml'", format)
	}
	return nil
}

// initSharedFlags initializes flags that are shared across multiple commands
func initSharedFlags() {
	// Add format flag to root command so it's available to all subcommands
	rootCmd.PersistentFlags().StringVar(&formatFlag, "format", "yaml", "Output format: yaml or json")
}
