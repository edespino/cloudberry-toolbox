// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// File: cmd/flags.go
// Purpose: Defines shared command flags and their initialization logic for the CloudBerry Database CLI.
// Includes functionality to validate and set global flags such as output format (yaml/json).

package cmd

import (
	"fmt"
)

// Shared command flags
var (
	formatFlag string // Common flag for output format (yaml/json)
)

// validateFormat checks if the provided format is either "json" or "yaml".
// Parameters:
// - format: A string representing the desired output format.
// Returns:
// - An error if the format is invalid, or nil if the format is valid.
func validateFormat(format string) error {
	if format != "json" && format != "yaml" {
		return fmt.Errorf("invalid format: %s. Valid options are 'json' or 'yaml'", format)
	}
	return nil
}

// initSharedFlags initializes flags that are shared across multiple commands.
// This includes setting up the --format flag for specifying output format.
func initSharedFlags() {
	// Add format flag to root command so it's available to all subcommands.
	rootCmd.PersistentFlags().StringVar(&formatFlag, "format", "yaml", "Output format: yaml or json")
}
