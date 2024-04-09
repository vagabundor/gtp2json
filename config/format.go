package config

var outputFormat string

// SetOutputFormat updates the global output format setting
func SetOutputFormat(format string) {
	outputFormat = format
}

// GetOutputFormat retrieves the current global output format setting
func GetOutputFormat() string {
	return outputFormat
}
