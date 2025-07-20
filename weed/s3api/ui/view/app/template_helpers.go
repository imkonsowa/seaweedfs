package app

import (
	"fmt"
	"strconv"
)

// formatBytes formats bytes into human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatNumber formats numbers with commas for readability
func formatNumber(num int64) string {
	str := strconv.FormatInt(num, 10)
	if len(str) <= 3 {
		return str
	}

	var result string
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(digit)
	}
	return result
}

// calculatePercent calculates percentage for progress bars
func calculatePercent(current, total int) int {
	if total == 0 {
		return 0
	}
	return int((float64(current) / float64(total)) * 100)
}
