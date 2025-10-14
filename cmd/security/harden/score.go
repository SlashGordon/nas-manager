package harden

import (
	"fmt"

	"github.com/SlashGordon/nas-manager/internal/constants"
)

type SecurityScore struct {
	Total      int
	Passed     int
	Failed     int
	Percentage int
	Grade      string
}

func CalculateScore(results []HardeningResult) SecurityScore {
	total := len(results)
	passed := 0

	for _, result := range results {
		if result.Secure {
			passed++
		}
	}

	failed := total - passed
	percentage := 0
	if total > 0 {
		percentage = (passed * constants.Percentage100) / total
	}

	grade := getSecurityGrade(percentage)

	return SecurityScore{
		Total:      total,
		Passed:     passed,
		Failed:     failed,
		Percentage: percentage,
		Grade:      grade,
	}
}

func getSecurityGrade(percentage int) string {
	switch {
	case percentage >= constants.Percentage90:
		return "A"
	case percentage >= constants.Percentage80:
		return "B"
	case percentage >= constants.Percentage70:
		return "C"
	case percentage >= constants.Percentage60:
		return "D"
	default:
		return "F"
	}
}

func (s SecurityScore) String() string {
	return fmt.Sprintf("Security Score: %d%% (%s) - %d/%d checks passed",
		s.Percentage, s.Grade, s.Passed, s.Total)
}
