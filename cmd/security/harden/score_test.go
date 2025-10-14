package harden_test

import (
	"testing"

	"github.com/SlashGordon/nas-manager/cmd/security/harden"
)

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		name     string
		results  []harden.HardeningResult
		expected int
		grade    string
	}{
		{
			name:     "All secure",
			results:  []harden.HardeningResult{{Secure: true}, {Secure: true}},
			expected: 100,
			grade:    "A",
		},
		{
			name:     "Half secure",
			results:  []harden.HardeningResult{{Secure: true}, {Secure: false}},
			expected: 50,
			grade:    "F",
		},
		{
			name:     "None secure",
			results:  []harden.HardeningResult{{Secure: false}, {Secure: false}},
			expected: 0,
			grade:    "F",
		},
		{
			name:     "Empty results",
			results:  []harden.HardeningResult{},
			expected: 0,
			grade:    "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := harden.CalculateScore(tt.results)
			if score.Percentage != tt.expected {
				t.Errorf("Expected percentage %d, got %d", tt.expected, score.Percentage)
			}
			if score.Grade != tt.grade {
				t.Errorf("Expected grade %s, got %s", tt.grade, score.Grade)
			}
		})
	}
}

func TestScoreString(t *testing.T) {
	score := harden.SecurityScore{Percentage: 85, Grade: "B", Passed: 17, Total: 20}
	expected := "Security Score: 85% (B) - 17/20 checks passed"
	if score.String() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, score.String())
	}
}
