package redactor

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// Summary returns a fully styled and rich terminal output representing the current
// proxy redaction statistics. It utilizes lipgloss for modern TUI presentation.
func (r *Redactor) Summary() string {
	stats := r.GetStats()
	var sb strings.Builder

	// Define styles
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		MarginBottom(1)

	sectionStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#04B575")).
		Underline(true).
		MarginTop(1).
		MarginBottom(1)

	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00BFFF"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FAFAFA"))

	sb.WriteString(titleStyle.Render("LLM-Prism Redaction Summary"))
	sb.WriteString("\n")

	// Section 1: Log file locations
	sb.WriteString(sectionStyle.Render("Log File Locations"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • App Log:       "), valStyle.Render(r.appLogPath)))
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Traffic Log:   "), valStyle.Render(r.trafficLogPath)))
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Detection Log: "), valStyle.Render(r.detectionLogPath)))

	// Section 2: Redactor configuration
	sb.WriteString(sectionStyle.Render("Redactor Configuration"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Rules Loaded:  "), valStyle.Render(fmt.Sprintf("%d", len(r.config.Rules)))))
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Detectors:     "), valStyle.Render(fmt.Sprintf("%d", len(r.detectors)))))

	listItemStyle := lipgloss.NewStyle().PaddingLeft(4).Foreground(lipgloss.Color("#04B575"))
	for _, d := range r.detectors {
		sb.WriteString(listItemStyle.Render(fmt.Sprintf("- %s\n", d.Type())))
	}

	if len(stats) == 0 {
		infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#F3F3F3")).Italic(true).MarginTop(1)
		sb.WriteString(infoStyle.Render("No secrets detected. Your data is clean!"))
		sb.WriteString("\n")
		// Wrap everything in a nice rounded box
		docStyle := lipgloss.NewStyle().Padding(1, 2).BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7D56F4"))
		return "\n" + docStyle.Render(strings.TrimSpace(sb.String())) + "\n"
	}

	// Section 3: Per-detector match counts
	sb.WriteString(sectionStyle.Render("Detection Stats by Detector"))
	sb.WriteString("\n")

	statsTable := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))).
		Headers("Detector Type", "Total Matches")

	var total int64
	for k, v := range stats {
		statsTable.Row(k, fmt.Sprintf("%d", v))
		total += v
	}
	statsTable.Row("TOTAL PROTECTED", fmt.Sprintf("%d", total))
	sb.WriteString(statsTable.Render())
	sb.WriteString("\n")

	// Section 4: Impact Summary
	r.mu.Lock()
	details := make([]DetectionDetail, len(r.details))
	copy(details, r.details)
	r.mu.Unlock()

	uniqueRequests := make(map[string]struct{})
	uniqueRules := make(map[string]struct{})
	ruleHitCount := make(map[string]int)
	for _, d := range details {
		if d.RequestID != "" {
			uniqueRequests[d.RequestID] = struct{}{}
		}
		uniqueRules[d.RuleID] = struct{}{}
		ruleHitCount[d.RuleID]++
	}

	sb.WriteString(sectionStyle.Render("Impact Summary"))
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Requests Affected:      "), valStyle.Render(fmt.Sprintf("%d", len(uniqueRequests)))))
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Unique Rules Triggered: "), valStyle.Render(fmt.Sprintf("%d / %d", len(uniqueRules), len(r.config.Rules)))))
	sb.WriteString(fmt.Sprintf("%s %s\n", keyStyle.Render("  • Unique Detections:      "), valStyle.Render(fmt.Sprintf("%d", len(details)))))

	// Section 5: Top triggered rules
	if len(ruleHitCount) > 0 {
		sb.WriteString(sectionStyle.Render("Top Triggered Rules"))
		sb.WriteString("\n")

		rulesTable := table.New().
			Border(lipgloss.NormalBorder()).
			BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))).
			Headers("Rule ID", "Hits")

		for ruleID, count := range ruleHitCount {
			displayID := ruleID
			if len(displayID) > 40 {
				displayID = displayID[:37] + "..."
			}
			rulesTable.Row(displayID, fmt.Sprintf("%d", count))
		}
		sb.WriteString(rulesTable.Render())
		sb.WriteString("\n")
	}

	// Section 6: Full detection details
	sb.WriteString(sectionStyle.Render("Detection Details"))
	sb.WriteString("\n")

	detailsTable := table.New().
		Border(lipgloss.NormalBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(lipgloss.Color("#999999"))).
		Headers("Request ID", "Detector", "Rule ID", "Masked Value")

	for _, d := range details {
		reqIDShort := d.RequestID
		if len(reqIDShort) > 16 {
			reqIDShort = reqIDShort[:16]
		}
		ruleIDShort := d.RuleID
		if len(ruleIDShort) > 29 {
			ruleIDShort = ruleIDShort[:26] + "..."
		}
		maskedShort := d.MaskedContent
		if len(maskedShort) > 16 {
			maskedShort = maskedShort[:13] + "..."
		}
		detailsTable.Row(reqIDShort, d.DetectorType, ruleIDShort, maskedShort)
	}
	sb.WriteString(detailsTable.Render())
	sb.WriteString("\n")

	docStyle := lipgloss.NewStyle().
		Padding(1, 2).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7D56F4"))

	return "\n" + docStyle.Render(strings.TrimSpace(sb.String())) + "\n"
}
