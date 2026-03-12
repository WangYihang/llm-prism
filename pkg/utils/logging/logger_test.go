package logging

import (
	"path/filepath"
	"testing"
)

func TestNew_FallbacksWhenFilesMissing(t *testing.T) {
	base := t.TempDir()
	appPath := filepath.Join(base, "app.log")
	trafficPath := filepath.Join(base, "missing", "traffic.log")
	detectionPath := filepath.Join(base, "missing", "detection.log")

	logs := New(appPath, trafficPath, detectionPath)
	if logs == nil {
		t.Fatal("expected loggers")
	}

	// Should not panic even if traffic/detection files couldn't be opened.
	logs.Traffic.Info().Msg("traffic")
	logs.Detection.Info().Msg("detection")
}
