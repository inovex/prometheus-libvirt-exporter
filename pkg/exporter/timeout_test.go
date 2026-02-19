package exporter

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestTimeoutAfterHonorsConfiguredDuration(t *testing.T) {
	start := time.Now()
	<-timeoutAfter(25 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < 20*time.Millisecond {
		t.Fatalf("timeoutAfter returned too early: %v", elapsed)
	}

	if elapsed > 500*time.Millisecond {
		t.Fatalf("timeoutAfter returned too late: %v", elapsed)
	}
}

func TestTimeoutAfterZeroReturnsImmediately(t *testing.T) {
	select {
	case <-timeoutAfter(0):
		return
	case <-time.After(50 * time.Millisecond):
		t.Fatal("timeoutAfter(0) did not return immediately")
	}
}

func TestNoDoubleDurationConversionInCollector(t *testing.T) {
	content, err := os.ReadFile("prometheus-libvirt-exporter.go")
	if err != nil {
		t.Fatalf("failed to read collector source: %v", err)
	}

	if strings.Contains(string(content), "time.After(time.Duration(timeout) * time.Second)") {
		t.Fatal("collector still contains double duration conversion in timeout expression")
	}
}
