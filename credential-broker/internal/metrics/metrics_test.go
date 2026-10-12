package metrics

import (
	"testing"
	"time"
)

func TestPercentiles(t *testing.T) {
	r := New()
	for i := 1; i <= 100; i++ {
		r.Observe("x", time.Duration(i)*time.Millisecond)
	}
	s := r.Snapshot()["x"]
	if s.Count != 100 || s.P50Ms != 50 || s.P95Ms != 95 || s.P99Ms != 99 || s.MaxMs != 100 || s.MeanMs != 50.5 {
		t.Fatalf("%+v", s)
	}
	var nilRec *Recorder
	nilRec.Observe("x", time.Second) // 不应 panic
	r.Reset()
	if len(r.Snapshot()) != 0 {
		t.Fatal("reset failed")
	}
}
