// Package metrics 记录 Broker 各阶段耗时，供 C 做性能实验（P50 / P95 / P99）。
package metrics

import (
	"sort"
	"sync"
	"time"
)

// 阶段名称。流水线各校验步骤以其 Step 名称记录。
const (
	StageConsume  = "atomic_consume"
	StageDecrypt  = "credential_decrypt"
	StageUpstream = "upstream"
	StageReceipt  = "receipt_sign"
	StageTotal    = "total"
)

const window = 2048 // 每个阶段保留最近 N 个样本用于分位数

type series struct {
	count   uint64
	total   time.Duration
	max     time.Duration
	samples []time.Duration
	next    int
}

// Recorder 是并发安全的耗时记录器。
type Recorder struct {
	mu     sync.Mutex
	stages map[string]*series
}

// New 创建 Recorder。
func New() *Recorder { return &Recorder{stages: map[string]*series{}} }

// Observe 记录一次耗时。r 为 nil 时忽略，便于测试中省略。
func (r *Recorder) Observe(stage string, d time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stages[stage]
	if s == nil {
		s = &series{samples: make([]time.Duration, 0, window)}
		r.stages[stage] = s
	}
	s.count++
	s.total += d
	if d > s.max {
		s.max = d
	}
	if len(s.samples) < window {
		s.samples = append(s.samples, d)
	} else {
		s.samples[s.next] = d
		s.next = (s.next + 1) % window
	}
}

// Since 是 Observe(stage, time.Since(start)) 的简写。
func (r *Recorder) Since(stage string, start time.Time) { r.Observe(stage, time.Since(start)) }

// Summary 是单个阶段的统计（毫秒）。
type Summary struct {
	Count  uint64  `json:"count"`
	MeanMs float64 `json:"mean_ms"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
}

// Snapshot 返回各阶段统计。
func (r *Recorder) Snapshot() map[string]Summary {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]Summary, len(r.stages))
	for name, s := range r.stages {
		sorted := append([]time.Duration(nil), s.samples...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		out[name] = Summary{
			Count:  s.count,
			MeanMs: ms(s.total) / float64(s.count),
			P50Ms:  ms(percentile(sorted, 0.50)),
			P95Ms:  ms(percentile(sorted, 0.95)),
			P99Ms:  ms(percentile(sorted, 0.99)),
			MaxMs:  ms(s.max),
		}
	}
	return out
}

// Reset 清空统计（实验之间使用）。
func (r *Recorder) Reset() {
	r.mu.Lock()
	r.stages = map[string]*series{}
	r.mu.Unlock()
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted))+0.5) - 1
	idx = max(0, min(idx, len(sorted)-1))
	return sorted[idx]
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
