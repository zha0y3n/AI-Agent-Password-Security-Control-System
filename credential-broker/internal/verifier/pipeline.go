// Package verifier 定义 Broker 的有序校验流水线。
//
// 具体步骤见 steps.go（按 docs/a-b-interface.md 的顺序）。
// 任何一步拒绝立即停止，后续步骤、Credential 读取、上游调用都不会发生（fail closed）。
package verifier

import (
	"context"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
)

// Plan 是校验全部通过后得到的执行计划，只能由校验步骤填写。
type Plan struct {
	Claim capability.Claim
	Call  upstream.Call
}

// Input 是一次执行请求在流水线中的上下文。
type Input struct {
	Body []byte    // 原始请求体（Execution Bundle）
	Now  time.Time // 本次校验使用的统一时间

	// 以下由步骤逐步填充
	Bundle      *protocol.ExecutionBundle
	RequestHash string // 由 Broker 对实际 AgentRequest 重算
	Plan        *Plan
}

// Denial 是拒绝原因。
type Denial struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// Step 是一个校验步骤。返回 nil 表示通过。
type Step interface {
	Name() string
	Verify(ctx context.Context, in *Input) *Denial
}

// StepFunc 将函数适配为 Step。
type StepFunc struct {
	StepName string
	Fn       func(ctx context.Context, in *Input) *Denial
}

func (s StepFunc) Name() string                                  { return s.StepName }
func (s StepFunc) Verify(ctx context.Context, in *Input) *Denial { return s.Fn(ctx, in) }

// StepResult 记录每一步的结果与耗时，供 Dashboard 展示请求链路。
type StepResult struct {
	Step     string  `json:"step"`
	Passed   bool    `json:"passed"`
	Duration float64 `json:"duration_ms"`
}

// Decision 是流水线结论。
type Decision struct {
	Allowed    bool         `json:"allowed"`
	FailedStep string       `json:"failed_step,omitempty"`
	Code       string       `json:"code,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	Steps      []StepResult `json:"steps"`
}

// Pipeline 按顺序执行步骤。
type Pipeline struct {
	steps   []Step
	metrics *metrics.Recorder
}

// New 创建流水线。
func New(m *metrics.Recorder, steps ...Step) *Pipeline {
	return &Pipeline{steps: steps, metrics: m}
}

// Run 执行全部步骤，遇到第一个拒绝即停止。
func (p *Pipeline) Run(ctx context.Context, in *Input) Decision {
	d := Decision{Steps: make([]StepResult, 0, len(p.steps))}
	for _, s := range p.steps {
		start := time.Now()
		denial := s.Verify(ctx, in)
		dur := time.Since(start)
		p.metrics.Observe("verify."+s.Name(), dur)
		d.Steps = append(d.Steps, StepResult{Step: s.Name(), Passed: denial == nil, Duration: float64(dur) / float64(time.Millisecond)})
		if denial != nil {
			d.FailedStep, d.Code, d.Reason = s.Name(), denial.Code, denial.Reason
			return d
		}
	}
	d.Allowed = true
	return d
}
