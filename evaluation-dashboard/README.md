# evaluation-dashboard（C 负责）

这里目前只保留 C 模块的工程入口和数据约定，没有宣称完成安全评测或 Dashboard。

C 应从 `shared/test-vectors/` 与 A/B 实际 API 构造独立用例，至少覆盖正常、签名篡改、过期、跨任务、跨服务、错误资源、Wrong Holder、RequestHash 不一致、Audience 错误、旧 epoch、撤销、重放、并发重放与撤销竞态。输出文件建议为：

```text
security.csv
performance.csv
concurrency.csv
revocation.csv
prompt_injection.csv
```

A 的 pytest 结果只能作为协议单元测试输入，不能直接当作 C 的全系统结果。
