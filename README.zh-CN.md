# Agent Security CI

AgentProbe 评测报告的离线回归门禁，并提供 GitHub Actions 模板。

当前报告与批准基线比较，以下情况失败：

- 必需攻击用例缺失、跳过、执行失败、不确定，或不再受保护；
- 正常业务用例不再通过；
- 基线中受保护/通过用例发生回归；
- 分类覆盖低于策略；
- 加固保护率或正常通过率低于策略；
- 基线缺失且未明确允许；
- 当前报告格式非法。

门禁不重新运行攻击或重新判断证据，只执行报告契约与发布政策。

## 安装

需要 Python 3.11–3.13。示例报告格式为 `schema_version: 1.0`、`report_type: agentprobe`。

```bash
python -m pip install -e ".[dev]"
```

## 快速启动

```bash
python examples/run_demo.py
```

预期：

```text
PASS baseline-vs-fixed: gate passed; failed_cases=[]
PASS baseline-vs-weakened: gate failed; failed_cases=['exfil-001']
PASS missing-baseline: gate failed; failed_cases=[]
```

该演示模拟“故意削弱权限 → 门禁失败 → 修复后通过”。输出位于 [`examples/output/`](examples/output/)。

直接运行门禁：

```bash
python -m agent_security_ci gate \
  --baseline examples/reports/baseline.json \
  --current examples/reports/weakened.json \
  --config examples/gate-policy.json \
  --out examples/output
```

退出码：`0` 通过，`1` 门禁失败，`2` 输入或配置错误。

## 门禁策略

关键字段：

- `required_categories`：每个攻击分类的最少非跳过用例数；
- `required_case_ids`：必须存在的用例；
- `min_hardened_protected_rate` / `min_benign_passed_rate`：总体比率；
- `fail_on_uncertain` / `fail_on_skipped` / `fail_on_execution_error`：证据质量门禁；
- `allow_missing_baseline`：默认 false；
- `max_allowed_regressions`：允许的回归数量，默认 0。

用例级检查始终独立于总体阈值；降低阈值不会放过单个违规用例。

`fail_on_*` 默认严格。显式关闭某一项时，对应用例会从比率分母和基线回归计数中排除，这属于明确的风险接受，而不是静默通过；必需用例仍然必须满足。基线与当前报告中同一用例的 `kind` 或 `category` 变化始终视为回归，不能通过把攻击用例改标为正常用例绕过门禁。

## 输出

- `gate-report.json`
- `gate-report.html`
- 控制台失败用例摘要
- 可选 `--github-annotations` GitHub 错误注解

## GitHub Actions

- `templates/agent-security-gate.yml`：Pull Request 工作流模板；
- `action/action.yml`：composite action；
- `action/README.md`：用法。

基线必须来自经过审查的提交，不能在同一 PR job 中现场生成，否则回归会自我批准。

## 测试

```bash
python -m pytest
```

覆盖通过、违规、执行失败、跳过、不确定、缺少基线、允许缺少基线、必需用例/分类覆盖、正常回归、降低阈值不能绕过、配置/报告非法和 CLI 退出码。

## 已知限制

- 只消费 AgentProbe 结构报告；
- 不验证基线产出来源的可信性；
- 默认把 `uncertain` 视为失败；
- 无签名、证明或构建来源验证；
- 演示报告是紧凑 fixture，不是真实模型结果。

## 贡献与安全

见 [`CONTRIBUTING.md`](CONTRIBUTING.md)、[`SECURITY.md`](SECURITY.md)。完整设计见 [`docs/DESIGN.zh-CN.md`](docs/DESIGN.zh-CN.md)。

## 许可

Apache-2.0，见 [`LICENSE`](LICENSE)。
