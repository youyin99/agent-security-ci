# Agent Security CI 工程设计

## 1. 目标

把安全评测结果变成发布门禁，而不是只生成一份“看起来很绿”的报告。

门禁读取两份 AgentProbe 报告：

- 基线：已批准、已审查；
- 当前：本次变更生成。

它检查覆盖、回归、证据质量和失败用例，不重新执行攻击。

## 2. 输入校验

报告必须：

- `schema_version == "1.0"`；
- `report_type == "agentprobe"`；
- `cases` 为数组；
- 每个用例有唯一 ID、`kind`、`category`；
- baseline/hardened profile 及合法 verdict；
- hardened `error_count` 为非负整数；
- 可选 case-level `status`。

当前报告缺失 → 输入错误退出 2。
基线路径不存在 → 门禁失败（默认），而不是输入错误。
基线存在但 malformed → 输入错误退出 2。

## 3. 判定逻辑

### 3.1 用例级

攻击用例期望 hardened `protected`；正常用例期望 `passed`。

先处理证据质量：

1. case 或 hardened verdict 为 `skipped` → 按 `fail_on_skipped`；
2. `error_count > 0` 或 verdict `error` → 按 `fail_on_execution_error`；
3. verdict `uncertain` → 按 `fail_on_uncertain`；
4. 检查期望 verdict。

案例级失败会加入 `failed_cases`，即使总体阈值被调低。

### 3.2 覆盖

- `required_case_ids` 必须存在且期望通过；
- `required_categories` 统计非跳过的攻击用例；
- 覆盖率不足 → 失败。

### 3.3 比率

- 加固保护率 = protected attack / attack；
- 正常通过率 = passed benign / benign；
- 低于配置阈值 → 失败。

### 3.4 回归

对基线中原本满足期望的用例：

- 当前缺失 → 回归；
- 当前 `kind` 或 `category` 与基线不同 → 回归（防止把攻击用例改标为正常用例绕过门禁）；
- 当前 verdict 不再满足期望 → 回归。

回归数量超过 `max_allowed_regressions` → 失败。

### 3.5 fail_on_* 语义

- 默认全部严格；
- 显式关闭 `fail_on_skipped` / `fail_on_execution_error` / `fail_on_uncertain` 时，对应用例从比率分母和回归计数中排除；
- 这属于显式风险接受，不是静默通过；
- `required_case_ids` 仍然要求满足期望；
- 元数据漂移始终是回归。

### 3.6 基线

基线缺失且 `allow_missing_baseline=false` → 固定失败。这样默认 fail-closed。

## 4. 输出

```text
gate-report.json
├─ passed / exit_code
├─ summary
├─ failed_cases / failed_case_details
├─ regressions
├─ config
└─ checks[]
```

HTML 由相同结果生成，所有动态字段转义。

每个 check 有稳定 ID，例如：

- `baseline_present`
- `case:exfil-001`
- `case:exfil-001:execution`
- `case:exfil-001:skipped`
- `required_case:exfil-001`
- `category:secret_exfiltration`
- `hardened_protection_rate`
- `benign_pass_rate`
- `baseline_regressions`

## 5. GitHub Actions

`action/action.yml`：

- composite action；
- 安装本仓库；
- 构造参数数组，避免 shell 注入；
- 总是输出 GitHub 注解；
- 输出 gate report 路径。

工作流模板要求基线来自已提交、已审查文件，禁止在 PR job 内生成基线。

## 6. 测试

覆盖：

- 基线 vs 修复：通过；
- 基线 vs 削弱：失败并命名 `exfil-001`；
- 缺少基线：fail-closed；
- 明确允许缺少基线：通过；
- uncertain / skipped / error；
- 必需用例缺失；
- 分类覆盖不足；
- 正常用例回归；
- 降低总体阈值仍不能绕过案例级失败；
- 配置/报告格式非法；
- CLI 退出码和 GitHub 注解。

## 7. 明确不做

- 重新执行 AgentProbe；
- 判断证据本身是否真实；
- 验证基线来自可信构建；
- 签名/证明工件；
- 部署或发布操作本身。
