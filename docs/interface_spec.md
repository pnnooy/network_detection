# 接口规范文档（Interface Specification）

本文件是 `network_detection` 项目的权威接口规范，README 中的接口章节为本文件的摘要。**任何模块的输入输出格式如与本文件冲突，以本文件为准**，如需修改字段需在群里同步全体成员并更新本文件。

---

## 一、数据流总览

```
[李哲] 数据包捕获与协议解析
         │
         ▼  报文记录 (Packet Record)
   ┌─────┼─────┐
   ▼     ▼     ▼
[曾子恒] [陈志恒] [姜新晨]
特征匹配  暴力破解   异常行为
   │     │     │
   └─────┼─────┘
         ▼  告警记录 (Alert Record)
    [韩宇飞] 汇总 + GUI展示
```

- Phase1~Phase3 阶段，B/C/D 三个检测模块的输入统一来自 `mock_data/mock_packets.json`
- Phase4 起，输入切换为李哲真实抓包模块的实时/落盘输出，格式保持不变

---

## 二、报文记录格式（Packet Record）

由 **李哲（capture 模块）** 产出，**曾子恒 / 陈志恒 / 姜新晨** 三个模块统一消费。

### 2.1 字段定义

| 字段 | 类型 | 是否必填 | 说明 |
|---|---|---|---|
| `timestamp` | string (ISO8601) | 是 | 报文捕获时间，精确到毫秒 |
| `flow_id` | string | 否 | 流标识，由 capture 模块根据五元组生成，格式 `"src_ip:src_port->dst_ip:dst_port/protocol"`，供消费模块按连接分组。未提供时消费模块可自行构建 |
| `src_ip` | string | 是 | 源IP地址 |
| `src_port` | int | 否 | 源端口，ICMP 等无端口协议可为 `null` |
| `dst_ip` | string | 是 | 目的IP地址 |
| `dst_port` | int | 否 | 目的端口，ICMP 等无端口协议可为 `null` |
| `protocol` | string | 是 | `TCP` / `UDP` / `ICMP` / `ARP` |
| `direction` | string | 否 | 报文方向：`"request"` / `"response"`。TCP 中可结合 flags 和端口判断；无法判断时可为 `null` |
| `flags` | string | 否 | TCP 标志位组合，如 `S`(SYN) `A`(ACK) `P`(PSH) `F`(FIN) `R`(RST)。非 TCP 可为空字符串 |
| `payload` | string | 否 | 应用层载荷，尽量转为可读字符串；无法解码部分可用 `\xNN` 转义表示 |
| `payload_len` | int | 是 | 线路上原始 payload 的字节长度（TCP/UDP 数据段长度），非解码后字符串长度。无 payload 时为 0 |

### 2.2 示例

```json
[
  {
    "timestamp": "2026-07-08T10:00:00.123",
    "flow_id": "192.168.1.10:51234->192.168.1.20:80/TCP",
    "src_ip": "192.168.1.10",
    "src_port": 51234,
    "dst_ip": "192.168.1.20",
    "dst_port": 80,
    "protocol": "TCP",
    "direction": "request",
    "flags": "PA",
    "payload": "GET /login.php?id=1 UNION SELECT username,password FROM users-- HTTP/1.1",
    "payload_len": 128
  },
  {
    "timestamp": "2026-07-08T10:00:01.500",
    "flow_id": "192.168.1.99:43210->192.168.1.20:22/TCP",
    "src_ip": "192.168.1.99",
    "src_port": 43210,
    "dst_ip": "192.168.1.20",
    "dst_port": 22,
    "protocol": "TCP",
    "direction": "request",
    "flags": "S",
    "payload": "",
    "payload_len": 0
  }
]
```

### 2.3 mock_packets.json 设计要求（李哲负责）

Phase1 交付的 mock 数据需要覆盖以下场景，并在 `docs/final_report.md` 中附一份"场景-预期检测结果"对照表，方便 B/C/D 三人自测比对：

| 场景 | 数量建议 | 预期被哪个模块检出 |
|---|---|---|
| 正常 HTTP/SSH/FTP 流量 | ≥20条 | 均不应产生告警 |
| SQL 注入特征报文（如 `UNION SELECT`、`' OR 1=1`） | ≥5条 | signature |
| XSS 特征报文（如 `<script>alert(1)</script>`） | ≥5条 | signature |
| 木马/恶意命令特征（如课件示例 `faxsurvey?/bin/cat%20/etc/passwd`） | ≥3条 | signature |
| 同一源IP短时间大量连接同一登录端口（22/21/Web登录） | ≥1组（建议15~30条连续记录） | bruteforce |
| 同一源IP短时间访问大量不同目标端口（端口扫描特征） | ≥1组（建议20+条连续记录） | anomaly |
| 内网主机异常外联陌生公网IP | ≥3条 | anomaly |

---

## 三、统一告警格式（Alert Record）

由 **曾子恒 / 陈志恒 / 姜新晨** 三个检测模块产出，**韩宇飞（gui_alert 模块）** 统一消费。

### 3.1 字段定义

| 字段 | 类型 | 是否必填 | 说明 |
|---|---|---|---|
| `alert_id` | string (uuid) | 是 | 全局唯一告警ID，建议用 `uuid.uuid4()` 生成 |
| `detector` | string | 是 | 固定取值：`signature` / `bruteforce` / `anomaly` |
| `category` | string | 是 | 攻击类型简述，如 `"Web攻击/SQL注入"`、`"暴力破解/非法登录"`、`"端口扫描"`、`"内网横向扩散"` |
| `src_ip` | string | 是 | 攻击源IP |
| `src_port` | int | 否 | 攻击源端口，无法确定时为 `null` |
| `dst_ip` | string | 是 | 受害目标IP（单IP）。当检测对象为网段级别行为时（如端口扫描），填写受扫描的单个代表性IP或 `"multiple"`，并在 `dst_network` 字段补充网段信息 |
| `dst_network` | string | 否 | 受害目标网段（CIDR 格式，如 `"192.168.1.0/24"`），适用于端口扫描、横向扩散等网段级告警。单IP告警可不填 |
| `dst_port` | int | 否 | 受害目标端口，无法确定时为 `null` |
| `severity` | string | 是 | `low` / `medium` / `high` |
| `description` | string | 是 | 人类可读的告警描述，用于 GUI 直接展示 |
| `evidence` | string | 否 | 匹配到的原始内容或统计证据（如匹配特征串、异常次数与阈值对比） |
| `timestamp` | string (ISO8601) | 是 | 告警产生时间 |

### 3.2 各模块产出示例

**signature（曾子恒）：**
```json
{
  "alert_id": "b3f1a2c4-1234-4abc-9def-000000000001",
  "detector": "signature",
  "category": "Web攻击/SQL注入",
  "src_ip": "192.168.1.10",
  "src_port": 51234,
  "dst_ip": "192.168.1.20",
  "dst_network": null,
  "dst_port": 80,
  "severity": "high",
  "description": "检测到SQL注入特征: UNION SELECT",
  "evidence": "GET /login.php?id=1 UNION SELECT username,password FROM users--",
  "timestamp": "2026-07-08T10:00:00.200"
}
```

**bruteforce（陈志恒）：**
```json
{
  "alert_id": "b3f1a2c4-1234-4abc-9def-000000000002",
  "detector": "bruteforce",
  "category": "暴力破解/非法登录",
  "src_ip": "192.168.1.99",
  "src_port": null,
  "dst_ip": "192.168.1.20",
  "dst_network": null,
  "dst_port": 22,
  "severity": "medium",
  "description": "60秒内检测到同一源IP对SSH端口发起18次连接尝试",
  "evidence": "attempt_count=18, time_window_sec=60, threshold=10",
  "timestamp": "2026-07-08T10:01:30.000"
}
```

**anomaly — 端口扫描（姜新晨）：**
```json
{
  "alert_id": "b3f1a2c4-1234-4abc-9def-000000000003",
  "detector": "anomaly",
  "category": "端口扫描",
  "src_ip": "192.168.1.77",
  "src_port": null,
  "dst_ip": "192.168.1.20",
  "dst_network": "192.168.1.0/24",
  "dst_port": null,
  "severity": "high",
  "description": "单IP在60秒内访问了35个不同目标端口，超出基线阈值",
  "evidence": "unique_dst_port_count=35, baseline_threshold=20",
  "timestamp": "2026-07-08T10:02:00.000"
}
```

**anomaly — 异常外联（姜新晨）：**
```json
{
  "alert_id": "b3f1a2c4-1234-4abc-9def-000000000004",
  "detector": "anomaly",
  "category": "异常外联",
  "src_ip": "192.168.1.55",
  "src_port": 52341,
  "dst_ip": "203.0.113.99",
  "dst_network": null,
  "dst_port": 443,
  "severity": "medium",
  "description": "内网主机外联陌生公网IP 203.0.113.99:443，不在已知外联白名单中",
  "evidence": "dst_ip=203.0.113.99, internal_networks=['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']",
  "timestamp": "2026-07-08T10:05:00.000"
}
```

---

## 四、函数签名约定

### 4.1 检测模块（B / C / D 共用签名）

```python
def detect(packets: list[dict]) -> list[dict]:
    """
    输入: 符合"报文记录格式"的列表
    输出: 符合"统一告警格式"的列表（无告警时返回空列表 []，不要返回 None）
    """
```

### 4.2 CLI 调用约定

每个检测模块需提供独立可执行入口，输入输出路径通过命令行参数指定，便于组长的汇总脚本统一调用，也便于各自单独调试：

```bash
python -m src.signature_engine.matcher \
    --input mock_data/mock_packets.json \
    --output results/signature_alerts.json

python -m src.bruteforce_detect.login_monitor \
    --input mock_data/mock_packets.json \
    --output results/bruteforce_alerts.json

python -m src.anomaly_detect.anomaly_detector \
    --input mock_data/mock_packets.json \
    --output results/anomaly_alerts.json
```

### 4.3 汇总模块（韩宇飞）

```python
def aggregate(alert_files: list[str]) -> list[dict]:
    """
    输入: results/ 目录下各检测模块产出的 json 文件路径列表
    输出: 合并、按 timestamp 排序、按 alert_id 去重后的统一告警列表
    """
```

### 4.4 统一日志规范

所有模块统一使用 Python 标准库 `logging` 模块，日志格式如下：

```python
import logging

logger = logging.getLogger(__name__)

# CLI 入口统一配置:
logging.basicConfig(
    level=logging.INFO,
    format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
)
```

- 调试信息使用 `logger.debug()`
- 正常流程信息使用 `logger.info()`
- 非致命异常（如文件缺失、字段缺失）使用 `logger.warning()`
- 致命错误使用 `logger.error()`
- **禁止使用 `print()` 输出调试信息**（CLI 结束时的摘要输出除外）

---

## 五、异常与边界情况约定

各模块需自行处理以下情况，不应抛出未捕获异常导致整个流程中断：

- 输入文件不存在 / 为空 → 打印警告日志，返回空结果，不崩溃
- 单条报文记录缺少非必填字段 → 按 `null` 处理，跳过依赖该字段的判断逻辑
- `payload` 字段包含无法解码的二进制内容 → 转义处理，不影响其余字段解析
- 时间窗口类检测（bruteforce / anomaly）在数据量不足以形成统计窗口时 → 不产生告警，不报错
- `flow_id` 缺失时 → 消费模块应自行根据五元组构建，不应因此崩溃

---

## 六、变更记录

| 日期 | 修改人 | 变更内容 |
|---|---|---|
| 2026-07-08 | 韩宇飞 | 初始版本，定义报文记录格式与统一告警格式 |
| 2026-07-08 | 韩宇飞（审阅修订） | 新增 `flow_id`、`direction` 可选字段；新增 `dst_network` 字段解决 CIDR 歧义；明确 `payload_len` 为线路上原始字节长度；新增统一日志规范（4.4节）；新增异常外联告警示例 |
