# 融合特征匹配与异常行为分析的网络攻击检测系统

信息安全科技创新 · 课程大作业

---

## 目录

- [一、项目简介](#一项目简介)
- [二、开发环境](#二开发环境)
- [三、项目成员与分工](#三项目成员与分工)
- [四、目录结构](#四目录结构)
- [五、各模块任务清单](#五各模块任务清单)
- [六、统一接口规范](#六统一接口规范)
- [七、Git 分支管理规范](#七git-分支管理规范)
- [八、阶段划分与提交要求](#八阶段划分与提交要求)
- [九、联调与合并流程](#九联调与合并流程)
- [十、真实攻击演示方案](#十真实攻击演示方案)
- [十一、时间计划表](#十一时间计划表)
- [十二、注意事项](#十二注意事项)

---

## 一、项目简介

本项目融合**误用检测**与**异常行为分析**两种思路，构建一个以攻击行为检测为目标的网络入侵检测系统。核心设计理念：不仅逐包匹配恶意特征，更关注攻击者行为的持续性与关联性，从流量数据中识别出有意义的攻击行为事件。

系统覆盖三个检测维度：

- **特征行为检测**：基于可维护的攻击特征库，识别 SQL 注入、XSS、木马远控、恶意命令等已知攻击行为。同一来源在时间窗口内对同一目标发起的同类攻击命中，聚合为一条行为告警，消除逐包报警的碎片化问题
- **统计行为检测**：建立主机并发连接、访问频次、端口分布、会话时长等行为基线，识别暴力破解（短时间大量登录尝试）、端口扫描（大规模端口探测）、异常外联陌生 IP、内网横向扩散等偏离正常基线的攻击行为
- **攻击行为监控界面**：以攻击行为为粒度统一汇总展示，支持按行为类型/严重程度/攻击源筛选，提供特征库可视化管理

系统整体数据流：**数据包捕获 → TCP重组/协议识别 → 特征行为检测 + 统计行为检测（并行）→ 行为告警汇总与关联 → GUI展示**

---

## 二、开发环境

| 项目 | 要求 |
|---|---|
| **Python** | ≥ 3.9 |
| **操作系统** | 建议 Linux 虚拟机 或 WSL2（Windows 下 scapy/libpcap 行为差异大，不推荐直接使用） |
| **权限** | 实时抓包需要管理员/root 权限，请在虚拟机中提前配置 |
| **依赖安装** | `pip install -r requirements.txt` |
| **代码格式化** | 推荐使用 `black` + `isort` 统一风格（可选但强烈建议） |

---

## 三、项目成员与分工

| 姓名 | 学号 | GitHub | 负责模块 | 状态 |
|---|---|---|---|---|
| **韩宇飞（组长）** | 524031910172 | pnnooy | 告警汇总 + 行为关联 + 监控GUI + 项目统筹 | ✅ 已合入 |
| 李哲 | 524031910017 | Entropy-wz | 数据包捕获与协议解析（地基模块） | ✅ 已合入 |
| 曾子恒 | 523010910022 | zengziheng-rude | 特征行为检测引擎（特征库 + 匹配算法 + 行为聚合） | ✅ 已合入 |
| 陈志恒 | 524031910111 | 陈志恒 | 暴力破解 / 非法登录检测 | ✅ 已合入 |
| 姜新晨 | 524031910769 | Jiang060117 | 异常流量 / 扫描行为基线检测 | ✅ 已合入 |

> 组长电话：18737507536

---

## 四、目录结构

```
network_detection/
├── README.md
├── requirements.txt                 # Python 依赖清单
├── .gitignore
├── main.py                          # 系统入口（韩宇飞维护）
├── config/
│   ├── signatures.txt               # 攻击特征库配置（曾子恒维护）
│   └── baseline_config.json         # 基线阈值配置（姜新晨维护）
├── src/
│   ├── __init__.py
│   ├── capture/                     # 李哲
│   │   ├── __init__.py
│   │   ├── mock_generator.py        # mock 数据生成器（可复现）
│   │   ├── packet_capture.py        # scapy 抓包
│   │   ├── tcp_reassembly.py        # TCP 流重组
│   │   └── protocol_parser.py       # 协议识别与字段解析
│   ├── signature_engine/            # 曾子恒
│   │   ├── __init__.py
│   │   ├── signature_db.py          # 特征库管理（增删改查）
│   │   └── matcher.py               # 特征匹配算法
│   ├── bruteforce_detect/           # 陈志恒
│   │   ├── __init__.py
│   │   └── login_monitor.py         # 登录行为监控与暴力破解判定
│   ├── anomaly_detect/              # 姜新晨
│   │   ├── __init__.py
│   │   ├── baseline.py              # 基线建立
│   │   └── anomaly_detector.py      # 偏离基线行为检测
│   └── gui_alert/                   # 韩宇飞
│       ├── __init__.py
│       ├── aggregator.py            # 汇总各模块告警
│       └── gui.py                   # 图形界面（规则管理 + 实时告警）
├── mock_data/
│   └── mock_packets.json            # 李哲在 Phase1 交付的模拟报文数据
├── results/                          # 告警输出目录（各模块产出 + 汇总）
│   ├── signature_alerts.json
│   ├── bruteforce_alerts.json
│   ├── anomaly_alerts.json
│   └── merged_alerts.json            # 韩宇飞汇总输出（含 behavior_id）
├── tests/
│   ├── __init__.py
│   ├── test_capture.py
│   ├── test_signature.py
│   ├── test_bruteforce.py
│   ├── test_anomaly.py
│   └── test_gui_aggregator.py
└── docs/
    ├── interface_spec.md            # 接口规范（权威版本）
    ├── 选题报告.md                   # 项目选题报告
    └── final_report.md              # 最终答辩报告/PPT素材
```

> 每人只在自己负责的 `src/<模块>/` 目录及对应 `tests/test_xxx.py` 内开发，避免相互修改文件产生冲突。

---

## 五、各模块任务清单

### A. 数据包捕获与协议解析 —— 李哲 ✅

- **实际完成**：TCP 重组、协议识别（TCP/UDP/ICMP/ARP）、TLS 流量识别、`mock_packets.json`（108 条 7 场景）+ `mock_generator.py` 可复现生成器
- **测试**：`tests/test_capture.py`（20 个测试），覆盖 TCP 重组正确性、协议字段解析、mock 数据格式合规性
- 输出：标准化报文记录（供 B/C/D 三个模块统一消费）

### B. 特征行为检测引擎 —— 曾子恒 ✅

- **实际完成**：12 条攻击特征规则（SQL注入 5 条 / XSS 2 条 / 木马通信 1 条 / 恶意命令 4 条），支持 `literal`（子串匹配）和 `regex`（正则匹配）两种模式，大小写不敏感
- **行为聚合**：同一 (src_ip, dst_ip, category) 在 60 秒窗口内的多次特征命中合并为一条行为告警，消除逐包碎片化
- **规则库管理**：`signature_db.py` 提供 `add_signature()` / `delete_signature()` 增删接口，含字段校验、自动 ID 分配、`|` 字符转义
- **测试**：`tests/test_signature.py`（38 个测试），覆盖四大类攻击检出、协议过滤、窗口聚合/拆分、告警格式合规、边界异常、mock 数据端到端
- 输出：`results/signature_alerts.json`

### C. 暴力破解 / 非法登录检测 —— 陈志恒 ✅

- **实际完成**：双指针滑动窗口统计 SYN/RST 包数量，针对 SSH(22)/FTP(21)/Web登录端口识别短时间内大量连接尝试，支持退化 flow_id 计数
- **测试**：`tests/test_bruteforce.py`（25 个测试），覆盖窗口边界、阈值可配置、mock 数据检出 1 条 SSH 暴力破解告警
- 输出：`results/bruteforce_alerts.json`

### D. 异常流量 / 扫描行为基线检测 —— 姜新晨 ✅

- **实际完成**：四项检测——端口扫描（滑动窗口统计唯一 dst_port）、异常外联（内网→公网 IP 匹配+去重）、内网横向扩散（滑动窗口统计唯一内网 dst_ip）、高频连接（滑动窗口统计连接速率）
- **基线模块**：`baseline.py` 提供主机行为基线统计（并发数/频次/端口分布/会话时长），供动态阈值参考
- **配置**：`config/baseline_config.json` 统一管理四项检测阈值与内网段定义
- **测试**：`tests/test_anomaly.py`（45 个测试），覆盖四项检测检出/不误报、窗口边界、告警格式合规、边界异常、mock 数据端到端
- 输出：`results/anomaly_alerts.json`

### E. 告警汇总 + 行为关联 + 监控 GUI —— 韩宇飞（组长） ✅

- **实际完成**：
  - `aggregator.py`：合并/排序/去重 + `correlate_behaviors()` 行为关联（同源同类时间相近 → 共享 behavior_id）
  - `gui.py`：tkinter 三页签（告警监控 / 特征库管理 / 统计概览），零外部依赖
  - `main.py`：全链路入口，一键运行 `python main.py --input mock_data/mock_packets.json`
- **接口规范**：`docs/interface_spec.md` 定义报文记录格式、统一告警格式、函数签名、CLI 调用约定、日志规范
- **测试**：`tests/test_gui_aggregator.py`（20 个测试）
- 输出：`results/merged_alerts.json`（含 `behavior_id`）+ 图形界面

### 测试覆盖总览

| 模块 | 测试文件 | 测试数 | 覆盖范围 |
|---|---|---|---|
| capture | `test_capture.py` | 20 | TCP 重组、协议解析、mock 格式合规 |
| signature | `test_signature.py` | 38 | SQL注入/XSS/木马/恶意命令 检出、协议过滤、窗口聚合、mock 端到端 |
| bruteforce | `test_bruteforce.py` | 25 | 滑动窗口统计、SYN/RST 计数、阈值可配、mock 端到端 |
| anomaly | `test_anomaly.py` | 45 | 端口扫描/异常外联/横向扩散/高频连接 检出、告警格式、mock 端到端 |
| gui + aggregator | `test_gui_aggregator.py` | 20 | 行为关联、去重排序、GUI 组件 |
| **合计** | | **148** | **全部通过，2 跳过（环境依赖）** |

> 运行全量测试：`python -m pytest tests/ -v`

---

## 六、统一接口规范

> 完整规范见 [`docs/interface_spec.md`](docs/interface_spec.md)，此处为摘要。

### 6.1 报文记录格式（李哲的模块产出，B/C/D 统一消费）

`mock_data/mock_packets.json` 与真实抓包模块输出格式一致，每条记录：

```json
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
  "payload": "GET /login.php?id=1 UNION SELECT ...",
  "payload_len": 128
}
```

> **新增字段说明**（审阅修订）：
> - `flow_id`（可选）：五元组流标识，格式 `src_ip:src_port->dst_ip:dst_port/protocol`，便于消费模块按连接分组
> - `direction`（可选）：`"request"` / `"response"`，供暴力破解等模块判断认证结果
> - `payload_len`：线路上原始 payload 字节长度（非解码后字符串长度）

各消费模块（B/C/D）统一函数签名：

```python
def detect(packets: list[dict], config: dict | None = None) -> list[dict]:
    """
    packets: 符合上方 schema 的报文记录列表
    config:  可选的模块配置字典，为 None 时从模块默认配置文件加载
    返回: 符合下方"统一告警格式"的告警列表（无告警时返回空列表 []，不要返回 None）
    """
```

### 6.2 统一告警格式（B/C/D 输出，供 E 汇总）

```json
{
  "alert_id": "uuid-string",
  "behavior_id": null,
  "detector": "signature",
  "category": "Web攻击/SQL注入",
  "src_ip": "192.168.1.10",
  "src_port": 51234,
  "dst_ip": "192.168.1.20",
  "dst_network": null,
  "dst_port": 80,
  "severity": "high",
  "description": "检测到针对 /login.php 的 SQL 注入攻击行为，攻击者尝试利用 UNION 查询提取数据库用户凭据",
  "evidence": "GET /login.php?id=1 UNION SELECT username,password FROM users--",
  "timestamp": "2026-07-08T10:00:01"
}
```

字段说明：
- `behavior_id`（新增可选字段）：攻击行为事件标识，由检测模块或汇总模块填入。同一源在时间窗口内对同一目标发起同类攻击的多条告警共享同一 `behavior_id`，供 GUI 按行为聚合展示。检测模块未填写时由 aggregator 自动关联赋值
- `detector`: `signature`（特征匹配）/ `bruteforce`（暴力破解）/ `anomaly`（异常行为）
- `severity`: `low` / `medium` / `high`
- `category`: 简要攻击类型描述，如"暴力破解/非法登录"、"端口扫描"、"内网横向扩散"等
- `dst_network`（可选）：CIDR 网段（如 `"192.168.1.0/24"`），仅在端口扫描、横向扩散等网段级告警时填写
- `description`：人类可读的**攻击行为描述**，用于 GUI 直接展示。须描述攻击者正在做什么（如"针对 SSH 服务的暴力破解行为，60 秒内尝试 18 次登录"），而非仅罗列匹配特征或统计数字

每个模块需支持独立 CLI 运行：

```bash
python -m src.signature_engine.matcher --input mock_data/mock_packets.json --output results/signature_alerts.json
```

### 6.3 统一日志规范

所有模块统一使用 Python 标准库 `logging`：

```python
import logging
logger = logging.getLogger(__name__)

# CLI 入口统一配置:
logging.basicConfig(
    level=logging.INFO,
    format="[%(name)s] %(levelname)s %(asctime)s %(message)s",
)
```

- `logger.debug()` — 调试信息
- `logger.info()` — 正常流程信息
- `logger.warning()` — 非致命异常（文件缺失、字段缺失）
- `logger.error()` — 致命错误
- **禁止使用 `print()` 输出调试信息**（CLI 结束时的摘要除外）

---

## 七、Git 分支管理规范

- `main`：主分支，**受保护**，只能通过 Pull Request 合并，禁止直接 push
- 每人一个 `feature/<模块简称>` 分支（见第三节表格），在自己的分支上开发
- 合并前需组长（或指定同学）完成 Code Review，确认：
  1. 代码可独立运行（用 mock 数据即可）
  2. 输出严格符合 `docs/interface_spec.md` 中的统一告警格式
  3. 有基本的异常处理（空报文、字段缺失、文件读取失败等）
- 分支保护建议：禁止 force push；有冲突由提出 PR 的人自行 rebase 解决后重新提交

```bash
# 克隆仓库
git clone git@github.com:pnnooy/network_detection.git
cd network_detection

# 安装依赖
pip install -r requirements.txt

# 创建并切换到自己的分支
git checkout -b feature/<你的分支名>   # 见第三节表格

# 日常提交
git add .
git commit -m "[signature] feat: 环境搭建与接口骨架完成"
git push origin feature/signature-engine

# 完成阶段后在网页端发起 Pull Request 到 main
```

---

## 八、阶段划分与提交要求

> **原则：每人独立开发，每完成一个阶段提交（commit）一次，禁止攒到最后一次性提交。**

| 阶段 | 内容 | 时间 | 状态 |
|---|---|---|---|
| **Phase 1** | 李哲交付 mock 数据 + capture 模块；其余人拉分支、搭建骨架 | 7/9 ~ 7/13 | ✅ 已完成 |
| **Phase 2** | 完成核心检测逻辑；基于 mock 数据跑通基础用例 | 7/14 ~ 7/18 | ✅ 已完成 |
| **Phase 2.5** | **接口对齐检查**：审核 PR 校验告警格式合规 | 7/20 ~ 7/22 | ✅ 已完成 |
| **Phase 3** | 单元测试 + 异常处理 + 日志规范；PR 合入 main | 7/21 ~ 7/22 | ✅ 已完成（148 测试全绿） |
| **Phase 4** | 真实抓包替换 mock 数据联调；补充文档/注释 | 7/23(四) ~ 7/25(六) | 🚀 **明天启动** |
| **Phase 5** | PPT、演示数据、截图、结题报告 | 7/26(日) ~ 7/28(二) | 📋 待开始 |
| **🎤 内部预演** | 完整走一遍汇报流程，发现并修正问题 | **7/28(二)** | — |
| **★ 项目汇报** | 课堂分享汇报 | **7/29(三)** | — |
| **📝 结题报告** | 结题报告撰写 + 源码整理 | 7/30(四) ~ 8/1(六) | — |
| **🏁 提前提交** | 源码 + 结题报告打包提交 | **8/2(日)** | — |
| **缓冲** | 应对意外问题 | 8/3(一) ~ 8/4(二) | — |
| **📅 官方截止** | 结题报告提交截止 | 8/5(三) | — |

> **Phase 2.5 已完成**（7/22）：韩宇飞审核 PR #2（anomaly）和 PR #3（signature），修复问题并补写测试后全部合入 main。全量 148 测试全绿，接口格式已验证通过。

### Commit message 规范

格式：`[模块标识] 类型: 简要描述`

模块标识对照：`capture` `signature` `bruteforce` `anomaly` `gui`

类型标签：`feat`（新功能）/ `fix`（修复）/ `docs`（文档）/ `test`（测试）/ `refactor`（重构）

```
[capture] feat: 实现基于scapy的TCP流重组
[signature] feat: 新增AC自动机多模式匹配，替换暴力匹配baseline
[bruteforce] fix: 修复时间窗口计数的边界判断
[anomaly] docs: 补充基线阈值配置说明
[gui] feat: 实现告警列表按严重程度筛选
```

---

## 九、联调与合并流程

1. 各自在 feature 分支完成核心逻辑后，发起 Pull Request 到 `main`
2. 组长（韩宇飞）完成 Code Review，修复问题后合并
3. **✅ Phase1~3 全部完成**：5 人全部模块已合入 main，148 测试全绿
4. **Phase 4 联调**（7/23 周四起）：
   - **Mock 数据全链路**已跑通：426 条报文 → 27 条规则 → 30 条行为告警
   - **真实攻击演示**：搭建本地靶机，用攻击脚本发起真实流量，scapy 抓包 → 检测引擎 → GUI 实时告警（7/23-7/25 韩宇飞搭建验证）
5. 联调中发现的问题以 Issue 形式记录 → 原模块负责人修复 → 重新提交 → 再次合并

---

## 十、真实攻击演示方案（Phase 4 核心）

> **目标**：答辩时同时展示「模拟数据离线检测」+「真实攻击实时检测」，体现系统在真实流量下的检测能力。

### 10.1 演示架构

```
┌──────────────────── 单台 Linux 虚拟机 / WSL2 ────────────────────┐
│                                                                    │
│  攻击脚本 (attack_scripts/)         靶机服务 (target_server.py)     │
│  ├─ sql_injection.sh    curl ───→  :8080/login.php (Python HTTP)  │
│  ├─ xss.sh              curl ───→  :8080/comment                  │
│  ├─ path_traversal.sh   curl ───→  :8080/download                 │
│  ├─ ssh_bruteforce.sh  hydra ───→  :22 (sshd)                     │
│  └─ port_scan.sh        nmap ───→  :1-1000                        │
│       │                            │                               │
│       └── 攻击流量 ──── lo 接口 ────┘                               │
│                       │                                            │
│                       ▼                                            │
│          capture 模块 (scapy 抓包 lo)                               │
│                       │                                            │
│                       ▼                                            │
│          B/C/D 检测引擎 → aggregator → GUI                          │
└────────────────────────────────────────────────────────────────────┘
```

### 10.2 文件清单

| 文件 | 说明 |
|------|------|
| `demo/target_server.py` | 靶机 HTTP 服务（模拟有漏洞的 Web 应用），监听 `0.0.0.0:8080` |
| `demo/attack_scripts/sql_injection.sh` | SQL 注入攻击（UNION SELECT / ' OR 1=1 / DROP TABLE） |
| `demo/attack_scripts/xss.sh` | XSS 攻击（`<script>alert(1)</script>` 等） |
| `demo/attack_scripts/path_traversal.sh` | 路径遍历攻击（`../../../etc/passwd` 等） |
| `demo/attack_scripts/cmd_injection.sh` | 命令注入攻击（`; wget` / `\| nc` 等） |
| `demo/attack_scripts/ssh_bruteforce.sh` | SSH 暴力破解（hydra 或手动循环 ssh） |
| `demo/attack_scripts/port_scan.sh` | 端口扫描（nmap 或手动循环 nc） |
| `demo/run_live_demo.sh` | 一键启动：靶机服务 + 开始抓包 + 执行攻击 |

### 10.3 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux（Ubuntu 22.04 推荐）或 WSL2 |
| Python | ≥ 3.9 |
| 系统包 | `scapy`、`openssh-server` |
| 权限 | root（scapy 抓包需要） |
| 可选 | `hydra`（SSH 爆破）、`nmap`（端口扫描），也可用纯 shell 替代 |

### 10.4 演示流程（约 5 分钟）

| 步骤 | 内容 | 时长 |
|------|------|------|
| 1 | 展示 mock 数据全链路结果（30 条告警） | 1 min |
| 2 | 启动靶机 HTTP 服务 + 开始抓包 | 30 s |
| 3 | 逐条执行攻击脚本，GUI 实时弹出告警 | 2 min |
| 4 | 对比 mock 告警 vs 真实抓包告警 | 1 min |
| 5 | 总结：统一接口、即插即用、双引擎互补 | 30 s |

### 10.5 防翻车预案

- **Plan A**：现场 live demo（Linux 虚拟机，提前配置好环境）
- **Plan B**：提前录制演示视频（全程录屏 + 旁白），现场播放 + 补充讲解
- 录制工具推荐：OBS Studio 或 Linux `peek` / `kazam`

---

## 十一、时间计划表

> 官方节点：第4周周三(7/29)汇报、第5周周三(8/5)提交。本表在此基础上提前 3 天留余量。

| 日期 | 里程碑 | 状态 |
|---|---|---|
| 7/9(四) ~ 7/12(日) | 李哲交付 mock 数据 + capture 模块 | ✅ 已完成 |
| 7/13(一) ~ 7/18(六) | 四人完成核心检测逻辑 | ✅ 已完成 |
| 7/20(一) ~ 7/22(三) | 单元测试 + PR 审核合入（148 测试全绿） | ✅ 已完成 |
| 7/22(三) | 扩充 mock 数据 426 条 + 27 规则 + 30 告警 | ✅ 已完成 |
| 7/23(四) ~ 7/25(六) | 🚀 真实攻击靶机搭建 + 抓包联调验证 | 📋 韩宇飞进行中 |
| 7/26(日) ~ 7/27(一) | PPT + 演示数据准备 + 录制演示视频 | 📋 待开始 |
| 7/28(二) | **内部预演**，发现并修正问题 | — |
| **7/29(三)** | ★ **项目分享汇报** | — |
| 7/30(四) ~ 8/1(六) | 结题报告撰写 + 源码整理 | — |
| **8/2(日)** | 🏁 **提前提交**（比 8/5 截止早 3 天） | — |
| 8/3(一) ~ 8/4(二) | 缓冲（应对意外） | — |
| 8/5(三) | 📅 官方截止，确认提交无误 | — |

---

## 十二、注意事项

- **开发环境**：实时抓包相关操作（scapy 混杂模式）需要管理员/root 权限，且 Windows 下兼容性差。**强烈建议全员在 Linux 虚拟机（如 Ubuntu 22.04）或 WSL2 中开发**，避免环境差异导致的联调问题
- 特征库、基线阈值等配置文件统一放在 `config/` 目录，便于集中管理和演示时调整
- 请**仅在自己搭建的测试环境或授权范围内**产生测试流量（如自己触发SQL注入/暴力破解请求用于验证检测效果），不要对外部无关网络发起攻击性请求
- ✅ **Phase1~3 全部完成**，5 人模块已合入 main，mock 数据覆盖 7 种场景 108 条记录，全量 148 测试全绿
- **Python 最低版本要求 3.9**，请勿使用 3.9+ 独有的语法特性（如 `match/case` 需要 3.10），保持向下兼容
- 各模块的 `detect()` 函数签名必须严格遵守 `docs/interface_spec.md`，**不要在函数签名中添加额外必填参数**（可选参数可以，但需有默认值）
- 联调前各模块可独立运行验证：`python -m src.<模块>.<文件> --input mock_data/mock_packets.json --output results/<模块>_alerts.json`

---

> **文档维护者**：韩宇飞（组长）
> **最后更新**：2026-07-22（Phase3 完成 + 真实攻击演示方案已规划，426条/27规则/30告警/148测试全绿）
