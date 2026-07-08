# 常见网络攻击的检测系统

信息安全科技创新 · 课程大作业

---

## 一、项目简介

本项目基于误用检测（特征串匹配）与异常行为检测两种思路，实现一个网络攻击检测系统，覆盖：

- **特征匹配检测**：内置攻击特征库，匹配病毒、漏洞利用、Web攻击（SQL注入、XSS等）、木马远控、恶意命令等固定报文指纹
- **异常行为检测**：建立主机并发连接、访问频次、端口访问、会话时长等基线，识别单IP高频扫描、短时间大量登录、异常外联陌生IP、内网横向扩散等偏离行为
- **友好的用户界面**：规则库管理 + 实时告警展示

系统整体数据流：**数据包捕获 → TCP重组/协议识别 → （特征匹配 / 异常行为检测）→ 告警汇总 → GUI展示**

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

| 姓名 | 学号 | 邮箱 | Git 分支 | 负责模块 |
|---|---|---|---|---|
| **韩宇飞（组长）** | 524031910172 | hanyufei24@sjtu.edu.com | `feature/gui-alert` | 告警汇总 + 规则管理/展示GUI + 项目统筹 |
| 李哲 | 524031910017 | lz3191323623@sjtu.edu.cn | `feature/packet-capture` | 数据包捕获与协议解析（地基模块） |
| 曾子恒 | 523010910022 | zengziheng@sjtu.edu.cn | `feature/signature-engine` | 特征串匹配引擎（攻击特征库 + 匹配算法） |
| 陈志恒 | 524031910111 | change57@sjtu.edu.cn | `feature/bruteforce-detect` | 暴力破解 / 非法登录检测 |
| 姜新晨 | 524031910769 | debruyne17@sjtu.edu.cn | `feature/anomaly-detect` | 异常流量 / 扫描行为基线检测 |

组长电话：18737507536

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
├── results/
│   ├── signature_alerts.json
│   ├── bruteforce_alerts.json
│   ├── anomaly_alerts.json
│   └── merged_alerts.json           # 韩宇飞汇总输出
├── tests/
│   ├── __init__.py
│   ├── test_capture.py
│   ├── test_signature.py
│   ├── test_bruteforce.py
│   ├── test_anomaly.py
│   └── test_gui_aggregator.py
└── docs/
    ├── interface_spec.md            # 接口规范（权威版本）
    └── final_report.md              # 最终答辩报告/PPT素材
```

> 每人只在自己负责的 `src/<模块>/` 目录及对应 `tests/test_xxx.py` 内开发，避免相互修改文件产生冲突。

---

## 五、各模块任务清单

### A. 数据包捕获与协议解析 —— 李哲（地基模块，需第一时间交付接口数据）
- 功能：调用 scapy 捕获网络报文；对 TCP 流做重组（不考虑跨包攻击特征可先简化）；解析出 IP/TCP/UDP/应用层字段与 payload
- 输出：标准化报文记录（供 B/C/D 三个模块统一消费）
- **关键职责**：Phase1 阶段必须交付 `mock_data/mock_packets.json`——一批覆盖"正常流量、SQL注入/XSS特征报文、高频登录尝试、端口扫描"等场景的模拟报文数据，供其余三人在真实抓包模块完成前先行开发和自测
- 加分项：支持 IP 分片重组、加密流量的基础识别（仅识别是否为TLS流量，不要求解密）

### B. 特征串匹配引擎 —— 曾子恒
- 功能：维护攻击特征库（配置文件 `config/signatures.txt`，格式为 `规则ID | 攻击类型 | 匹配模式(literal/regex) | 特征串 | 适用协议 | 严重程度`），对报文 payload 做特征匹配，覆盖 SQL注入、XSS、木马通信、恶意命令等
- 技术要点：先实现暴力字符串匹配 baseline，**可选做加分项**——替换为 KMP/BM/AC自动机等高效算法，并测试匹配速度对比（这是本项目最容易出彩、最容易量化的创新点）
- 输入：`mock_data/mock_packets.json`（Phase1-3）→ 真实抓包模块输出（Phase4联调后）
- 输出：`results/signature_alerts.json`

### C. 暴力破解 / 非法登录检测 —— 陈志恒
- 功能：监控 SSH(22)、FTP(21)、Web登录等端口的连接与认证尝试，识别短时间内针对同一目标的大量登录请求，判定为暴力破解/非法尝试登录
- 技术要点：基于时间窗口的计数统计（如60秒内同一源IP对同一端口的连接次数超过阈值即告警）。可结合 `direction` / `flags` 字段辅助判断连接是否被拒绝
- 输入：`mock_data/mock_packets.json` → 真实抓包模块输出
- 输出：`results/bruteforce_alerts.json`

### D. 异常流量 / 扫描行为基线检测 —— 姜新晨
- 功能：建立主机行为基线（并发连接数、访问频次、端口访问分布、会话时长等），识别偏离基线的行为：单IP高频端口扫描、异常外联陌生IP、内网横向扩散迹象
- 技术要点：基线可先用简单的统计阈值（均值+标准差或固定阈值），阈值存放于 `config/baseline_config.json` 方便调整
- 输入：`mock_data/mock_packets.json` → 真实抓包模块输出
- 输出：`results/anomaly_alerts.json`
- 加分项：机器学习方法识别未知模式（可选，作为传统阈值方法的对比补充，不强制要求）

### E. 告警汇总 + 规则管理/展示 GUI —— 韩宇飞（组长）
- 功能 1：`aggregator.py` 汇总 B/C/D 三个模块输出的告警 json，去重/排序后统一展示
- 功能 2：GUI（tkinter/PyQt/或简易Web页面），展示实时告警列表、支持按类型/严重程度筛选，支持特征库的导入导出/增删改查界面
- 输出：`results/merged_alerts.json` + 图形界面
- 组长额外职责：统筹进度、组织联调、定义并维护统一告警 schema、维护 `main.py` 入口与本 README

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
def detect(packets: list[dict]) -> list[dict]:
    """
    packets: 符合上方 schema 的报文记录列表
    返回: 符合下方"统一告警格式"的告警列表
    """
```

### 6.2 统一告警格式（B/C/D 输出，供 E 汇总）

```json
{
  "alert_id": "uuid-string",
  "detector": "signature",
  "category": "Web攻击/SQL注入",
  "src_ip": "192.168.1.10",
  "src_port": 51234,
  "dst_ip": "192.168.1.20",
  "dst_network": null,
  "dst_port": 80,
  "severity": "high",
  "description": "检测到SQL注入特征: UNION SELECT",
  "evidence": "GET /login.php?id=1 UNION SELECT ...",
  "timestamp": "2026-07-08T10:00:01"
}
```

字段说明：
- `detector`: `signature`（特征匹配）/ `bruteforce`（暴力破解）/ `anomaly`（异常行为）
- `severity`: `low` / `medium` / `high`
- `category`: 简要攻击类型描述，如"暴力破解/非法登录"、"端口扫描"、"内网横向扩散"等
- `dst_network`（可选）：CIDR 网段（如 `"192.168.1.0/24"`），仅在端口扫描、横向扩散等网段级告警时填写

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

# 创建并切换到自己的分支（以曾子恒为例）
git checkout -b feature/signature-engine

# 日常提交
git add .
git commit -m "[signature] feat: Phase1 环境搭建与接口骨架完成"
git push origin feature/signature-engine

# 完成阶段后在网页端发起 Pull Request 到 main
```

---

## 八、阶段划分与提交要求

> **原则：每人独立开发，每完成一个阶段提交（commit）一次，禁止攒到最后一次性提交。**

| 阶段 | 内容 | 时间 | Commit message 示例 |
|---|---|---|---|
| **Phase 1** | **李哲**：7/9(四)~7/12(日) 交付 `mock_data/mock_packets.json`；**其余人**：7/13(一)起拉分支、搭建模块骨架、基于统一格式确认接口无误 | 7/9 ~ 7/14 | `[capture] feat: 抓包框架骨架 + mock数据交付` |
| **Phase 2** | 完成核心检测逻辑；基于 mock 数据跑通基础用例（如成功检出SQL注入/暴力破解/端口扫描）| 7/15 ~ 7/21 | `[bruteforce] feat: 核心检测逻辑实现完成` |
| **Phase 2.5** | **接口对齐检查**：每人用真实输出跑一次 `aggregator.py` 骨架，确认告警格式与接口规范完全一致 | 7/20(日) | — |
| **Phase 3** | 编写 `tests/test_xxx.py` 单元测试，覆盖正常/异常场景；补充日志与异常处理 | 7/22 ~ 7/25 | `[anomaly] test: 单元测试与异常处理完成` |
| **Phase 4** | 补充模块内文档/注释/使用示例；**真实抓包模块替换mock数据，与其余模块联调**；提交 PR 到 main | 7/26 ~ 7/29 | `[gui] feat: 文档补充与全链路联调完成` |
| **Phase 5** | 根据 Review 意见修改；准备演示数据/截图/答辩素材 | 7/30 ~ 8/5 | `[signature] docs: 最终版本，验收就绪` |

> **新增 Phase 2.5**（审阅修订）：在第 2 周末进行一次接口对齐检查，由韩宇飞运行 `aggregator.py` 读取各模块输出，提前发现格式不一致问题，避免所有联调风险积压到 Phase4。

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

1. 各自在 feature 分支完成 Phase1~Phase4 后，发起 Pull Request 到 `main`
2. 组长（韩宇飞）或指定同学完成 Code Review
3. Review 通过后合并入 `main`；若有冲突，由提出者自行解决后重新提交
4. **Phase1 结束后**，李哲优先合并其骨架 + mock 数据，确保其余三人 Phase2 起有稳定的数据源可用
5. **Phase 2.5**（第2周末），韩宇飞运行 `aggregator.py` 对各模块实际输出做接口格式校验，发现不一致立即通知对应同学修正
6. **Phase4 阶段**，李哲的真实抓包模块与 B/C/D 三个检测模块做替换 mock 数据的全链路联调，确认真实场景下检测结果仍然正确
7. 全部模块合并后，由韩宇飞负责的 `aggregator.py` + `gui.py` 统一读取 `results/` 下所有 json，完成汇总展示联调
8. 联调中发现的问题以 Issue 形式记录 → 原模块负责人修复 → 重新提交 → 再次合并

---

## 十、时间计划表（可按实际调整）

| 日期 | 里程碑 |
|---|---|
| 7/9(四) ~ 7/12(日) | **李哲**交付 mock 数据 + 抓包骨架（地基先行） |
| 7/13(一) ~ 7/14(一) | 其余四人拉分支、确认接口、搭建模块骨架 |
| 7/15 ~ 7/21 | 各检测模块核心功能实现完成（基于mock数据可正确检出对应攻击）；**7/20 接口对齐检查** |
| 7/22 ~ 7/29 | 单元测试通过；真实抓包模块与检测模块联调；PR提交 |
| 7/30 ~ 8/5 | GUI汇总展示完成；最终验收；答辩材料（PPT/演示视频/测试数据）准备完毕 |

---

## 十一、注意事项

- **开发环境**：实时抓包相关操作（scapy 混杂模式）需要管理员/root 权限，且 Windows 下兼容性差。**强烈建议全员在 Linux 虚拟机（如 Ubuntu 22.04）或 WSL2 中开发**，避免环境差异导致的联调问题
- 特征库、基线阈值等配置文件统一放在 `config/` 目录，便于集中管理和演示时调整
- 请**仅在自己搭建的测试环境或授权范围内**产生测试流量（如自己触发SQL注入/暴力破解请求用于验证检测效果），不要对外部无关网络发起攻击性请求
- Phase1 的 mock 数据质量直接影响后续三人的开发效率，建议李哲在设计 mock 数据时，逐条标注"预期应被哪个模块检测出、检测结果应是什么"，方便大家自测比对
- **Python 最低版本要求 3.9**，请勿使用 3.9+ 独有的语法特性（如 `match/case` 需要 3.10），保持向下兼容
- 各模块的 `detect()` 函数签名必须严格遵守 `docs/interface_spec.md`，**不要在函数签名中添加额外必填参数**（可选参数可以，但需有默认值）

---

> **文档维护者**：韩宇飞（组长）
> **最后更新**：2026-07-08（审阅修订版）
