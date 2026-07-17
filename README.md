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
- [十、时间计划表](#十时间计划表)
- [十一、注意事项](#十一注意事项)

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

| 姓名 | 学号 | 邮箱 | Git 分支 | 负责模块 |
|---|---|---|---|---|
| **韩宇飞（组长）** | 524031910172 | hanyufei24@sjtu.edu.com | `feature/gui-alert` | 告警汇总 + 规则管理/展示GUI + 项目统筹 |
| 李哲 | 524031910017 | lz3191323623@sjtu.edu.cn | `feature/packet-capture` | ✅ 数据包捕获与协议解析（地基模块） |
| 曾子恒 | 523010910022 | zengziheng@sjtu.edu.cn | `feature/signature-engine` | 特征行为检测引擎（特征库 + 匹配算法 + 行为聚合） |
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
    ├── 选题报告.md                   # 项目选题报告
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

### B. 特征行为检测引擎 —— 曾子恒
- 功能：维护攻击特征库（配置文件 `config/signatures.txt`，格式为 `规则ID | 攻击类型 | 匹配模式(literal/regex) | 特征串 | 适用协议 | 严重程度`），对报文 payload 做特征匹配，覆盖 SQL注入、XSS、木马通信、恶意命令等
- **行为聚合**：对同一源 IP 在时间窗口（默认 60 秒）内对同一目标命中同类特征的多次匹配，聚合为一条攻击行为告警，而非逐包逐条报警。告警描述应体现攻击行为（如"针对 /login.php 的 SQL 注入攻击行为"），而非仅罗列特征串
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

### E. 告警汇总 + 行为关联 + 监控 GUI —— 韩宇飞（组长）
- 功能 1：`aggregator.py` 汇总 B/C/D 三个模块输出的告警 json，按 timestamp 排序、按 alert_id 去重
- 功能 2：**行为关联**：将来自同一源 IP、同一 attack_category、时间相近（默认 60 秒内）的多条告警归入同一攻击行为事件，赋予相同的 `behavior_id`，便于 GUI 以行为粒度而非逐条告警维度展示
- 功能 3：GUI（tkinter/PyQt/或简易Web页面），以攻击行为为粒度展示实时告警、支持按行为类型/严重程度/攻击源筛选，支持特征库的导入导出/增删改查界面
- 输出：`results/merged_alerts.json`（含 `behavior_id`）+ 图形界面
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

| 阶段 | 内容 | 时间 | Commit message 示例 |
|---|---|---|---|
| **Phase 1** | **李哲**：7/9(四)~7/12(日) 交付 `mock_data/mock_packets.json`；**其余人**：7/13(一)拉分支、搭建模块骨架、确认接口 | 7/9 ~ 7/13 | `[capture] feat: 抓包框架骨架 + mock数据交付` |
| **Phase 2** | 完成核心检测逻辑；基于 mock 数据跑通基础用例（如正确检出SQL注入攻击行为/暴力破解行为/端口扫描行为）| 7/14(二) ~ 7/18(六) | `[bruteforce] feat: 核心检测逻辑实现完成` |
| **Phase 2.5** | **接口对齐检查**：每人用真实输出跑 `aggregator.py`，确认告警格式含 `behavior_id`、`description` 为行为导向语态 | 7/20(一) | — |
| **Phase 3** | 编写单元测试，覆盖正常/异常场景；补充日志与异常处理 | 7/21(二) ~ 7/22(三) | `[anomaly] test: 单元测试与异常处理完成` |
| **Phase 4** | 真实抓包替换mock数据联调；补充文档/注释；提 PR 合入 main | 7/23(四) ~ 7/25(六) | `[gui] feat: 全链路联调 + PR合入` |
| **Phase 5** | PPT、演示数据、截图、结题报告 | 7/26(日) ~ 7/28(二) | `[signature] docs: 答辩材料准备完成` |
| **🎤 内部预演** | 完整走一遍汇报流程，发现并修正问题 | **7/28(二)** | — |
| **★ 项目汇报** | 课堂分享汇报 | **7/29(三)** | — |
| **📝 结题报告** | 结题报告撰写 + 源码整理 | 7/30(四) ~ 8/1(六) | — |
| **🏁 提前提交** | 源码 + 结题报告打包提交 | **8/2(日)** | — |
| **缓冲** | 应对意外问题 | 8/3(一) ~ 8/4(二) | — |
| **📅 官方截止** | 结题报告提交截止 | 8/5(三) | — |

> **Phase 2.5 定在周一**：7/20(一) 由韩宇飞运行 `aggregator.py` 读取各模块实际输出，校验告警格式。发现不一致立即通知对应同学修正。

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
4. **✅ Phase1 已完成**，李哲的 capture 模块 + mock 数据已合入 main，其余三人 Phase2 起有稳定的数据源可用
5. **Phase 2.5**（7/20 周一），韩宇飞运行 `aggregator.py` 对各模块实际输出做接口格式校验，发现不一致立即修正
6. **Phase4 阶段**，李哲的真实抓包模块与 B/C/D 三个检测模块做替换 mock 数据的全链路联调，确认真实场景下检测行为结果仍然正确
7. 全部模块合并后，由韩宇飞负责的 `aggregator.py` + `gui.py` 统一读取 `results/` 下所有 json，完成行为关联汇总展示联调
8. 联调中发现的问题以 Issue 形式记录 → 原模块负责人修复 → 重新提交 → 再次合并

---

## 十、时间计划表

> 官方节点：第4周周三(7/29)汇报、第5周周三(8/5)提交。本表在此基础上提前 3 天留余量。

| 日期 | 里程碑 |
|---|---|
| 7/9(四) ~ 7/12(日) | ✅ **李哲**交付 mock 数据 + capture 模块（已完成合入） |
| 7/13(一) ~ 7/18(六) | 四人完成核心检测逻辑，7/20(一) **接口对齐检查** |
| 7/20(一) ~ 7/22(三) | 单元测试 + 异常处理，修正接口问题 |
| 7/23(四) ~ 7/25(六) | 联调 + PR 合入 main |
| 7/26(日) ~ 7/27(一) | PPT + 演示数据准备 |
| 7/28(二) | **内部预演**，发现并修正问题 |
| **7/29(三)** | ★ **项目分享汇报** |
| 7/30(四) ~ 8/1(六) | 结题报告撰写 + 源码整理 |
| **8/2(日)** | 🏁 **提前提交**（比 8/5 截止早 3 天） |
| 8/3(一) ~ 8/4(二) | 缓冲（应对意外） |
| 8/5(三) | 📅 官方截止，确认提交无误 |

---

## 十一、注意事项

- **开发环境**：实时抓包相关操作（scapy 混杂模式）需要管理员/root 权限，且 Windows 下兼容性差。**强烈建议全员在 Linux 虚拟机（如 Ubuntu 22.04）或 WSL2 中开发**，避免环境差异导致的联调问题
- 特征库、基线阈值等配置文件统一放在 `config/` 目录，便于集中管理和演示时调整
- 请**仅在自己搭建的测试环境或授权范围内**产生测试流量（如自己触发SQL注入/暴力破解请求用于验证检测效果），不要对外部无关网络发起攻击性请求
- ✅ Phase1 已完成，mock 数据已合入 main，覆盖 7 种场景 108 条记录。各检测模块基于 mock 数据自测时对照 `docs/interface_spec.md` 第 2.3 节的场景-预期检测结果对照表
- **Python 最低版本要求 3.9**，请勿使用 3.9+ 独有的语法特性（如 `match/case` 需要 3.10），保持向下兼容
- 各模块的 `detect()` 函数签名必须严格遵守 `docs/interface_spec.md`，**不要在函数签名中添加额外必填参数**（可选参数可以，但需有默认值）

---

> **文档维护者**：韩宇飞（组长）
> **最后更新**：2026-07-13（Phase2 启动）
