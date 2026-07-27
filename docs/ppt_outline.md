# PPT 大纲 —— 网络攻击检测系统

> 10 分钟 | 16 页 | **姜新晨 P1-P8** | **曾子恒 P9-P16** | ddl: 7/28 22:00

## 图例说明

- 🤖 **需画图**：流程图/架构图/示意图（队员负责）
- 📸 **截图**：系统截图/终端截图/Web截图（韩宇飞后补，先留空）
- 📊 **数据图**：matplotlib 生成图表（曾子恒负责，P11）

---

# 姜新晨负责（P1 — P8）

---

## P1 · 封面

- 标题：融合特征匹配与异常行为分析的网络攻击检测系统
- 副标题：信息安全科技创新 · 课程大作业
- 5 人姓名+学号，2026.07

> 无图，纯排版

---

## P2 · 项目背景

**文字**（≤5 条要点）：
- 传统 IDS：逐包报警碎片化，单一检测方法误报率高
- 我们的方案：**特征匹配 + 异常分析** 双引擎互补，**行为粒度**告警
- 覆盖 **9 类攻击**：SQL注入 / XSS / 路径遍历 / 命令注入 / Webshell / 木马 / XXE / 端口扫描 / SSH爆破
- 5 人 4 周，426 条报文 → 30 条行为告警，157 测试全绿

**配图**：
- 🤖 画一张对比图：左侧传统 IDS（碎片告警）→ 右侧本系统（行为告警列表），简洁图标风格

---

## P3 · 系统总架构

**文字**（≤3 条要点，这张图比文字重要）：
- 四层架构：数据采集 → 检测引擎 → 关联汇总 → 展示
- 统一 JSON 接口串联全链路

**配图**：
- 🤖 **核心图，需要精心画**。四层从上到下：
  - 第一层：scapy 抓包 + TCP 重组 + 协议解析
  - 第二层：三个引擎并行（蓝色框 Signature、红色框 Bruteforce、绿色框 Anomaly）
  - 第三层：Aggregator + Correlator
  - 第四层：Web 面板 + tkinter 桌面
  - 层间箭头标数据格式："标准化报文 JSON" → "统一告警 JSON" → "行为告警 JSON"
  - 工具：draw.io / ProcessOn

---

## P4 · 数据流与接口规范

**文字**（≤4 条）：
- 报文格式 JSON（12 字段）→ 三个引擎统一消费
- 告警格式 JSON（11 字段）→ Aggregator 汇总
- 统一函数签名：`detect(packets, config) → alerts`
- 5 人分支持续 4 周，零接口冲突

**配图**：
- 🤖 一张横向流程图：报文 JSON 代码块 → 三个检测器方框 → 告警 JSON 代码块 → 汇总告警
- 关键字段高亮（alert_id, detector, src_ip 等）

---

## P5 · 三引擎总览

**文字**（一表搞定）：

| | Signature | Bruteforce | Anomaly |
|---|---|---|---|
| 方法 | 子串/正则匹配 | 滑窗频率统计 | 基线偏离 |
| 目标 | SQL注入/XSS/Webshell等 | SSH/FTP 爆破 | 端口扫描/外联/横向/高频 |
| mock告警 | 16 | 3 | 11 |
| 负责人 | 曾子恒 | 陈志恒 | 姜新晨 |

- 三引擎并行、格式统一、可独立运行

**配图**：
- 🤖 三个方框 → 汇聚箭头 → Aggregator，简单示意图

---

## P6 · 异常检测详解

**文字**（四格布局，每格 ≤2 行）：

| | 端口扫描 | 异常外联 | 横向扩散 | 高频连接 |
|---|---|---|---|---|
| 窗口 | 60s | — | 300s | 60s |
| 阈值 | ≥15端口 | 内网→公网 | ≥8个内网IP | ≥80次 |
| 判定 | 唯一 dst_port 数 | CIDR 白名单 | 唯一 dst_ip 数 | 总连接数 |

- 固定阈值 + 动态基线互补，阈值统一配置于 `baseline_config.json`

**配图**：
- 🤖 四张卡片横向排列，每张一个图标 + 名称 + 阈值数字 + 一句话。或用一张滑动窗口示意图

---

## P7 · 特征检测 + 暴力破解速览

**文字**：

**特征检测（曾子恒）**：
- 27 条规则，literal 子串 + regex 正则，大小写不敏感
- 行为聚合：同源同目标同类 60s 内命中合并为 1 条告警
- URL 解码：curl 发送 `%3Cscript%3E` → 自动解码为 `<script>` 匹配

**暴力破解（陈志恒）**：
- 双指针滑窗，60s 内 ≥10 次 SYN 连接 → 告警
- 监控 22/21/3306/3389 等端口，无外部工具依赖

**配图**：
- 🤖 左侧：特征匹配流程图（报文→逐条匹配→命中聚合→告警）
- 右侧：滑窗统计示意（时间轴+窗口+计数）

---

## P8 · 跨检测器协同联动

**文字**（≤5 条）：
- **交叉验证**：同 IP 在 signature + anomaly 双引擎命中 → 置信度提升。Mock 中 6 条交叉验证
- **攻击链识别**：6 阶段模型标注（recon → exploitation → installation → C2 → lateral → credential）。Mock 中 20 条攻击链
- **严重度升级**：多引擎交叉 → 自动 medium→high 升级。Mock 中 4 条升级

**配图**：
- 🤖 左侧：攻击链 6 阶段横向箭头，每阶段标对应告警数
- 右侧：交叉验证示意，一个 IP → 两条线（sig + anom）→ 汇聚到升级标记

---

# 曾子恒负责（P9 — P16）

---

## P9 · Mock 全链路结果

**文字**（数字为主）：
- 426 条报文（17 种攻击场景）→ 27 条规则 → **30 条行为告警**
- Signature 16 · Bruteforce 3 · Anomaly 11
- 最高频：SQL注入 5 条，异常外联 4 条
- 157 测试全绿

**配图**：
- 📊 用 matplotlib 生成两张柱状图（代码见附录）：
  - 图1：按检测类别分布（横轴=类别，纵轴=告警数，teal 色）
  - 图2：按严重度分布（HIGH/MEDIUM/LOW，三色柱）
- 📸 统计概览页签截图（韩宇飞后补）

---

## P10 · 跨机器真实攻击演示

**文字**（≤5 条）：
- 环境：Kali VM (192.168.235.133) → VMware NAT → Windows 11 (192.168.235.1)
- Windows 端 Npcap 抓包 VMnet8 + 持续检测 + Web 面板
- 9 类攻击全部执行，1,560 条真实流量 → **18 条告警**
- Kali IP 192.168.235.133 出现在所有告警中，验证跨机器检测正确性

**配图**：
- 🤖 网络拓扑图：Kali 方框 → 攻击箭头 → Windows 方框（标注四个服务：靶机/抓包/检测/Web），中间标 VMnet8
- 📸 双终端同框照（左 Kali 攻击菜单 + 右 Web 面板告警列表）——韩宇飞后补

---

## P11 · Web 监控面板

**文字**（3 个功能点）：
- **Mock/Live 双模式**：Mock=预置数据演示 · Live=2s 自动刷新实时告警
- **三页签**：告警监控（筛选+详情）· 特征库管理（增删规则）· 统计概览（分布图+攻击源排名）
- **清空+基线**：一键重置，后续只检测新攻击

**配图**：
- 📸 三张页签截图横向排列——韩宇飞后补

---

## P12 · SSH 爆破跨机器检测实例

**文字**（一条完整案例展示端到端）：
- Kali hydra → Windows sshd，50 次登录尝试
- 检测到：42 次连接 / 60s 窗口 / 阈值 10 → **HIGH 严重度**
- 攻击链标注：exploitation → credential_access
- 这是三层检测中最直观的一条——从攻击到告警全链路可追溯

**配图**：
- 📸 Web 面板告警详情截图（点击 SSH 爆破那行展开后的完整面板）——韩宇飞后补

---

## P13 · 测试覆盖与代码质量

**文字**（数字+要点）：

| 模块 | 测试数 |
|------|--------|
| capture | 24 |
| signature | 38 |
| bruteforce | 25 |
| anomaly | 45 |
| aggregator+gui | 25 |
| **合计** | **157 passed** |

- 全项目 docstring 覆盖率 >95%
- 统一 logging 日志规范，统一 Commit 规范

**配图**：
- 📸 pytest 全绿终端输出截图——韩宇飞后补

---

## P14 · 技术难点与解决方案

**文字**（3-4 个坑，精炼到各 1 行）：
- **URL 编码匹配**：curl 发送 `%3Cscript%3E`，签名找 `<script>` → 加 `unquote()` 解码
- **跨机器抓包**：CMD `set` 尾随空格 → 接口名错误 → 环境变量 + `.strip()` 修复
- **SIGTERM 丢数据**：`sniff()` 被 kill 来不及 `save_packets()` → 改为 `prn` 回调边抓边存
- **清空后旧包复现**：抓包文件已积累 → 基线计数机制跳过已检测包

---

## P15 · 心得体会

**文字**（每人 1 条，≤5 条总共）：
- 统一接口是 5 人协作的基石——前期 2 天定义 interface_spec，后期 4 周零冲突
- Mock 数据驱动的并行开发——各模块独立验证，合入即跑通
- 双引擎互补让系统检测面更宽——特征覆盖已知，异常捕获未知
- 老师建议的 TCP 流重组增强 + 协同联动 → 系统质量质的提升
- 真实流量与 mock 差异巨大——URL编码、包序、时序都需要额外处理

---

## P16 · Q&A + 致谢

**文字**：
- GitHub: `github.com/pnnooy/network_detection`
- 谢谢老师与助教
- 欢迎提问

**配图**：
- 防翻车三条：Plan A 现场跨机器 / Plan B 预录视频 / Plan C Mock模式
- 或纯色背景 + 大字 Q&A

---

## 附录 A · 配图责任清单

| 页码 | 图类型 | 谁做 |
|------|--------|------|
| P2 | 🤖 传统 vs 本系统对比图 | 姜新晨 |
| P3 | 🤖 系统架构图（核心！） | 姜新晨 |
| P4 | 🤖 数据流+接口示意图 | 姜新晨 |
| P5 | 🤖 三引擎并行汇聚图 | 姜新晨 |
| P6 | 🤖 四维检测卡片+滑窗示意 | 姜新晨 |
| P7 | 🤖 特征匹配流程+暴力破解滑窗 | 姜新晨 |
| P8 | 🤖 攻击链时间线+交叉验证 | 姜新晨 |
| P9 | 📊 matplotlib 柱状图×2 | 曾子恒 |
| P9 | 📸 统计概览截图 | 韩宇飞 |
| P10 | 🤖 网络拓扑图 | 曾子恒 |
| P10 | 📸 双终端同框照 | 韩宇飞 |
| P11 | 📸 Web 三页签截图 | 韩宇飞 |
| P12 | 📸 告警详情截图 | 韩宇飞 |
| P13 | 📸 pytest 截图 | 韩宇飞 |
| P14 | 无图 | — |
| P15 | 无图 | — |
| P16 | 无图 | — |

## 附录 B · matplotlib 代码（P9 柱状图）

```python
import json
from collections import Counter
import matplotlib.pyplot as plt
import matplotlib
matplotlib.rcParams['font.sans-serif'] = ['SimHei']
matplotlib.rcParams['axes.unicode_minus'] = False

with open('results/merged_alerts.json', encoding='utf-8') as f:
    alerts = json.load(f)

# 图1：按类别
cats = Counter(a['category'] for a in alerts)
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(cats.keys(), cats.values(), color='#0d9488', edgecolor='white')
ax.set_title('Alert Distribution by Category', fontsize=14, fontweight='bold')
ax.set_ylabel('Alert Count')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('ppt_category_dist.png', dpi=150, bbox_inches='tight')

# 图2：按严重度
sevs = Counter(a['severity'] for a in alerts)
colors = {'high': '#dc3545', 'medium': '#fd7e14', 'low': '#ffc107'}
fig, ax = plt.subplots(figsize=(6, 5))
ax.bar([s.upper() for s in sevs.keys()], sevs.values(),
       color=[colors.get(s, '#0d9488') for s in sevs.keys()], edgecolor='white')
ax.set_title('Alert Distribution by Severity', fontsize=14, fontweight='bold')
ax.set_ylabel('Alert Count')
plt.tight_layout()
plt.savefig('ppt_severity_dist.png', dpi=150, bbox_inches='tight')
```

## 附录 C · 每页风格要求

- 标题明确加粗，正文 ≤5 条要点，**不要大段文字**
- 每页至少 1 张配图（🤖 需画 / 📸 留空待补）
- 统一使用 teal 色系主题（`#0d9488` 主色）
- 推荐字体：微软雅黑（中文）+ Arial（英文/数字）
