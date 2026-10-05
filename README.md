# RT-AAPS

> **R**eal-**T**ime **A**I **A**utomated **A**ttack **P**latform **S**ystem
> 基于本地大模型 + Kali 原生工具 + 自建漏洞/脚本库的交互式自动化渗透框架

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![Platform](https://img.shields.io/badge/Platform-Kali_Linux-black) ![License](https://img.shields.io/badge/License-仅供授权测试使用-red)

---

## 项目定位

| 特性 | 说明 |
|------|------|
| 🔒 纯本地运行 | 调用本地 Ollama 模型，工具、漏洞库、脚本库全部本地化，无需外网 |
| 🗣️ 自然语言驱动 | 大白话下达任务，AI 拆解步骤、调用工具、分析结果 |
| 🛡️ 稳场可控 | 每步人工确认，核心操作二次校验，绝不盲执行 |
| 🧩 可扩展架构 | 漏洞库、脚本库、工具库均可自行添加，框架不动能力扩容 |
| 🎯 紧贴靶场链路 | 适配「外网跳板 → 内网代理 → 横向移动 → 域控」标准攻击路径 |

> ⚠️ **免责声明**：本项目仅用于授权范围内的网络安全竞赛、CTF、靶场训练及教学研究。严禁用于未授权的真实目标。使用者需自行承担一切法律责任。

---

## 系统架构

```
┌──────────────────────────────────────────────┐
│           交互层 [RT-AAPS] 终端                │
│   大白话指令 → 执行计划 → 结果分析 → 下一步    │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│           智能调度层（本地 Ollama 模型）        │
│   任务拆解 → 命令生成 → 结果提炼 → 报告汇总    │
└──────────────────────┬───────────────────────┘
                       ↓
┌──────────────────────────────────────────────┐
│           执行层（Kali 原生能力）              │
│   ┌──────────┐ ┌──────────┐ ┌────────────┐   │
│   │ 本地漏洞库 │ │ 工具库模板 │ │ 自定义脚本库 │   │
│   │ exploit_db│ │ tool_db  │ │  scripts/  │   │
│   └──────────┘ └──────────┘ └────────────┘   │
│   nmap / gobuster / nikto / sqlmap / hydra    │
│   msfconsole（MSF 自动利用）                   │
└──────────────────────────────────────────────┘
```

### 双轨执行机制（核心设计）

| 轨道 | 适用场景 | 特点 |
|------|---------|------|
| **本地漏洞库** | 永恒之蓝、MS08-067、SQL注入、弱口令爆破等标准漏洞 | 命令 100% 准确，不依赖 AI 生成 |
| **工具库模板** | 端口扫描、目录爆破、Web扫描等常规操作 | 关键词命中，命令精准 |
| **AI 生成命令** | 上述未覆盖的灵活任务 | 兜底方案，AI 生成后人工确认 |

> 执行策略优先级：**漏洞库 > 自定义脚本 > 工具库模板 > AI 生成**

---

## 目录结构

```
RT-AAPS/
├── README.md              # 项目说明文档
├── rt-aaps.py             # 主程序入口（交互终端）
├── config/
│   └── settings.json      # 全局配置（模型/超时/端口/路径）
├── core/                  # 核心引擎
│   ├── __init__.py
│   ├── task_planner.py    # 任务拆解引擎（大白话 → 步骤计划）
│   ├── tool_executor.py   # 工具执行引擎（漏洞库/脚本/模板/AI）
│   ├── vuln_matcher.py    # 漏洞匹配引擎（端口规则 + AI 精筛）
│   └── result_analyzer.py # 结果分析引擎（提炼/报告）
├── db/                    # 本地知识库
│   ├── exploit_db.json    # 漏洞库（可无限扩展）
│   └── tool_db.json       # 工具库（命令模板）
├── scripts/               # 自定义脚本库（你自己写的）
│   ├── reverse/           # 反弹 shell 类
│   ├── scan/              # 扫描类
│   └── exploit/           # 利用类
└── prompts/
    └── system_prompts.py  # 系统提示词（AI 行为约束）
```

---

## 安装部署

### 1. 环境要求
```bash
# Kali Linux + Python3 + Ollama
ollama pull qwen2.5:1.5b          # 下载本地模型（已装可跳过）
pip install ollama                # Python SDK（建议用 venv/conda 环境）
```

### 2. 从 GitHub 下载
```bash
git clone https://github.com/你的用户名/RT-AAPS.git
cd RT-AAPS
```

### 3. 运行
```bash
python3 rt-aaps.py
```

> 如果脚本报错 `bash\r`（Windows 上传导致换行符问题）：
> ```bash
> sudo apt install dos2unix
> find scripts -name "*.sh" -exec dos2unix {} \;
> ```

---

## 使用方法

### 大白话指令示例

```
[RT-AAPS] >> 扫描192.168.10.0/24网段存活主机
[RT-AAPS] >> 对192.168.10.152做端口和服务扫描
[RT-AAPS] >> 用永恒之蓝攻击192.168.10.152
[RT-AAPS] >> 扫描192.168.10.152的Web漏洞
[RT-AAPS] >> 对192.168.10.0/24网段进行完整渗透测试
[RT-AAPS] >> 用我的 quick_host_scan 脚本扫网段
[RT-AAPS] >> 爆破http://192.168.10.152的目录
```

### 内置命令

| 命令 | 功能 |
|------|------|
| `help` | 显示帮助 |
| `report` | 生成会话汇总报告 |
| `vulns` | 查看本地漏洞库 |
| `tools` | 查看工具库 |
| `scripts` | 查看自定义脚本 |
| `clear` | 清空会话记录 |
| `exit` | 退出系统 |

### 完整流程演示
```
输入: 对192.168.10.0/24网段进行完整渗透测试
AI拆解: ①存活主机扫描 → ②端口扫描 → ③漏洞匹配 → ④利用建议
人工确认后分步执行，每步返回 AI 提炼结果
执行完输入 report 生成完整报告
```

---

## 扩展漏洞库

编辑 `db/exploit_db.json`，按格式添加：

```json
"my_vuln_key": {
    "name": "漏洞名称",
    "aliases": ["中文名", "别名"],        // AI 识别用
    "category": "web",
    "tool": "msf",                        // msf / sqlmap / nmap / hydra / manual
    "module": "exploit/xxx/xxx",          // msf 专用
    "payload": "xxx/meterpreter/reverse_tcp",
    "params": ["RHOSTS", "LHOST", "LPORT"],
    "cmd_template": "工具命令 {target}",   // 非 msf 工具专用
    "description": "漏洞描述"
}
```

`tool` 字段说明：
- `msf` → 自动生成 MSF 资源脚本并后台启动攻击
- `sqlmap` / `nmap` / `hydra` → 执行 `cmd_template`（`{target}` 自动替换）
- `manual` → 只输出利用提示，人工操作

---

## 自定义脚本

把脚本放到 `scripts/` 目录，终端输入 `scripts` 即可查看，大白话直接调用：

```bash
# 示例：自定义扫描脚本
cat > scripts/scan/my_scan.sh << 'EOF'
#!/bin/bash
TARGET=$1
echo "[*] 我的自定义扫描: $TARGET"
nmap -sV -T4 -n $TARGET
EOF
```

```
[RT-AAPS] >> 用我的 my_scan 脚本扫描192.168.10.152
```

支持 `.sh`（bash 调用）和 `.py`（python3 调用），第一个参数为目标。

---

## 配置说明（config/settings.json）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `ollama.model` | qwen2.5:1.5b | 本地模型名 |
| `system.cmd_timeout` | 300 | 命令超时（秒） |
| `system.auto_confirm` | false | true = 跳过人工确认（不推荐） |
| `system.local_ip` | auto | 反向连接监听 IP，可手动指定 |
| `system.msf_listen_port` | 4444 | MSF 监听端口 |

---

## 常见问题

**Q: AI 分析结果出现编造内容？**
A: 系统已强制「100% 基于原始输出」约束。若仍出现，升级模型（如 qwen2.5:7b）效果更佳。

**Q: 网段扫描超时？**
A: 调大 `cmd_timeout`，或改用 `quick_host_scan` 脚本（ARP 模式最快）。

**Q: 命令生成错误？**
A: 标准操作会优先命中工具库/漏洞库（命令固定精准），AI 只兜底非常规任务，且执行前有人工确认。

**Q: MSF 攻击无会话回弹？**
A: 确认目标漏洞版本匹配、防火墙放行 4444 端口、`local_ip` 正确（可手动在 settings.json 指定）。

---

## 许可证

仅供网络安全竞赛、CTF、授权靶场训练使用。禁止用于任何未授权目标。
