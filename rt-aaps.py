#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RT-AAPS 主程序入口
AI自动化渗透作战系统：本地模型 + Kali 原生工具 + 自建漏洞/脚本库
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.task_planner import TaskPlanner
from core.tool_executor import ToolExecutor
from core.vuln_matcher import VulnMatcher
from core.result_analyzer import ResultAnalyzer


def load_config():
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "settings.json")
    with open(cfg_path, "r", encoding="utf-8") as f:
        return json.load(f)


def print_banner():
    banner = """
╔══════════════════════════════════════════════════╗
║   ____  _____ _    _    _    ____   ___  ____    ║
║  |  _ \\|_   _| |  / \\  / \\  |  _ \\ / _ \\/ ___|  ║
║  | |_) | | | | | / _ \\/ _ \\ | |_) | | | \\___ \\  ║
║  |  _ <  | | | |/ ___ \\ ___ \\|  __/| |_| |___) | ║
║  |_| \\_\\ |_| |_/_/   \\_\\_/  \\_\\_|   \\___/|____/  ║
║                                                  ║
║   AI Automated Attack Platform System  v3.0      ║
║   本地模型 + Kali原生工具 + 自建漏洞/脚本库       ║
╚══════════════════════════════════════════════════╝
"""
    print(banner)


def print_help():
    help_text = """
═══════════════ 帮助信息 ═══════════════
【大白话指令示例】
  扫描192.168.10.0/24网段存活主机
  对192.168.10.152做端口和服务扫描
  用永恒之蓝攻击192.168.10.152
  扫描192.168.10.152的Web漏洞
  对192.168.10.0/24网段进行完整渗透测试
  用我的 quick_host_scan 脚本扫网段
  给192.168.10.152做目录爆破

【内置命令】
  help     显示帮助
  report   生成会话汇总报告
  vulns    查看本地漏洞库
  tools    查看工具库
  scripts  查看自定义脚本
  clear    清空会话记录
  exit     退出系统
═══════════════════════════════════════
"""
    print(help_text)


def main():
    config = load_config()
    print_banner()

    planner = TaskPlanner(config)
    executor = ToolExecutor(config)
    matcher = VulnMatcher(config)
    analyzer = ResultAnalyzer(config)

    session_records = []
    print(f"[+] 模型：{config['ollama']['model']}")
    print(f"[+] 本机IP：{executor.local_ip}  |  监听端口：{executor.msf_port}")
    print(f"[+] 漏洞库：已加载 {len(matcher.db)} 条漏洞  |  工具库：{len(executor.tool_db)} 类")
    print(f"[+] 自定义脚本：{len(executor.list_scripts())} 个")
    print("[+] 输入任务开始执行，输入 help 查看帮助，输入 exit 退出\n")

    while True:
        try:
            user_input = input("[RT-AAPS] >> ").strip()
            if not user_input:
                continue

            cmd = user_input.lower()
            if cmd == "exit":
                print("[!] 退出系统")
                break
            elif cmd == "help":
                print_help()
                continue
            elif cmd == "report":
                if session_records:
                    report = analyzer.generate_report(session_records)
                    print("\n" + "=" * 50)
                    print("  会话执行报告")
                    print("=" * 50)
                    print(report)
                    print("=" * 50 + "\n")
                else:
                    print("[-] 当前会话无执行记录")
                continue
            elif cmd == "clear":
                session_records.clear()
                print("[+] 已清空会话记录")
                continue
            elif cmd == "vulns":
                print(f"\n[+] 本地漏洞库（{len(matcher.db)} 条）：")
                for k, v in matcher.db.items():
                    print(f"  - {k} : {v['name']} [{v['tool']}]")
                print()
                continue
            elif cmd == "tools":
                print(f"\n[+] 工具库（{len(executor.tool_db)} 类）：")
                for k, v in executor.tool_db.items():
                    print(f"  - {v['name']} : {v['cmd_template']}")
                print()
                continue
            elif cmd == "scripts":
                scripts = executor.list_scripts()
                print(f"\n[+] 自定义脚本（{len(scripts)} 个）：")
                for s in scripts:
                    print(f"  - scripts/{s}")
                print()
                continue

            # ========== 1. 任务拆解 ==========
            print("\n[*] 正在分析任务，规划执行步骤...")
            steps = planner.decompose(user_input)
            if not steps:
                print("[-] 任务拆解失败，请换一种说法重新描述")
                continue

            # 注入漏洞 key 和自定义脚本
            steps = planner.inject_vuln_keys(steps, user_input, matcher)
            steps = planner.inject_script(steps, user_input, executor.list_scripts())

            print(f"[+] 规划完成，共 {len(steps)} 个步骤：")
            for s in steps:
                extra = ""
                if s.get("vuln_key"):
                    extra = f"  → 利用漏洞 [{s['vuln_key']}]"
                if s.get("script"):
                    extra = f"  → 调用脚本 [{s['script']}]"
                print(f"    {s['step']}. {s['action']} [{s['tool']}]{extra}")

            confirm = input("\n确认执行该计划？(y/n)：").strip().lower()
            if confirm != "y":
                print("[*] 已取消任务")
                continue

            # ========== 2. 分步执行 ==========
            step_results = []
            for step in steps:
                print(f"\n━━━ 执行步骤 {step['step']}：{step['action']} ━━━")

                # 执行
                raw_output = executor.execute(step)

                # 端口/服务扫描后自动漏洞匹配
                action_l = step["action"].lower()
                if ("端口" in action_l or "服务" in action_l) and not step.get("vuln_key"):
                    vulns = matcher.match(raw_output)
                    if vulns:
                        vuln_names = [matcher.db[v]["name"] for v in vulns]
                        print(f"\n[+] 检测到潜在漏洞：{', '.join(vuln_names)}")
                        step["detected_vulns"] = vulns
                        print("[+] 下一步可输入：利用 <漏洞> 攻击 <目标>")

                # 结果分析
                summary = analyzer.analyze(step["action"], raw_output)

                step_result = {
                    "step": step["step"],
                    "action": step["action"],
                    "summary": summary,
                    "raw": raw_output[:1000],
                }
                step_results.append(step_result)
                session_records.append(step_result)

                # 输出本步结果
                print("\n" + "-" * 40)
                print("[+] 本步结果：")
                print(summary)
                print("-" * 40)

            print("\n✅ 本轮任务执行完成")
            print("[提示] 输入 report 查看完整汇总报告\n")

        except KeyboardInterrupt:
            print("\n[!] 中断当前操作")
            continue
        except Exception as e:
            print(f"[-] 系统错误：{str(e)}")


if __name__ == "__main__":
    main()
