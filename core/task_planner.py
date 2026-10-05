# -*- coding: utf-8 -*-
"""
RT-AAPS 任务拆解引擎
将用户大白话任务拆解为有序执行步骤（JSON 数组）
"""
import json
import re
import ollama
from prompts.system_prompts import TASK_PLANNER_PROMPT


class TaskPlanner:
    def __init__(self, config):
        self.config = config
        self.model = config["ollama"]["model"]

    def decompose(self, task):
        """拆解任务，返回步骤列表，失败返回 None"""
        prompt = TASK_PLANNER_PROMPT.format(task=task)
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0},
            )
            text = resp["message"]["content"].strip()

            # 提取 JSON 数组
            m = re.search(r"\[.*\]", text, re.DOTALL)
            if not m:
                print("[-] AI 未返回有效 JSON 计划")
                return None

            steps = json.loads(m.group())

            # 校验并规范化
            valid = []
            for idx, s in enumerate(steps):
                if not isinstance(s, dict):
                    continue
                action = s.get("action", "")
                tool = s.get("tool", "")
                if not action or not tool:
                    continue
                s.setdefault("step", idx + 1)
                s.setdefault("target", "")
                s.setdefault("vuln_key", "")
                valid.append(s)

            return valid if valid else None
        except Exception as e:
            print(f"[-] 任务拆解出错：{str(e)}")
            return None

    def inject_vuln_keys(self, steps, user_input, matcher):
        """根据用户输入中的漏洞关键词，把 vuln_key 注入到利用步骤"""
        lower_input = user_input.lower()
        for key, exp in matcher.db.items():
            names = [key.lower(), exp["name"].lower()]
            names += [a.lower() for a in exp.get("aliases", [])]
            if any(n in lower_input for n in names if n):
                for s in steps:
                    if "利用" in s.get("action", "") or "攻击" in s.get("action", ""):
                        s["vuln_key"] = key
        return steps

    def inject_script(self, steps, user_input, scripts):
        """如果用户提到自己的脚本，把 script 字段注入对应步骤"""
        lower_input = user_input.lower()
        if "脚本" not in lower_input and "script" not in lower_input:
            return steps
        for s in steps:
            if not s.get("script") and not s.get("vuln_key"):
                for name in scripts:
                    if name.lower().split("/")[-1].replace(".sh", "").replace(".py", "") in lower_input:
                        s["script"] = name
                        break
        return steps
