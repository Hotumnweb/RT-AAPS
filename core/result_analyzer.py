# -*- coding: utf-8 -*-
"""
RT-AAPS 结果分析引擎
1. analyze: 单步结果提炼（严格基于原始输出，禁止编造）
2. generate_report: 会话汇总报告
"""
import json
import ollama
from prompts.system_prompts import RESULT_ANALYZER_PROMPT, REPORT_GENERATOR_PROMPT


class ResultAnalyzer:
    def __init__(self, config):
        self.config = config
        self.model = config["ollama"]["model"]

    def analyze(self, task, raw_output):
        """单步结果分析"""
        prompt = RESULT_ANALYZER_PROMPT.format(
            task=task, raw_output=raw_output[:3000]
        )
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0},
            )
            return resp["message"]["content"].strip()
        except Exception as e:
            return f"分析失败：{str(e)}"

    def generate_report(self, records):
        """生成会话汇总报告"""
        prompt = REPORT_GENERATOR_PROMPT.format(
            task="本次渗透测试会话",
            records=json.dumps(records, ensure_ascii=False, indent=2),
        )
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0},
            )
            return resp["message"]["content"].strip()
        except Exception:
            return "报告生成失败"
