# -*- coding: utf-8 -*-
"""
RT-AAPS 漏洞匹配引擎
双轨匹配：
1. 本地规则：扫描结果中的开放端口 → 候选漏洞（不依赖 AI，保证稳定）
2. AI 精筛：从候选漏洞中选出最可能的（AI 只做选择，不做编造）
"""
import json
import re
import ollama
from prompts.system_prompts import VULN_MATCH_PROMPT

# 端口 → 候选漏洞规则（本地兜底，覆盖靶场常见场景）
PORT_VULN_RULES = {
    "445": ["ms17-010", "ms08-067", "smb_brute"],
    "139": ["ms17-010", "ms08-067"],
    "22": ["ssh_brute", "hydra_ssh"],
    "80": ["nikto_web", "sqlmap_auto", "file_upload", "thinkphp_rce"],
    "443": ["nikto_web", "sqlmap_auto"],
    "8080": ["nikto_web", "sqlmap_auto", "thinkphp_rce"],
    "3389": ["smb_brute"],
}


class VulnMatcher:
    def __init__(self, config):
        self.config = config
        self.model = config["ollama"]["model"]
        with open(config["paths"]["exploit_db"], "r", encoding="utf-8") as f:
            self.db = json.load(f)

    def match(self, scan_result):
        """匹配漏洞，返回漏洞 key 列表"""
        candidates = self._rule_candidates(scan_result)
        if not candidates:
            return []

        # AI 从候选中精筛
        vuln_list = ",".join(candidates)
        prompt = VULN_MATCH_PROMPT.format(
            vuln_list=vuln_list, scan_result=scan_result[:2000]
        )
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0},
            )
            text = resp["message"]["content"].strip().lower()
            if not text or "none" in text:
                return candidates[:2]  # AI 判断不出时，兜底返回规则候选
            matched = [v.strip() for v in text.split(",") if v.strip() in self.db]
            return matched if matched else candidates[:2]
        except Exception:
            return candidates[:2]

    def _rule_candidates(self, scan_result):
        """从扫描结果提取开放端口，按规则映射候选漏洞"""
        ports = set()
        for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)", scan_result):
            ports.add(m.group(1))
        if not ports:
            # 兼容 nmap 其他输出格式
            for m in re.finditer(r"(\d+)\s+(\S+)\s+open", scan_result):
                ports.add(m.group(1))
        candidates = []
        for p in sorted(ports, key=int):
            for v in PORT_VULN_RULES.get(p, []):
                if v in self.db and v not in candidates:
                    candidates.append(v)
        return candidates
