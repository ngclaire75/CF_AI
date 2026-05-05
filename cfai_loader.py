#!/usr/bin/env python3
"""
CF_AI config loader — reads ai_config.json, ai_knowledge_base.json,
and tool_signatures.json at startup to improve AI tool execution accuracy.
"""

import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent


def _load_json(filename: str) -> dict:
    path = BASE_DIR / filename
    if not path.exists():
        logger.warning(f"Config file not found: {filename}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error in {filename}: {e}")
        return {}


class CFAIConfig:
    """Centralized config and knowledge base accessor."""

    def __init__(self):
        self._config    = _load_json("ai_config.json")
        self._kb        = _load_json("ai_knowledge_base.json")
        self._sigs      = _load_json("tool_signatures.json")

    # ── ai_config.json accessors ──────────────────���───────────────────────

    @property
    def injection_protection_enabled(self) -> bool:
        return self._config.get("prompt_injection_protection", {}).get("enabled", True)

    @property
    def max_input_length(self) -> int:
        return self._config.get("prompt_injection_protection", {}).get("max_input_length", 2000)

    @property
    def default_timeout(self) -> int:
        return self._config.get("tool_execution", {}).get("default_timeout_seconds", 120)

    @property
    def max_timeout(self) -> int:
        return self._config.get("tool_execution", {}).get("max_timeout_seconds", 600)

    @property
    def use_cache(self) -> bool:
        return self._config.get("tool_execution", {}).get("use_cache", True)

    @property
    def cache_ttl(self) -> int:
        return self._config.get("tool_execution", {}).get("cache_ttl_seconds", 1800)

    def get_tool_timeout(self, tool_name: str) -> int:
        pmap = self._config.get("tool_priority_map", {})
        return pmap.get(tool_name, {}).get("timeout", self.default_timeout)

    def get_tool_command(self, tool_name: str, variant: str = "default", **kwargs) -> str:
        templates = self._config.get("tool_command_templates", {}).get(tool_name, {})
        template = templates.get(variant, templates.get("default", ""))
        if not template:
            return tool_name
        try:
            return template.format(**kwargs)
        except KeyError:
            return template

    def get_wordlist(self, name: str) -> str:
        return self._config.get("wordlists", {}).get(name, "")

    def get_response_template(self, key: str) -> str:
        return self._config.get("response_templates", {}).get(key, "")

    # ── ai_knowledge_base.json accessors ─────────────────────────────────

    def get_tool_alternatives(self, tool_name: str) -> list:
        return self._kb.get("tool_alternatives", {}).get(tool_name, [])

    def get_attack_chain(self, chain_name: str) -> dict:
        return self._kb.get("attack_chains", {}).get(chain_name, {})

    def get_error_action(self, output: str) -> dict:
        for _key, spec in self._kb.get("common_errors", {}).items():
            for pattern in spec.get("patterns", []):
                if pattern.lower() in output.lower():
                    return spec
        return {}

    def get_ctf_hints(self, category: str, vuln_type: str = None) -> dict:
        ctf = self._kb.get("ctf_hints", {}).get(category, {})
        if vuln_type:
            return ctf.get(vuln_type, ctf)
        return ctf

    def get_wp_report_sections(self) -> list:
        return self._kb.get("wordpress_report_criteria", {}).get("report_sections", [])

    def get_wp_firm_requirements(self) -> list:
        return self._kb.get("wordpress_report_criteria", {}).get("certified_firm_requirements", [])

    def get_wp_vulnerabilities(self) -> list:
        return self._kb.get("wordpress_report_criteria", {}).get("common_wordpress_vulnerabilities", [])

    # ── tool_signatures.json accessors ───────────────────────────────────

    def detect_technology(self, response_text: str) -> list:
        detected = []
        for tech, spec in self._sigs.get("technology_signatures", {}).items():
            for indicator in spec.get("indicators", []):
                if indicator.lower() in response_text.lower():
                    detected.append({
                        "technology": tech,
                        "recommended_tools": spec.get("recommended_tools", [])
                    })
                    break
        return detected

    def get_output_parser(self, tool_name: str) -> dict:
        return self._sigs.get("output_parsers", {}).get(tool_name, {})

    def get_owasp_mapping(self, owasp_id: str) -> dict:
        return self._sigs.get("owasp_mapping", {}).get(owasp_id, {})

    def get_severity_weight(self, severity: str) -> int:
        return self._sigs.get("severity_weights", {}).get(severity.lower(), 0)


cfai_config = CFAIConfig()
