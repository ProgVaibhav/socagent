"""Safe rendering of model-influenced text (Chapters 10, 11, 13).

Anything the model wrote (summary, claims, reasons) may have been steered by
the attacker. Before it goes into Markdown that a SOAR war room, ticket or chat
client will render, neutralise everything that could:
  * load a remote resource (images, links): an exfiltration channel,
  * create a clickable link to attacker infrastructure,
  * change the structure of the page (headings, tables, HTML).
Do not rely on the model to sanitise its own output.
"""
from __future__ import annotations

import re

_URL = re.compile(r"\b(h)(ttps?)(://)", re.IGNORECASE)
_DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+)([a-z]{2,24})\b", re.IGNORECASE)
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|<>~])")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f‪-‮⁦-⁩]")


def defang(text: str) -> str:
    """http -> hxxp and example.com -> example[.]com, the SOC convention for inert IOCs."""
    text = _URL.sub(lambda m: "hxx" + m.group(2)[2:] + "[://]", text)
    return _DOMAIN.sub(lambda m: m.group(1)[:-1].replace(".", "[.]") + "[.]" + m.group(2), text)


def safe_md(text: str, limit: int = 2000, defang_iocs: bool = True) -> str:
    """Plain, inert text for Markdown contexts: defanged, escaped, single-line, bounded.
    Use defang_iocs=False only for values our code generated (ids, runbook refs)."""
    text = _CTRL.sub("", str(text))[:limit]          # also strips bidi overrides
    text = text.replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", defang(text) if defang_iocs else text)
