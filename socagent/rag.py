"""A dependency-free runbook retriever.

Splits Markdown runbooks on headings and ranks sections with TF-IDF.
Small, inspectable and good enough for a few hundred runbook sections.
Swap in a vector store or hybrid search when you outgrow it; the tool
contract (query in, cited chunks out) does not change.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field

from .tools.registry import Tool

TOKEN = re.compile(r"[a-z0-9]+(?:[.\-][a-z0-9]+)*")
STOP = set("a an and are as at be by for from has have if in into is it of on or that the this to was "
           "were will with you your".split())


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if t not in STOP]


@dataclass
class Chunk:
    id: str        # "phishing.md#containment"
    heading: str
    text: str
    version: str = ""      # content hash of the source file: changes when the runbook changes
    tenant: str = "global"  # "global" or a customer id (MSSP)


def chunk_markdown(name: str, text: str, tenant: str = "global") -> list[Chunk]:
    import hashlib

    version = hashlib.sha256(text.encode()).hexdigest()[:12]
    chunks: list[Chunk] = []
    heading, buf = "intro", []
    for line in text.splitlines():
        m = re.match(r"^#{1,3}\s+(.*)", line)
        if m:
            if "".join(buf).strip():
                chunks.append(Chunk(f"{name}#{_slug(heading)}", heading, "\n".join(buf).strip(), version, tenant))
            heading, buf = m.group(1).strip(), []
        else:
            buf.append(line)
    if "".join(buf).strip():
        chunks.append(Chunk(f"{name}#{_slug(heading)}", heading, "\n".join(buf).strip(), version, tenant))
    return chunks


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


class RunbookIndex:
    def __init__(self, chunks: list[Chunk]):
        self.chunks = chunks
        self._tf = [Counter(tokenize(c.heading + " " + c.text)) for c in chunks]
        df = Counter(term for tf in self._tf for term in tf)
        n = len(chunks)
        self._idf = {t: math.log((n + 1) / (d + 1)) + 1 for t, d in df.items()}

    @classmethod
    def from_dir(cls, path: str | Path) -> "RunbookIndex":
        """Global runbooks in `path/*.md`; customer runbooks in `path/tenants/<tenant>/*.md`."""
        path = Path(path)
        chunks: list[Chunk] = []
        for f in sorted(path.glob("*.md")):
            chunks.extend(chunk_markdown(f.name, f.read_text()))
        for tdir in sorted((path / "tenants").glob("*")) if (path / "tenants").exists() else []:
            for f in sorted(tdir.glob("*.md")):
                chunks.extend(chunk_markdown(f"{tdir.name}/{f.name}", f.read_text(), tenant=tdir.name))
        return cls(chunks)

    def search(self, query: str, k: int = 3, tenant: str | None = None,
               min_score: float = 0.12) -> list[dict[str, str | float]]:
        """Top-k sections at or above `min_score`, from global runbooks and `tenant`'s only.

        The best match is not necessarily a relevant match: below the threshold we
        return nothing and the caller reports that no runbook applies.
        """
        q = Counter(tokenize(query))
        scored = []
        for chunk, tf in zip(self.chunks, self._tf):
            if chunk.tenant != "global" and chunk.tenant != tenant:
                continue                      # never retrieve another customer's runbooks
            total = sum(tf.values()) or 1
            score = sum((tf[t] / total) * self._idf.get(t, 0) * qn for t, qn in q.items())
            if score >= min_score:
                scored.append((score, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"id": c.id, "heading": c.heading, "text": c.text, "score": round(s, 4),
                 "version": c.version, "tenant": c.tenant} for s, c in scored[:k]]


class RunbookArgs(BaseModel):
    query: str = Field(min_length=3, description="What you need guidance on, e.g. 'credential phishing containment'")


def make_runbook_tool(index: RunbookIndex, tenant: str | None = None) -> Tool:
    """The tenant is bound here, in code. The model cannot ask for another tenant's runbooks."""

    def search_runbooks(query: str) -> dict:
        results = index.search(query, tenant=tenant)
        return {"results": results, "no_applicable_runbook": not results}

    return Tool("search_runbooks",
                "Search the SOC's approved runbooks. Cite a returned id in runbook_refs only if you "
                "follow it. If no_applicable_runbook is true, say so and use needs_human when unsure.",
                RunbookArgs, search_runbooks)
