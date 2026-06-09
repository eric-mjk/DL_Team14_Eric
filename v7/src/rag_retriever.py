"""Offline lexical retriever for parser-repair RAG.

The retriever reads bundled spec text under ``v7/artifacts/documents`` and
scores chunks with a small BM25-style formula. It has no network or heavyweight
runtime dependencies, so it is safe to import during grading.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from .rag_schema import RetrievedChunk


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOCUMENT_ROOT = ROOT / "artifacts" / "documents"

_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "be",
        "by",
        "for",
        "from",
        "if",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "the",
        "to",
        "with",
    }
)


@dataclass(frozen=True)
class _Document:
    section: str
    path: str
    title: str
    text: str
    tokens: tuple[str, ...]
    term_counts: dict[str, int]


def _split_camel(text: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = text.replace("_", " ")
    return text


def _tokens(text: str) -> list[str]:
    terms = []
    for raw in _TOKEN_RE.findall(_split_camel(text)):
        term = raw.lower()
        if len(term) <= 1 or term in _STOPWORDS:
            continue
        terms.append(term)
    return terms


def _section_from_path(path: Path) -> str:
    return path.stem


def _load_title_maps(document_root: Path) -> dict[str, str]:
    titles: dict[str, str] = {}
    for title_file in document_root.glob("*/section_title.json"):
        try:
            data = json.loads(title_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        prefix = title_file.parent.name
        for section, title in data.items():
            if isinstance(section, str) and isinstance(title, str):
                titles[f"{prefix}/{section}"] = title
    return titles


def _title_from_text(section: str, text: str) -> str:
    first = text.splitlines()[0].strip() if text.splitlines() else ""
    if first.startswith(section):
        return first[len(section) :].strip(" -:\t") or first
    return first[:120] if first else section


def _read_documents(document_root: Path) -> list[_Document]:
    titles = _load_title_maps(document_root)
    docs: list[_Document] = []
    if not document_root.exists():
        return docs

    for path in sorted(document_root.glob("*/*.txt")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not text:
            continue
        rel_path = path.relative_to(ROOT).as_posix()
        section = _section_from_path(path)
        key = f"{path.parent.name}/{section}"
        title = titles.get(key) or _title_from_text(section, text)
        token_list = _tokens(f"{section} {title} {text}")
        counts: dict[str, int] = {}
        for term in token_list:
            counts[term] = counts.get(term, 0) + 1
        docs.append(
            _Document(
                section=section,
                path=rel_path,
                title=title,
                text=text,
                tokens=tuple(token_list),
                term_counts=counts,
            )
        )
    return docs


def _highlight_window(text: str, query_terms: Iterable[str], max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    lower = text.lower()
    positions = [lower.find(term.lower()) for term in query_terms if term and lower.find(term.lower()) >= 0]
    pos = min(positions) if positions else 0
    start = max(0, pos - max_chars // 3)
    end = min(len(text), start + max_chars)
    start = max(0, end - max_chars)
    snippet = text[start:end].strip()
    if start:
        snippet = "... " + snippet
    if end < len(text):
        snippet += " ..."
    return snippet


class SpecTextRetriever:
    """Dependency-free lexical retriever over bundled spec text chunks."""

    def __init__(self, document_root: str | Path | None = None, max_chunk_chars: int | None = None):
        self.document_root = Path(document_root) if document_root is not None else DEFAULT_DOCUMENT_ROOT
        env_limit = os.environ.get("RAG_MAX_CHUNK_CHARS")
        self.max_chunk_chars = max_chunk_chars if max_chunk_chars is not None else int(env_limit or "1800")
        self._docs = _cached_documents(str(self.document_root.resolve()))
        self._avg_len = sum(len(d.tokens) for d in self._docs) / max(len(self._docs), 1)
        self._df = self._document_frequencies(self._docs)

    @staticmethod
    def _document_frequencies(docs: list[_Document]) -> dict[str, int]:
        df: dict[str, int] = {}
        for doc in docs:
            for term in set(doc.tokens):
                df[term] = df.get(term, 0) + 1
        return df

    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievedChunk]:
        query_terms = _tokens(query)
        if not query_terms or not self._docs or top_k <= 0:
            return []
        query_counts: dict[str, int] = {}
        for term in query_terms:
            query_counts[term] = query_counts.get(term, 0) + 1

        scored: list[tuple[float, _Document]] = []
        total_docs = len(self._docs)
        k1 = 1.4
        b = 0.72
        for doc in self._docs:
            doc_len = max(len(doc.tokens), 1)
            score = 0.0
            for term, qtf in query_counts.items():
                tf = doc.term_counts.get(term, 0)
                if tf <= 0:
                    continue
                df = self._df.get(term, 0)
                idf = math.log(1.0 + (total_docs - df + 0.5) / (df + 0.5))
                denom = tf + k1 * (1.0 - b + b * doc_len / max(self._avg_len, 1.0))
                score += idf * ((tf * (k1 + 1.0)) / denom) * min(qtf, 3)

            title_text = f"{doc.section} {doc.title}".lower()
            title_hits = sum(1 for term in query_counts if term in title_text)
            if title_hits:
                score += 0.35 * title_hits
            if score > 0.0:
                scored.append((score, doc))

        scored.sort(key=lambda item: item[0], reverse=True)
        results: list[RetrievedChunk] = []
        for score, doc in scored[:top_k]:
            snippet = _highlight_window(doc.text, query_terms, self.max_chunk_chars)
            results.append(
                RetrievedChunk(
                    section=doc.section,
                    path=doc.path,
                    title=doc.title,
                    text=snippet,
                    score=round(float(score), 4),
                )
            )
        return results


@lru_cache(maxsize=4)
def _cached_documents(document_root: str) -> list[_Document]:
    return _read_documents(Path(document_root))
