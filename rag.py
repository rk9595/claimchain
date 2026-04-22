"""Lightweight RAG over the local `data/` markdown files.

Uses LangChain's `InMemoryVectorStore` and OpenAI embeddings so we avoid
FAISS/native-build headaches on Windows. Everything stays in-process and
is rebuilt on startup (the corpus is small, <20 KB).
"""

from __future__ import annotations

import os
from pathlib import Path

from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore
from langchain_openai import OpenAIEmbeddings


DATA_DIR = Path(__file__).resolve().parent / "data"


def _chunk(text: str, size: int = 900, overlap: int = 150) -> list[str]:
    """Deterministic character-window chunker. Preserves markdown sections
    by preferring newline boundaries within the window.
    """
    chunks: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        end = min(i + size, n)
        if end < n:
            # Try to break at the nearest newline within the last 200 chars.
            nl = text.rfind("\n", max(i + size - 200, i), end)
            if nl > i:
                end = nl
        chunks.append(text[i:end].strip())
        if end >= n:
            break
        i = max(end - overlap, i + 1)
    return [c for c in chunks if c]


def load_corpus() -> list[Document]:
    docs: list[Document] = []
    for md in sorted(DATA_DIR.glob("*.md")):
        raw = md.read_text(encoding="utf-8")
        for idx, chunk in enumerate(_chunk(raw)):
            docs.append(Document(
                page_content=chunk,
                metadata={"source": md.name, "chunk": idx},
            ))
    return docs


class InsuranceRAG:
    """Container for the vector store plus a simple search() helper."""

    def __init__(self, embedding_model: str | None = None) -> None:
        model = embedding_model or os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
        self._embeddings = OpenAIEmbeddings(model=model)
        self._store: InMemoryVectorStore | None = None
        self._docs: list[Document] = []

    def build(self) -> "InsuranceRAG":
        self._docs = load_corpus()
        if not self._docs:
            raise RuntimeError(f"No markdown found in {DATA_DIR}")
        self._store = InMemoryVectorStore.from_documents(self._docs, self._embeddings)
        return self

    def search(self, query: str, k: int = 4) -> list[Document]:
        if self._store is None:
            self.build()
        assert self._store is not None
        return self._store.similarity_search(query, k=k)

    def format_context(self, query: str, k: int = 4) -> str:
        """Return RAG hits as a newline-joined context block the agent can
        embed in a system/tool message.
        """
        hits = self.search(query, k=k)
        if not hits:
            return "(no matching policy documents)"
        parts = []
        for h in hits:
            src = h.metadata.get("source", "?")
            parts.append(f"[{src}]\n{h.page_content}")
        return "\n\n---\n\n".join(parts)

    @property
    def num_chunks(self) -> int:
        return len(self._docs)


_rag: InsuranceRAG | None = None


def get_rag() -> InsuranceRAG:
    """Lazy singleton used by tools and agents."""
    global _rag
    if _rag is None:
        _rag = InsuranceRAG().build()
    return _rag
