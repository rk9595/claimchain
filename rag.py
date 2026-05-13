"""Lightweight RAG over the local `data/` markdown files.

For the POC, retrieval is intentionally local and embedding-free. The corpus
is tiny (<20 KB), so a simple lexical scorer is enough to find relevant
policy chunks without any calls to OpenAI, LiteLLM embeddings, or a vector
database. This keeps the app deployable in environments where all model
traffic must go through a chat-only LiteLLM proxy.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from langchain_core.documents import Document


DATA_DIR = Path(__file__).resolve().parent / "data"


_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9'-]*")
_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "how",
    "i", "in", "is", "it", "me", "my", "of", "on", "or", "the", "to",
    "what", "when", "where", "which", "who", "why", "with", "you", "your",
}


def _tokenize(text: str) -> list[str]:
    """Small deterministic tokenizer for keyword retrieval."""
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def _chunk(text: str, size: int = 450, overlap: int = 50) -> list[str]:
    """Deterministic character-window chunker. Preserves markdown sections
    by preferring newline boundaries within the window.
    """
    if "**Q:" in text:
        first_question = text.find("**Q:")
        prefix = text[:first_question].strip()
        questions = re.split(r"\n(?=\*\*Q:)", text[first_question:].strip())
        chunks = []
        for idx, question in enumerate(questions):
            chunk = f"{prefix}\n\n{question}" if idx == 0 and prefix else question
            chunks.append(chunk.strip())
        return [c for c in chunks if c]

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
    """Container for local policy docs plus a lexical search() helper."""

    def __init__(self, embedding_model: str | None = None) -> None:
        # Kept for backwards compatibility with older callers/tests that may
        # still pass an embedding model. It is ignored by design.
        self._embedding_model = embedding_model
        self._docs: list[Document] = []
        self._term_counts: list[Counter[str]] = []

    def build(self) -> "InsuranceRAG":
        self._docs = load_corpus()
        if not self._docs:
            raise RuntimeError(f"No markdown found in {DATA_DIR}")
        self._term_counts = [
            Counter(_tokenize(f"{doc.metadata.get('source', '')} {doc.page_content}"))
            for doc in self._docs
        ]
        return self

    def search(self, query: str, k: int = 4) -> list[Document]:
        if not self._docs:
            self.build()

        query_terms = Counter(_tokenize(query))
        if not query_terms:
            return self._docs[:k]

        query_lower = query.lower().strip()
        scored: list[tuple[float, int, Document]] = []
        for idx, (doc, term_counts) in enumerate(zip(self._docs, self._term_counts)):
            # Term frequency with a small coverage boost. This is not trying
            # to be a search engine; it just needs stable, local retrieval for
            # a very small policy corpus.
            matched_terms = [term for term in query_terms if term_counts.get(term, 0)]
            score = sum(term_counts.get(term, 0) * count
                        for term, count in query_terms.items())
            score += 2.0 * len(matched_terms)

            page_lower = doc.page_content.lower()
            if query_lower and query_lower in page_lower:
                score += 12.0

            source = str(doc.metadata.get("source", "")).replace("_", " ").lower()
            if any(term in source for term in query_terms):
                score += 3.0

            if score > 0:
                scored.append((score, idx, doc))

        if not scored:
            return self._docs[:k]

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [doc for _, _, doc in scored[:k]]

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
