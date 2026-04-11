"""RAG — knowledge layer 3.

Vector store for dynamic lookup of CVEs, specific techniques, and
edge-case knowledge that's too large to embed in prompts or skill docs.

Uses a local FAISS or Chroma vector store with LangChain's retriever
interface. Documents are ingested from OWASP guides, HackTricks,
CVE databases, and technique references.

This layer is the most expensive (embedding cost + retrieval latency)
but provides the deepest, most specific knowledge. It's independently
toggleable for ablation studies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langchain_core.documents import Document


class KnowledgeStore:
    """Vector store wrapper for pentesting knowledge retrieval."""

    def __init__(self, persist_dir: str = ".knowledge_store"):
        self._persist_dir = Path(persist_dir)
        self._store = None
        self._retriever = None

    def _init_store(self) -> None:
        """Lazy-initialize the vector store."""
        if self._store is not None:
            return

        try:
            from langchain_community.vectorstores import FAISS
            from langchain_openai import OpenAIEmbeddings

            if self._persist_dir.exists():
                self._store = FAISS.load_local(
                    str(self._persist_dir),
                    OpenAIEmbeddings(),
                    allow_dangerous_deserialization=True,
                )
            else:
                # Create empty store
                self._store = FAISS.from_texts(
                    ["SwarmAttacker knowledge base initialized."],
                    OpenAIEmbeddings(),
                )
                self._store.save_local(str(self._persist_dir))

            self._retriever = self._store.as_retriever(
                search_kwargs={"k": 5}
            )
        except ImportError:
            # FAISS or embeddings not available — RAG disabled
            self._store = None
            self._retriever = None

    def ingest_directory(self, docs_dir: str, glob_pattern: str = "**/*.md") -> int:
        """Ingest markdown files from a directory into the store.

        Returns the number of documents ingested.
        """
        self._init_store()
        if self._store is None:
            return 0

        from langchain_text_splitters import RecursiveCharacterTextSplitter

        path = Path(docs_dir)
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
        )

        docs = []
        for file_path in path.glob(glob_pattern):
            content = file_path.read_text()
            chunks = splitter.split_text(content)
            for chunk in chunks:
                docs.append(Document(
                    page_content=chunk,
                    metadata={"source": str(file_path), "filename": file_path.name},
                ))

        if docs:
            self._store.add_documents(docs)
            self._store.save_local(str(self._persist_dir))

        return len(docs)

    def query(self, question: str, k: int = 5) -> list[Document]:
        """Retrieve relevant documents for a question."""
        self._init_store()
        if self._retriever is None:
            return []
        return self._retriever.invoke(question)

    def query_text(self, question: str, k: int = 5) -> str:
        """Retrieve and format as a single text block for injection into prompts."""
        docs = self.query(question, k)
        if not docs:
            return ""
        parts = []
        for i, doc in enumerate(docs, 1):
            source = doc.metadata.get("filename", "unknown")
            parts.append(f"[{i}] ({source})\n{doc.page_content}")
        return "\n\n".join(parts)

    @property
    def available(self) -> bool:
        """Check if RAG is available (dependencies installed + store exists)."""
        self._init_store()
        return self._store is not None
