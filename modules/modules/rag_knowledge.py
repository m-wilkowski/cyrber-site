"""
RAG module - PayloadsAllTheThings knowledge base
Semantic search over security payloads and techniques
"""
import os
import json
import pickle
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

KNOWLEDGE_BASE_DIR = os.getenv("KNOWLEDGE_BASE_DIR", "/app/knowledge_base/PayloadsAllTheThings")
INDEX_PATH = os.getenv("RAG_INDEX_PATH", "/app/knowledge_base/rag_index.pkl")
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"  # ONNX, ~50MB, szybki


class RAGKnowledge:
    def __init__(self):
        self._index = None
        self._chunks = []
        self._model = None
        self._ready = False

    def _load_model(self):
        if self._model is None:
            from fastembed import TextEmbedding
            self._model = TextEmbedding(EMBEDDING_MODEL)
        return self._model

    def build_index(self) -> dict:
        """Buduje indeks FAISS z plików MD w knowledge_base"""
        import faiss
        import numpy as np

        kb_path = Path(KNOWLEDGE_BASE_DIR)
        if not kb_path.exists():
            return {"error": f"Knowledge base not found: {KNOWLEDGE_BASE_DIR}"}

        # Załaduj wszystkie pliki MD
        chunks = []
        md_files = list(kb_path.rglob("*.md"))
        logger.info(f"[rag] Found {len(md_files)} MD files")

        for md_file in md_files:
            try:
                text = md_file.read_text(encoding='utf-8', errors='ignore')
                # Podziel na chunki po ~500 znaków z overlap
                category = md_file.parent.name
                paragraphs = [p.strip() for p in text.split('\n\n') if len(p.strip()) > 50]
                for para in paragraphs:
                    chunks.append({
                        "text": para[:600],
                        "source": str(md_file.relative_to(kb_path)),
                        "category": category
                    })
            except Exception as e:
                logger.warning(f"[rag] Error reading {md_file}: {e}")

        if not chunks:
            return {"error": "No chunks extracted"}

        logger.info(f"[rag] Encoding {len(chunks)} chunks...")
        model = self._load_model()
        texts = [c["text"] for c in chunks]
        embeddings = list(model.embed(texts))
        embeddings = np.array(embeddings, dtype='float32')

        # Normalizuj dla cosine similarity
        faiss.normalize_L2(embeddings)

        # Zbuduj indeks
        dim = embeddings.shape[1]
        index = faiss.IndexFlatIP(dim)  # Inner Product = cosine po normalizacji
        index.add(embeddings)

        # Zapisz na dysk
        index_path = Path(INDEX_PATH)
        index_path.parent.mkdir(parents=True, exist_ok=True)
        with open(INDEX_PATH, 'wb') as f:
            pickle.dump({"index": faiss.serialize_index(index), "chunks": chunks}, f)

        self._index = index
        self._chunks = chunks
        self._ready = True

        return {
            "status": "ok",
            "chunks": len(chunks),
            "files": len(md_files),
            "index_path": INDEX_PATH
        }

    def load_index(self) -> bool:
        """Ładuje zapisany indeks z dysku"""
        try:
            import faiss
            if not Path(INDEX_PATH).exists():
                return False
            with open(INDEX_PATH, 'rb') as f:
                data = pickle.load(f)
            self._index = faiss.deserialize_index(data["index"])
            self._chunks = data["chunks"]
            self._ready = True
            logger.info(f"[rag] Index loaded: {len(self._chunks)} chunks")
            return True
        except Exception as e:
            logger.error(f"[rag] Failed to load index: {e}")
            return False

    def search(self, query: str, top_k: int = 5, category_filter: str = None) -> list:
        """Semantic search - zwraca top_k najbardziej relevantnych chunków"""
        if not self._ready:
            if not self.load_index():
                return []
        try:
            import faiss
            import numpy as np
            model = self._load_model()
            q_emb = list(model.embed([query]))[0]
            q_emb = np.array([q_emb], dtype='float32')
            faiss.normalize_L2(q_emb)

            scores, indices = self._index.search(q_emb, top_k * 3)

            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < 0:
                    continue
                chunk = self._chunks[idx]
                if category_filter and category_filter.lower() not in chunk["category"].lower():
                    continue
                results.append({
                    "text": chunk["text"],
                    "source": chunk["source"],
                    "category": chunk["category"],
                    "score": float(score)
                })
                if len(results) >= top_k:
                    break
            return results
        except Exception as e:
            logger.error(f"[rag] Search error: {e}")
            return []

    def search_for_vulnerabilities(self, findings: list, max_results: int = 3) -> dict:
        """Dla każdego finding szuka relevantnych technik ataku"""
        if not findings:
            return {}
        enriched = {}
        for finding in findings[:10]:  # max 10 findings
            name = finding.get("name", "") or finding.get("title", "")
            if not name:
                continue
            results = self.search(name, top_k=max_results)
            if results:
                enriched[name] = results
        return enriched


# Singleton
_rag = None


def get_rag() -> RAGKnowledge:
    global _rag
    if _rag is None:
        _rag = RAGKnowledge()
    return _rag
