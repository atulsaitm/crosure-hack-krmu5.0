"""ChromaDB vector store for semantic search over exploit knowledge base."""

import chromadb
from chromadb.config import Settings as ChromaSettings
from typing import List, Dict, Any, Optional

from config import settings

_client = None
_collection = None


def get_chroma_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(
            path=settings.CHROMADB_PATH,
            settings=ChromaSettings(anonymized_telemetry=False),
        )
    return _client


def get_collection():
    global _collection
    if _collection is None:
        client = get_chroma_client()
        _collection = client.get_or_create_collection(
            name="exploit_vectors",
            metadata={"hnsw:space": "cosine"},
        )
    return _collection


def embed_exploit(exploit_id: int, text: str, metadata: Dict[str, Any]) -> str:
    """Embed an exploit document into ChromaDB."""
    collection = get_collection()
    doc_id = f"exploit_{exploit_id}"

    clean_metadata = {}
    for k, v in metadata.items():
        if v is not None and isinstance(v, (str, int, float, bool)):
            clean_metadata[k] = v

    collection.upsert(
        ids=[doc_id],
        documents=[text],
        metadatas=[clean_metadata],
    )
    return doc_id


def embed_chain(chain_id: int, text: str, metadata: Dict[str, Any]) -> str:
    """Embed an attack chain into ChromaDB."""
    collection = get_collection()
    doc_id = f"chain_{chain_id}"

    clean_metadata = {"is_chain": True}
    for k, v in metadata.items():
        if v is not None and isinstance(v, (str, int, float, bool)):
            clean_metadata[k] = v

    collection.upsert(
        ids=[doc_id],
        documents=[text],
        metadatas=[clean_metadata],
    )
    return doc_id


def search_exploits(
    query: str,
    n_results: int = 10,
    attack_type: Optional[str] = None,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Semantic search for relevant exploits."""
    collection = get_collection()

    where_filter = None
    conditions = []
    if attack_type:
        conditions.append({"attack_type": attack_type})
    if severity:
        conditions.append({"severity": severity})

    if len(conditions) == 1:
        where_filter = conditions[0]
    elif len(conditions) > 1:
        where_filter = {"$and": conditions}

    try:
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
            where=where_filter,
        )
    except Exception:
        # Fallback without filter if metadata doesn't match
        results = collection.query(
            query_texts=[query],
            n_results=n_results,
        )

    matches = []
    if results and results["ids"] and results["ids"][0]:
        for i, doc_id in enumerate(results["ids"][0]):
            matches.append({
                "id": doc_id,
                "document": results["documents"][0][i] if results["documents"] else "",
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else 1.0,
            })
    return matches


def search_chains_for_findings(findings_description: str, n_results: int = 5) -> List[Dict[str, Any]]:
    """Search for chain templates matching a set of discovered findings."""
    collection = get_collection()

    try:
        results = collection.query(
            query_texts=[findings_description],
            n_results=n_results,
            where={"is_chain": True},
        )
    except Exception:
        results = collection.query(
            query_texts=[findings_description],
            n_results=n_results,
        )

    matches = []
    if results and results["ids"] and results["ids"][0]:
        for i, doc_id in enumerate(results["ids"][0]):
            matches.append({
                "id": doc_id,
                "document": results["documents"][0][i] if results["documents"] else "",
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else 1.0,
            })
    return matches
