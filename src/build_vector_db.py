"""
build_vector_db.py  (v2 -- real semantic embeddings)
Embeds the cleaned MITRE ATT&CK techniques into a local ChromaDB collection
using a sentence-transformer model (true meaning-based search, not just
keyword overlap like the TF-IDF version).
"""
import json
from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions

DATA_DIR = Path(__file__).parent.parent / "data"
TECHNIQUES_FILE = DATA_DIR / "techniques_clean.json"
CHROMA_DIR = DATA_DIR / "chroma_db"

COLLECTION_NAME = "mitre_attack_techniques"
EMBED_MODEL = "all-MiniLM-L6-v2"  # small, fast, free, runs locally after first download


def build():
    with open(TECHNIQUES_FILE, "r", encoding="utf-8") as f:
        techniques = json.load(f)

    print(f"Loaded {len(techniques)} techniques to embed.")
    print("First run will download the embedding model (~90MB) -- this is normal.")

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)

    # Delete the old TF-IDF collection so we don't mix embedding spaces
    try:
        client.delete_collection(COLLECTION_NAME)
        print("Deleted old TF-IDF collection.")
    except Exception:
        pass

    collection = client.create_collection(name=COLLECTION_NAME, embedding_function=embed_fn)

    ids, documents, metadatas = [], [], []
    for t in techniques:
        doc_text = f"{t['name']} ({t['id']}): {t['description']}"
        ids.append(t["id"])
        documents.append(doc_text)
        metadatas.append({
            "name": t["name"],
            "tactics": ", ".join(t["tactics"]),
            "platforms": ", ".join(t["platforms"]),
        })

    batch_size = 200
    for i in range(0, len(ids), batch_size):
        collection.add(
            ids=ids[i:i + batch_size],
            documents=documents[i:i + batch_size],
            metadatas=metadatas[i:i + batch_size],
        )
        print(f"  Embedded {min(i + batch_size, len(ids))}/{len(ids)}")

    print(f"\nVector DB rebuilt at: {CHROMA_DIR}")
    print(f"Collection '{COLLECTION_NAME}' contains {collection.count()} techniques.")
    return collection


if __name__ == "__main__":
    build()
