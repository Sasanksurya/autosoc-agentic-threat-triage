"""
query_test.py  (v2 -- works with real sentence-transformer embeddings)
"""
from pathlib import Path
import chromadb
from chromadb.utils import embedding_functions

DATA_DIR = Path(__file__).parent.parent / "data"
CHROMA_DIR = DATA_DIR / "chroma_db"
COLLECTION_NAME = "mitre_attack_techniques"
EMBED_MODEL = "all-MiniLM-L6-v2"


def load_collection():
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
    return client.get_collection(COLLECTION_NAME, embedding_function=embed_fn)


def retrieve_techniques(alert_text: str, n_results: int = 3):
    """Given a raw alert/log description, retrieve the top-N matching MITRE techniques."""
    collection = load_collection()
    results = collection.query(query_texts=[alert_text], n_results=n_results)

    matches = []
    for i in range(len(results["ids"][0])):
        matches.append({
            "id": results["ids"][0][i],
            "name": results["metadatas"][0][i]["name"],
            "tactics": results["metadatas"][0][i]["tactics"],
            "distance": round(results["distances"][0][i], 4),
            "snippet": results["documents"][0][i][:200] + "...",
        })
    return matches


if __name__ == "__main__":
    test_alerts = [
        "PowerShell process spawned from a Word document with an encoded command",
        "Multiple failed login attempts followed by a successful login from a new country",
        "Large volume of data uploaded to an unknown external FTP server at 3am",
        "A scheduled task was created that runs a script every time the user logs in",
    ]

    for alert in test_alerts:
        print("=" * 90)
        print(f"ALERT: {alert}")
        print("-" * 90)
        matches = retrieve_techniques(alert, n_results=3)
        for m in matches:
            print(f"  [{m['id']}] {m['name']}  (tactics: {m['tactics']})  dist={m['distance']}")
        print()
