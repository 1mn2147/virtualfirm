from __future__ import annotations

from pathlib import Path
import re
import sqlite3

from .models import FirmwareContext, RagHit


TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def search_references(context: FirmwareContext, device: str, references_dir: Path) -> list[RagHit]:
    if not references_dir.exists():
        return []

    query_terms = _query_terms(context, device)
    hits = _search_sqlite_index(
        _load_reference_documents(references_dir),
        query_terms,
        [address.lower() for address in context.mmio_addresses],
    )
    return sorted(hits, key=lambda hit: hit.score, reverse=True)[:8]


def _load_reference_documents(references_dir: Path) -> list[tuple[Path, str]]:
    documents = []
    for path in sorted(references_dir.glob("**/*")):
        if not path.is_file() or path.suffix.lower() not in {".md", ".txt", ".csv", ".json"}:
            continue
        documents.append((path, path.read_text(encoding="utf-8", errors="ignore")))
    return documents


def _search_sqlite_index(
    documents: list[tuple[Path, str]],
    query_terms: set[str],
    addresses: list[str],
) -> list[RagHit]:
    if not documents or not query_terms:
        return []
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE references_doc(path TEXT PRIMARY KEY, text TEXT, lower_text TEXT)")
        connection.executemany(
            "INSERT INTO references_doc(path, text, lower_text) VALUES (?, ?, ?)",
            [(str(path), text, text.lower()) for path, text in documents],
        )
        hits = []
        for path_text, text, lower_text in connection.execute(
            "SELECT path, text, lower_text FROM references_doc"
        ):
            score = sum(lower_text.count(term) for term in query_terms)
            score += sum(lower_text.count(address) * 5 for address in addresses)
            if score:
                path = Path(path_text)
                excerpt, line_number = _excerpt_with_location(text, query_terms)
                hits.append(
                    RagHit(
                        source=path_text,
                        score=score,
                        excerpt=excerpt,
                        kind="sqlite-text",
                        source_location=f"{path}:{line_number}" if line_number else path_text,
                    )
                )
        return hits
    finally:
        connection.close()


def _query_terms(context: FirmwareContext, device: str) -> set[str]:
    terms = {device.lower(), context.architecture_hint.lower()}
    for address in context.mmio_addresses:
        terms.add(address.lower())
        terms.add(address[:6].lower())
    for value in context.strings[:30]:
        terms.update(token.lower() for token in TOKEN_RE.findall(value) if len(token) >= 3)
    return {term for term in terms if term and term != "unknown"}


def _excerpt_with_location(text: str, terms: set[str]) -> tuple[str, int | None]:
    lines = [(index, line.strip()) for index, line in enumerate(text.splitlines(), start=1) if line.strip()]
    for line_number, line in lines:
        lowered = line.lower()
        if any(term in lowered for term in terms):
            return line[:500], line_number
    return " ".join(line for _, line in lines[:2])[:500], lines[0][0] if lines else None
