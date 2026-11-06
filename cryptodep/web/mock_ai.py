"""Opt-in local Chat Completions mock. No model inference or external requests."""
from __future__ import annotations

import json
import time
import uuid
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


MODEL = "mock-cryptodep"
app = FastAPI(title="CryptoDep Mock AI", description="Respons tetap untuk pengujian, bukan model AI nyata.")


class Message(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(max_length=1_000_000)


class Completion(BaseModel):
    model: str
    messages: list[Message] = Field(min_length=1, max_length=100)
    stream: bool = False


def mock_reply(messages: list[dict]) -> str:
    text = " ".join(message["content"] for message in messages)
    if "Return exactly this JSON array" in text:
        return '[{"ok":true}]'
    if "Generate a PQC migration report" in text:
        return ("# Laporan mock lokal\n\n"
                "Ini respons tetap untuk pengujian alur CryptoDep, bukan hasil penalaran AI. "
                "Tinjau temuan statis, bukti kode, dan saran migrasi pada graph. "
                "Mock tidak menambahkan temuan semantik atau hubungan dependensi baru.")
    if "Graph CDG:\n" in text and "\n\nPertanyaan:" in text:
        graph = json.loads(text.split("Graph CDG:\n", 1)[1].split("\n\nPertanyaan:", 1)[0])
        red = [node["id"] for node in graph["nodes"] if node.get("risk") == "red"]
        return json.dumps({"answer": f"Respons mock: {len(red)} node ditandai perlu migrasi PQC. Ini bukan hasil penalaran AI.",
                           "node_ids": red, "path": []})
    return "[]"


@app.get("/health")
def health():
    return {"status": "ok", "mock": True}


@app.get("/v1/models")
def models():
    return {"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": "local-mock"}]}


@app.post("/v1/chat/completions")
def complete(request: Completion):
    if request.model != MODEL:
        raise HTTPException(404, f"Model mock yang tersedia: {MODEL}")
    if request.stream:
        raise HTTPException(400, "Mock hanya mendukung respons non-streaming.")
    return {"id": "chatcmpl-mock-" + uuid.uuid4().hex,
            "object": "chat.completion", "created": int(time.time()), "model": MODEL,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": mock_reply([m.model_dump() for m in request.messages])},
                         "finish_reason": "stop"}]}
