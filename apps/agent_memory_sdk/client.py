"""Cliente in-process e adaptador de Function Calling para o Epistemic Memory Core.

Integra `Store`, `Knowledge`, `Retrieval`, `atribuicao`, `revisoes`,
`apoio_decisao` e `evidencias` diretamente em aplicações Python ou malhas
multiagente (LangGraph, OpenAI Agents, Google Gemini SDK, loops customizados),
sem exigir transporte MCP stdio e preservando integralmente os contratos
epistemológicos dos 17 capítulos de `00_Manual/`:
- Separação estrita entre fontes primárias (`30_Fontes`) e conhecimento derivado;
- Pinagem obrigatória de revisão (`RevRef` = `{"record_id": ..., "revision": ...}`);
- Ausência de diagnóstico clínico implícito;
- Firewall determinístico de atribuição de sujeito/citação (`atribuicao.py`);
- Comprovantes determinísticos `lab-assurance-2` (`field`, `sum`, `chain`);
- Suspensão automática em cascata (*stale-on-write*) após retificações.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
import copy
import difflib
import hashlib
import importlib.resources
import json
import os
import re
import sqlite3
import sys
import unicodedata
from pathlib import Path, PurePath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if SRC_DIR.is_dir() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


VAULT_FOLDERS: tuple[str, ...] = (
    "00_Manual",
    "10_Entidades",
    "20_Afirmacoes",
    "30_Fontes",
    "40_Avaliacoes",
    "50_Sinteses",
    "60_Questoes",
    "70_Operacao",
    "80_Visoes",
)

PROHIBITED_CLINICAL_KEYS: frozenset[str] = frozenset(
    {
        "diagnosis",
        "clinical_diagnosis",
        "diagnostic_probability",
        "psychiatric_diagnosis",
        "icd_code",
        "dsm_code",
    }
)

_EMBEDDER_CACHE: dict[str, Any] = {}


class ErrorCode:
    """Códigos de erro determinísticos expostos ao loop de Function Calling."""

    ACCESS_DENIED = "ACCESS_DENIED"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    MALFORMED_ARGUMENTS = "MALFORMED_ARGUMENTS"
    ATTRIBUTION_FIREWALL_BLOCKED = "ATTRIBUTION_FIREWALL_BLOCKED"
    REVISION_CONFLICT = "REVISION_CONFLICT"
    RESOURCE_LOCKED = "RESOURCE_LOCKED"
    UNCERTAIN_EFFECT = "UNCERTAIN_EFFECT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    IO_STORAGE_ERROR = "IO_STORAGE_ERROR"


class EpistemicAccessDeniedError(PermissionError):
    """Levantada quando o cofre está em manutenção ou sem autorização local."""


def _append_authorized_root(root_path: Path) -> None:
    resolved = str(root_path.resolve())
    existing = [p.strip() for p in os.environ.get("EMC_AUTHORIZED_ROOTS", "").split(os.pathsep) if p.strip()]
    if resolved not in existing:
        existing.append(resolved)
        os.environ["EMC_AUTHORIZED_ROOTS"] = os.pathsep.join(existing)


def _is_authorized_scope(system_root: Path, vault_root: Path) -> bool:
    import nucleo

    checker = getattr(nucleo, "is_authorized_scope", None)
    if callable(checker):
        return bool(checker(system_root, vault_root))
    r = Path(system_root).resolve()
    v = Path(vault_root).resolve()
    real_sys = Path(nucleo.REAL_SYSTEM).resolve()
    real_vault = Path(nucleo.REAL_VAULT).resolve()
    temp = (real_sys / "testes_temporarios").resolve()
    if (r == real_sys and v == real_vault) or (temp in r.parents and temp in v.parents):
        return True
    for entry in os.environ.get("EMC_AUTHORIZED_ROOTS", "").split(os.pathsep):
        cleaned = entry.strip()
        if not cleaned:
            continue
        base = Path(cleaned).resolve()
        if (r == base or base in r.parents) and (v == base or base in v.parents):
            return True
    return False


def _canonical_fingerprint(value: Any) -> str:
    from nucleo import Invalid

    try:
        encoded = json.dumps(
            _normalize_for_key(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Invalid("argumentos da operação exigem JSON finito e serializável") from exc
    return hashlib.sha256(encoded).hexdigest()


def bootstrap_workspace_env(workspace_dir: str | Path) -> tuple[Path, Path]:
    """Configura `EMC_SYSTEM`, `EMC_VAULT` e `EMC_AUTHORIZED_ROOTS` em processos dedicados."""
    ws = Path(workspace_dir).resolve()
    sys_root = ws / "sistema"
    vault_root = ws / "cofre"
    os.environ["EMC_SYSTEM"] = str(sys_root)
    os.environ["EMC_VAULT"] = str(vault_root)
    _append_authorized_root(ws)
    return sys_root, vault_root


def _normalize_for_key(value: Any) -> Any:
    if isinstance(value, PurePath):
        return value.as_posix()
    if isinstance(value, tuple):
        return [_normalize_for_key(item) for item in value]
    if isinstance(value, list):
        return [_normalize_for_key(item) for item in value]
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                from nucleo import Invalid

                raise Invalid("chaves de dicionário em make_operation_key devem ser strings")
            out[k] = _normalize_for_key(v)
        return out
    return value


def make_operation_key(namespace: str, *parts: Any, max_length: int = 52) -> str:
    """Gera chave de idempotência determinística compatível com todos os contratos do motor.

    O limite padrão (`52`) respeita simultaneamente `Store.apply` (`<= 80`),
    `Knowledge.contribution` (`<= 60`) e `apoio_decisao.prepare` (`<= 55`).
    """
    from nucleo import Invalid

    if not isinstance(namespace, str) or not namespace.strip():
        raise Invalid("namespace de operação deve ser texto não vazio")
    if type(max_length) is not int or not 16 <= max_length <= 80:
        raise Invalid("max_length deve ser inteiro entre 16 e 80")

    ascii_ns = "".join(
        ch for ch in unicodedata.normalize("NFKD", namespace) if not unicodedata.combining(ch)
    )
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", ascii_ns).strip("-_").lower() or "op"

    try:
        canonical = json.dumps(
            {"ns": namespace, "parts": [_normalize_for_key(p) for p in parts]},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Invalid("make_operation_key exige valores JSON finitos e serializáveis") from exc

    digest = hashlib.sha256(canonical).hexdigest()
    hash_len = min(32, max(12, max_length - 4))
    max_prefix = max(2, max_length - hash_len - 1)
    prefix = slug[:max_prefix].rstrip("-_") or "op"
    key = f"{prefix}-{digest[:hash_len]}"
    return key[:max_length]


def _validate_rev_ref(ref: Any, label: str = "referência") -> dict[str, Any]:
    from nucleo import Invalid

    if not isinstance(ref, Mapping):
        raise Invalid(f"{label} deve ser um objeto RevRef")
    rec_id = ref.get("record_id")
    rev = ref.get("revision")
    if not isinstance(rec_id, str) or not rec_id.strip():
        raise Invalid(f"{label} exige record_id textual não vazio")
    if type(rev) is not int or rev < 1:
        raise Invalid(f"{label} exige revision inteira positiva")
    cleaned: dict[str, Any] = {"record_id": rec_id, "revision": rev}
    if "fragment" in ref and ref["fragment"] is not None:
        if not isinstance(ref["fragment"], str) or not ref["fragment"]:
            raise Invalid(f"{label} possui fragment inválido")
        cleaned["fragment"] = ref["fragment"]
    if "path" in ref and ref["path"] is not None:
        if not isinstance(ref["path"], str) or not ref["path"]:
            raise Invalid(f"{label} possui path inválido")
        cleaned["path"] = ref["path"]
    return cleaned


def _reject_clinical_keys(mapping: Mapping[str, Any]) -> None:
    from nucleo import Invalid

    found = PROHIBITED_CLINICAL_KEYS.intersection(mapping.keys())
    if found:
        joined = ", ".join(sorted(found))
        raise Invalid(f"diagnóstico clínico implícito não permitido no contrato: {joined}")


def _resolve_embedder(enable_embeddings: bool | None) -> Any:
    if enable_embeddings is False:
        return None
    emb_env = os.environ.get("EMC_EMBEDDINGS_DIR", "").strip()
    candidate = Path(emb_env) if emb_env else (REPO_ROOT / "modelos" / "e5-multilingual-small")
    if not ((candidate / "model.onnx").is_file() and (candidate / "tokenizer.json").is_file()):
        return None
    cache_key = candidate.resolve().as_posix()
    if cache_key in _EMBEDDER_CACHE:
        return _EMBEDDER_CACHE[cache_key]
    try:
        from recuperacao import LocalEmbeddings
    except ImportError:
        return None
    try:
        embedder = LocalEmbeddings(candidate)
    except ImportError:
        return None
    _EMBEDDER_CACHE[cache_key] = embedder
    return embedder


def _classify_exception(exc: BaseException) -> tuple[str, str, bool, bool]:
    from atribuicao import AttributionError
    from nucleo import Conflict, Invalid, Locked, Uncertain

    if isinstance(exc, EpistemicAccessDeniedError):
        return ErrorCode.ACCESS_DENIED, "denied", False, False
    if isinstance(exc, AttributionError):
        return ErrorCode.ATTRIBUTION_FIREWALL_BLOCKED, "blocked", False, bool(exc.ambiguous)
    if isinstance(exc, Conflict):
        return ErrorCode.REVISION_CONFLICT, "conflict", False, False
    if isinstance(exc, Locked):
        return ErrorCode.RESOURCE_LOCKED, "locked", True, False
    if isinstance(exc, Uncertain):
        return ErrorCode.UNCERTAIN_EFFECT, "uncertain", False, False
    if isinstance(exc, (Invalid, ValueError, TypeError, KeyError)):
        return ErrorCode.VALIDATION_ERROR, "invalid", False, False
    if isinstance(exc, (OSError, sqlite3.Error)):
        return ErrorCode.IO_STORAGE_ERROR, "io_error", False, False
    return ErrorCode.VALIDATION_ERROR, "invalid", False, False


_REV_REF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Referência versionada imutável (RevRef) a um registro canônico.",
    "properties": {
        "record_id": {"type": "string", "description": "UUID do registro referenciado."},
        "revision": {"type": "integer", "description": "Número inteiro positivo da revisão examinada."},
    },
    "required": ["record_id", "revision"],
    "additionalProperties": False,
}

_CLAIM_REF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Ponteiro RFC 6901 versionado para um campo estruturado em uma fonte primária.",
    "properties": {
        "record_id": {"type": "string", "description": "UUID da fonte primária em 30_Fontes."},
        "revision": {"type": "integer", "description": "Revisão inteira positiva da fonte primária."},
        "path": {"type": "string", "description": "Ponteiro JSON RFC 6901 (ex.: '/opex_anual')."},
    },
    "required": ["record_id", "revision", "path"],
    "additionalProperties": False,
}

_CITATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Citação literal vinculada a uma revisão explícita.",
    "properties": {
        "record_id": {"type": "string", "description": "UUID do registro citado."},
        "revision": {"type": "integer", "description": "Revisão inteira positiva do registro citado."},
        "quote": {"type": "string", "description": "Trecho literal exato presente no registro."},
    },
    "required": ["record_id", "revision", "quote"],
    "additionalProperties": False,
}


_TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "remember_source",
        "description": (
            "Registra uma fonte primária imutável por revisão em 30_Fontes com hash SHA-256. "
            "Separa estritamente relato/documento original de interpretações derivadas."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Título legível da fonte (1 a 120 caracteres)."},
                "content": {"type": "string", "description": "Conteúdo literal ou JSON estruturado da fonte."},
                "operation_key": {
                    "type": "string",
                    "description": "Chave de idempotência opcional ([A-Za-z0-9_-]{1,80}).",
                },
                "source_kind": {
                    "type": "string",
                    "enum": [
                        "conversation",
                        "conversation_turn",
                        "document",
                        "publication",
                        "web_page",
                        "tool_output",
                        "observation_record",
                    ],
                    "description": "Natureza canônica da fonte primária.",
                },
                "origin_description": {
                    "type": "string",
                    "description": "Descrição da origem documental ou conversacional.",
                },
                "reference_locator": {
                    "type": "string",
                    "description": "URI ou localizador de referência (obrigatório em publication/web_page).",
                },
                "publication_title": {
                    "type": "string",
                    "description": "Título do periódico/obra quando source_kind='publication'.",
                },
                "parent_source_ref": _REV_REF_SCHEMA,
            },
            "required": ["title", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rectify_source",
        "description": (
            "Retifica uma fonte primária existente exigindo revisão esperada (controle otimista), "
            "arquiva a revisão anterior em estado/revisoes/ e suspende derivados em cascata."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string", "description": "UUID da fonte primária em 30_Fontes."},
                "expected_revision": {
                    "type": "integer",
                    "description": "Revisão atual esperada da fonte antes da retificação.",
                },
                "new_content": {"type": "string", "description": "Novo conteúdo integral da fonte retificada."},
                "reason": {"type": "string", "description": "Motivo auditável da retificação (1 a 500 caracteres)."},
                "operation_key": {"type": "string", "description": "Chave de idempotência opcional."},
            },
            "required": ["record_id", "expected_revision", "new_content", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "register_entity",
        "description": (
            "Registra ou atualiza uma entidade canônica em 10_Entidades (person, project, goal, "
            "organization, concept, etc.) com pinagem obrigatória de origin_refs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Título canônico da entidade."},
                "entity_kind": {
                    "type": "string",
                    "description": "Subtipo da entidade (ex.: person, project, goal, organization, concept, idea).",
                },
                "origin_refs": {
                    "type": "array",
                    "items": _REV_REF_SCHEMA,
                    "description": "Lista não vazia de RevRefs de origem.",
                },
                "identity_status": {
                    "type": "string",
                    "enum": ["provisional", "identified", "ambiguous", "merged"],
                    "description": "Estado de identificação da entidade.",
                },
                "fields": {
                    "type": "object",
                    "description": "Campos específicos do subtipo (ex.: display_name, aliases, purpose, desired_outcome).",
                },
                "operation_key": {"type": "string", "description": "Chave de idempotência opcional."},
                "record_id": {"type": "string", "description": "UUID existente em caso de atualização."},
                "expected_revision": {
                    "type": "integer",
                    "description": "Revisão esperada em caso de atualização.",
                },
            },
            "required": ["title", "entity_kind", "origin_refs"],
            "additionalProperties": False,
        },
    },
    {
        "name": "assert_fact",
        "description": (
            "Registra uma afirmação tipada em 20_Afirmacoes aplicando o firewall determinístico "
            "de atribuição (atribuicao.py) para impedir troca de interlocutor ou métricas. "
            "Nunca produz diagnóstico clínico implícito nem autoaprova revisão humana."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Título descritivo da afirmação."},
                "subject_ref": _REV_REF_SCHEMA,
                "predicate": {
                    "type": "string",
                    "description": "Predicado semântico canônico (ex.: reports_preference, reports_value, pursues_goal).",
                },
                "nature": {
                    "type": "string",
                    "enum": [
                        "user_report",
                        "third_party_report",
                        "documented_observation",
                        "instrument_result",
                        "inference",
                    ],
                    "description": "Natureza epistemológica da afirmação.",
                },
                "asserted_by": {"type": "string", "description": "Identificador do agente ou autor responsável."},
                "source_refs": {
                    "type": "array",
                    "items": _REV_REF_SCHEMA,
                    "description": "Fontes primárias que sustentam relatos/observações.",
                },
                "basis_refs": {
                    "type": "array",
                    "items": _REV_REF_SCHEMA,
                    "description": "Bases versionadas quando nature='inference'.",
                },
                "value": {
                    "type": "object",
                    "description": "Valor estruturado {'type': 'text|number|...', 'content': ...} (exclusivo com object_ref).",
                },
                "object_ref": _REV_REF_SCHEMA,
                "evidence_quote": {
                    "type": "string",
                    "description": "Trecho literal exato da fonte comprovando a atribuição ao sujeito.",
                },
                "evidence_source_ref": _REV_REF_SCHEMA,
                "attribution_resolution_ref": _REV_REF_SCHEMA,
                "context_description": {
                    "type": "string",
                    "description": "Contexto situacional da afirmação.",
                },
                "valid_time": {
                    "type": "object",
                    "description": "Especificação temporal (ex.: {'precision': 'unknown'} ou {'precision': 'day', 'value': '2026-11-17'}).",
                },
                "scope_note": {"type": "string", "description": "Nota de alcance (obrigatória em avaliação de evidência)."},
                "limitations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Limitações explícitas da inferência ou observação.",
                },
                "operation_key": {"type": "string", "description": "Chave de idempotência opcional."},
            },
            "required": ["title", "subject_ref", "predicate"],
            "additionalProperties": False,
        },
    },
    {
        "name": "synthesize",
        "description": (
            "Registra uma síntese derivada revisável em 50_Sinteses com bases versionadas "
            "(basis_refs) e limitações explícitas."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Título da síntese."},
                "content": {"type": "string", "description": "Texto analítico derivado das bases."},
                "scope": {"type": "string", "description": "Escopo estrito de validade da síntese."},
                "basis_refs": {
                    "type": "array",
                    "items": _REV_REF_SCHEMA,
                    "description": "Lista não vazia de RevRefs das bases utilizadas.",
                },
                "limitations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Limitações explícitas e condições de invalidação.",
                },
                "synthesis_kind": {
                    "type": "string",
                    "description": "Subtipo da síntese (padrão: knowledge_summary).",
                },
                "coverage_status": {
                    "type": "string",
                    "enum": [
                        "provisional",
                        "supported_within_scope",
                        "limited",
                        "conflicting",
                        "needs_revalidation",
                    ],
                    "description": "Estado de cobertura das evidências.",
                },
                "as_of": {"type": "string", "description": "Instante/data de referência opcional."},
                "operation_key": {"type": "string", "description": "Chave de idempotência opcional."},
            },
            "required": ["title", "content", "scope", "basis_refs", "limitations"],
            "additionalProperties": False,
        },
    },
    {
        "name": "prepare_decision",
        "description": (
            "Registra análise estruturada de apoio à decisão (entidade decision, síntese de "
            "análise e questões abertas de lacunas), sem escolher nem executar ações pelo usuário."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Título da decisão (1 a 90 caracteres)."},
                "situation": {"type": "string", "description": "Descrição da situação decisória."},
                "options": {
                    "type": "array",
                    "description": "Entre 2 e 8 opções (ao menos uma com origem='relatada_pelo_usuario').",
                    "items": {
                        "type": "object",
                        "properties": {
                            "descricao": {"type": "string", "description": "Descrição da alternativa."},
                            "origem": {
                                "type": "string",
                                "enum": ["relatada_pelo_usuario", "sugerida_pela_ia"],
                                "description": "Origem explícita da opção.",
                            },
                            "pros": {"type": "array", "items": {"type": "string"}},
                            "contras": {"type": "array", "items": {"type": "string"}},
                            "incertezas": {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["descricao", "origem", "pros", "contras", "incertezas"],
                        "additionalProperties": False,
                    },
                },
                "source_refs": {
                    "type": "array",
                    "items": _REV_REF_SCHEMA,
                    "description": "Fontes primárias atuais que contextualizam a decisão.",
                },
                "gaps": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Lacunas em aberto convertidas em questões rastreáveis (60_Questoes).",
                },
                "operation_key": {"type": "string", "description": "Chave de idempotência opcional (<= 55 caracteres)."},
            },
            "required": ["title", "situation", "options", "source_refs"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_claims",
        "description": (
            "Verifica alegações objetivas (field, sum, chain) e citações contra fontes primárias "
            "atuais sem usar LLM, emitindo comprovante criptográfico lab-assurance-2."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "claims": {
                    "type": "array",
                    "description": "Lista de alegações estruturadas (até 64 itens).",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "Identificador único da alegação no recibo."},
                            "kind": {
                                "type": "string",
                                "enum": ["field", "sum", "chain", "hypothesis", "free_text"],
                                "description": "Tipo de verificação determinística.",
                            },
                            "refs": {
                                "type": "array",
                                "items": _CLAIM_REF_SCHEMA,
                                "description": "Ponteiros RFC 6901 em fontes primárias atuais.",
                            },
                            "value": {
                                "description": "Valor JSON exato alegado (número, texto, booleano, lista ou objeto)."
                            },
                        },
                        "required": ["id", "kind", "refs", "value"],
                        "additionalProperties": False,
                    },
                },
                "answer": {
                    "type": "string",
                    "description": "Texto da resposta (opcional em modo controlled, obrigatório em free_text).",
                },
                "answer_format": {
                    "type": "string",
                    "enum": ["controlled", "free_text"],
                    "description": "Modalidade de vinculação da resposta ao comprovante.",
                },
                "citations": {
                    "type": "array",
                    "items": _CITATION_SCHEMA,
                    "description": "Citações literais opcionais verificadas também por atribuicao.py.",
                },
                "context_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs inicialmente presentes no contexto (aciona suplementação seletiva se necessário).",
                },
                "max_context": {
                    "type": "integer",
                    "description": "Orçamento máximo de registros de evidência (1 a 50).",
                },
                "operation_key": {"type": "string", "description": "Chave de idempotência opcional."},
            },
            "required": ["claims"],
            "additionalProperties": False,
        },
    },
    {
        "name": "recall_context",
        "description": (
            "Executa recuperação híbrida auditável (RRF lexical + vetorial ONNX E5 quando "
            "disponível + expansão em grafo), excluindo automaticamente registros suspensos/stale."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Consulta de busca (1 a 500 caracteres)."},
                "limit": {"type": "integer", "description": "Limite de resultados (1 a 50, padrão 12)."},
                "depth": {"type": "integer", "description": "Profundidade de expansão no grafo (0 a 2, padrão 1)."},
                "include_records": {
                    "type": "boolean",
                    "description": "Se verdadeiro, inclui o envelope completo de cada nota retornada.",
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "blast_radius",
        "description": (
            "Inspeciona o raio de impacto (linhagem a jusante) de um registro ou de todo o cofre, "
            "separando registros derivados ativos vs suspensos (needs_revalidation) e recibos stale."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "UUID opcional do registro de origem; se omitido, lista todo o cofre.",
                },
                "include_receipts": {
                    "type": "boolean",
                    "description": "Se verdadeiro, revalida também os comprovantes lab-assurance-2.",
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_record",
        "description": (
            "Lê um registro canônico (fonte ou derivado) informando vigência atual "
            "(current_within_scope) ou bloqueio por suspensão (needs_revalidation)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string", "description": "UUID do registro no cofre."},
            },
            "required": ["record_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_receipt",
        "description": (
            "Revalida um comprovante lab-assurance-2 contra a geração atual do cofre, "
            "detectando imediatamente transição para stale ou adulteração."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "receipt_id": {"type": "string", "description": "Hash SHA-256 (64 hex chars) do comprovante."},
            },
            "required": ["receipt_id"],
            "additionalProperties": False,
        },
    },
)

_TOOL_MAP: dict[str, dict[str, Any]] = {spec["name"]: spec for spec in _TOOL_DEFINITIONS}

_GEMINI_TYPE_MAP: dict[str, str] = {
    "object": "OBJECT",
    "string": "STRING",
    "integer": "INTEGER",
    "number": "NUMBER",
    "boolean": "BOOLEAN",
    "array": "ARRAY",
}


def _to_gemini_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Converte um JSON Schema restrito para o formato `Schema` de `FunctionDeclaration` do Gemini."""
    raw_type = schema.get("type")
    out: dict[str, Any] = {}
    if isinstance(raw_type, str) and raw_type in _GEMINI_TYPE_MAP:
        out["type"] = _GEMINI_TYPE_MAP[raw_type]
    else:
        # Campos polimórficos (ex.: claim.value) usam OBJECT/valor livre sem restringir tipo fixo;
        # na API Gemini Schema `type` omitido ou STRING/OBJECT exige estrutura válida:
        # omitimos `type` apenas em nós folha polimórficos com `description`.
        pass
    if "description" in schema:
        out["description"] = schema["description"]
    if "enum" in schema:
        out["enum"] = list(schema["enum"])
    if "properties" in schema and isinstance(schema["properties"], Mapping):
        out["properties"] = {
            prop_name: _to_gemini_schema(prop_schema)
            for prop_name, prop_schema in schema["properties"].items()
        }
    if "required" in schema and isinstance(schema["required"], list) and schema["required"]:
        out["required"] = list(schema["required"])
    if "items" in schema and isinstance(schema["items"], Mapping):
        out["items"] = _to_gemini_schema(schema["items"])
    return out


class EpistemicMemoryClient:
    """Cliente de alto nível sobre o Epistemic Memory Core para agentes e pipelines Python."""

    make_operation_key = staticmethod(make_operation_key)

    def __init__(
        self,
        workspace_dir: str | Path | None = None,
        *,
        system_root: str | Path | None = None,
        vault_root: str | Path | None = None,
        store: Any | None = None,
        enable_embeddings: bool | None = None,
        owner_person_id: str | None = None,
        require_access_env: bool | None = None,
        scope: str = "proprietario_local",
    ) -> None:
        from autonomia import atomic_json
        from conhecimento import Knowledge
        from execucao import DEFAULT
        from nucleo import REAL_SYSTEM, REAL_VAULT, Invalid, Store, config_file
        from recuperacao import Retrieval

        if not isinstance(scope, str) or not scope.strip():
            raise Invalid("scope deve ser texto não vazio")
        self.scope = scope
        self._require_access_env = require_access_env

        if store is not None:
            if workspace_dir is not None or system_root is not None or vault_root is not None:
                raise Invalid("informe apenas store OU diretórios de workspace/sistema/cofre")
            self.store = store
            self.system_root = Path(store.root).resolve()
            self.vault_root = Path(store.vault).resolve()
        else:
            if workspace_dir is not None:
                if system_root is not None or vault_root is not None:
                    raise Invalid("informe workspace_dir OU (system_root, vault_root), não ambos")
                ws = Path(workspace_dir).resolve()
                self.system_root = ws / "sistema"
                self.vault_root = ws / "cofre"
            elif system_root is not None or vault_root is not None:
                if system_root is None or vault_root is None:
                    raise Invalid("system_root e vault_root devem ser informados juntos")
                self.system_root = Path(system_root).resolve()
                self.vault_root = Path(vault_root).resolve()
            else:
                self.system_root = REAL_SYSTEM
                self.vault_root = REAL_VAULT

            # Valida escopo ANTES de criar qualquer diretório ou arquivo em disco.
            if not _is_authorized_scope(self.system_root, self.vault_root):
                raise Invalid("raiz fora do escopo autorizado")

            # Verifica bloqueio de acesso antes de inicializar ou tocar o cofre real.
            self._check_access()

            if self.system_root != REAL_SYSTEM or self.vault_root != REAL_VAULT:
                self._bootstrap_isolated_dirs(self.system_root, self.vault_root)

            self.store = Store(self.system_root, self.vault_root)

        self._check_access()
        self.ops_db = self.system_root / "estado" / "sdk_operacoes.sqlite3"
        self._ensure_ops_db()
        self.knowledge = Knowledge(self.store)
        self.embedder = _resolve_embedder(enable_embeddings)

        if self.system_root != REAL_SYSTEM:
            cfg_path = config_file(self.system_root, "execucao.json")
            if not cfg_path.exists():
                cfg = copy.deepcopy(DEFAULT)
                cfg["enabled"] = True
                emb_dir_env = os.environ.get("EMC_EMBEDDINGS_DIR", "").strip()
                default_model_dir = REPO_ROOT / "modelos" / "e5-multilingual-small"
                emb_cfg = dict(cfg.get("embeddings", {}))
                emb_cfg["enabled"] = self.embedder is not None
                emb_cfg["folder"] = (
                    emb_dir_env
                    if emb_dir_env
                    else (str(default_model_dir) if default_model_dir.is_dir() else "")
                )
                emb_cfg.setdefault("vector_storage", "packed_f64")
                cfg["embeddings"] = emb_cfg
                atomic_json(cfg_path, cfg)

        if owner_person_id is not None:
            self.set_owner_person(owner_person_id)

        self.retrieval = Retrieval(self.store, embedder=self.embedder, scope=self.scope)
        self.retriever = self.retrieval

    @classmethod
    def from_workspace(
        cls,
        workspace_dir: str | Path,
        *,
        enable_embeddings: bool | None = None,
        owner_person_id: str | None = None,
        require_access_env: bool | None = None,
        scope: str = "proprietario_local",
    ) -> "EpistemicMemoryClient":
        """Construtor semântico para inicialização direta a partir de um diretório de workspace."""
        return cls(
            workspace_dir,
            enable_embeddings=enable_embeddings,
            owner_person_id=owner_person_id,
            require_access_env=require_access_env,
            scope=scope,
        )

    @staticmethod
    def _bootstrap_isolated_dirs(system_root: Path, vault_root: Path) -> None:
        from autonomia import atomic_json
        from nucleo import REAL_SYSTEM, config_file

        system_root.mkdir(parents=True, exist_ok=True)
        vault_root.mkdir(parents=True, exist_ok=True)
        for folder in VAULT_FOLDERS:
            (vault_root / folder).mkdir(parents=True, exist_ok=True)

        try:
            from recursos_pacote import bootstrap_manual_tree
        except ImportError:
            bootstrap_manual_tree = None  # type: ignore[assignment]

        if callable(bootstrap_manual_tree):
            bootstrap_manual_tree(system_root, vault_root)
            return

        manifest: dict[str, str] | None = None
        manifest_src = config_file(REPO_ROOT, "manual_manifest.json")
        if not manifest_src.exists():
            manifest_src = config_file(REAL_SYSTEM, "manual_manifest.json")
        if manifest_src.exists():
            manifest = json.loads(manifest_src.read_text(encoding="utf-8"))
        else:
            try:
                res_manifest = importlib.resources.files("emc_resources").joinpath("config/manual_manifest.json")
                manifest = json.loads(res_manifest.read_text(encoding="utf-8"))
            except (ModuleNotFoundError, FileNotFoundError):
                manifest = None

        if manifest is None:
            raise FileNotFoundError("manual_manifest.json não encontrado no repositório nem em emc_resources")

        manual_src_dir = REPO_ROOT / "00_Manual"
        for name in manifest:
            dest_file = vault_root / "00_Manual" / name
            if dest_file.exists():
                continue
            src_file = manual_src_dir / name
            if src_file.is_file():
                dest_file.write_bytes(src_file.read_bytes())
            else:
                res_chapter = importlib.resources.files("emc_resources").joinpath("manual", name)
                dest_file.write_bytes(res_chapter.read_bytes())

        if not (system_root / "manual_manifest.json").exists():
            atomic_json(system_root / "manual_manifest.json", manifest)

    def _check_access(self) -> None:
        from nucleo import REAL_SYSTEM

        if (self.system_root / "estado" / "implantacao.lock").exists():
            raise EpistemicAccessDeniedError(
                "Atualização do serviço em andamento (implantacao.lock ativo); aguarde a conclusão."
            )
        must_check_env = (
            self._require_access_env is True
            or (self._require_access_env is None and self.system_root == REAL_SYSTEM)
        )
        if must_check_env and os.environ.get("CEREBRO_PESSOAL_ACESSO") != "permitido":
            raise EpistemicAccessDeniedError(
                "Acesso ao conteúdo desabilitado na configuração local (CEREBRO_PESSOAL_ACESSO!=permitido)."
            )

    @contextmanager
    def _connect_ops_db(self):
        self.ops_db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.ops_db, timeout=15)
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA secure_delete=ON")
        try:
            with conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sdk_operation_receipts (
                        domain TEXT NOT NULL,
                        operation_key TEXT NOT NULL,
                        request_fingerprint TEXT NOT NULL,
                        record_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        receipt_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (domain, operation_key)
                    )
                    """
                )
                yield conn
        finally:
            conn.close()

    def _ensure_ops_db(self) -> None:
        if (self.system_root / "estado").is_dir():
            with self._connect_ops_db():
                pass

    def _load_op_receipt(self, domain: str, operation_key: str) -> tuple[str, dict[str, Any]] | None:
        with self._connect_ops_db() as conn:
            row = conn.execute(
                "SELECT request_fingerprint, receipt_json FROM sdk_operation_receipts WHERE domain=? AND operation_key=?",
                (domain, operation_key),
            ).fetchone()
        if not row:
            return None
        return str(row[0]), json.loads(row[1])

    def _save_op_receipt(
        self,
        domain: str,
        operation_key: str,
        request_fingerprint: str,
        record_id: str,
        revision: int,
        receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        from nucleo import Conflict, NOW

        serialized = json.dumps(
            dict(receipt),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        with self._connect_ops_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT request_fingerprint, receipt_json FROM sdk_operation_receipts WHERE domain=? AND operation_key=?",
                (domain, operation_key),
            ).fetchone()
            if existing:
                if existing[0] != request_fingerprint:
                    raise Conflict("chave reutilizada para outro pedido")
                return json.loads(existing[1])
            conn.execute(
                "INSERT INTO sdk_operation_receipts VALUES (?, ?, ?, ?, ?, ?, ?)",
                (domain, operation_key, request_fingerprint, record_id, revision, serialized, NOW()),
            )
        return json.loads(serialized)

    def _read_source_revision_snapshot(self, record_id: str, rev: int) -> dict[str, Any]:
        """Recupera bytes exatos, SHA-256 e conteúdo de qualquer revisão (histórica ou atual) de uma fonte."""
        from nucleo import Conflict, Invalid, parse, read_exclusive, sha

        if not isinstance(record_id, str) or not record_id.strip():
            raise Invalid("record_id inválido")
        if type(rev) is not int or rev < 1:
            raise Invalid("revisão deve ser inteiro positivo")

        with self.store.connect() as conn:
            if conn.execute("SELECT 1 FROM tombstones WHERE record_id=?", (record_id,)).fetchone():
                raise Invalid("registro excluído ou em exclusão")
            row = conn.execute(
                "SELECT filename, revision, digest FROM records WHERE id=?", (record_id,)
            ).fetchone()
            hist_op = conn.execute(
                "SELECT new_digest FROM operations WHERE record_id=? AND expected=? AND status='confirmed'",
                (record_id, rev - 1),
            ).fetchone()
        if not row:
            raise Invalid("registro não encontrado")

        fname, current_rev, current_digest = row
        if rev > current_rev:
            raise Invalid(f"revisão {rev} inexistente para fonte {record_id}")

        if rev == current_rev:
            raw_bytes = read_exclusive(self.store.safe_path(fname))
            digest = sha(raw_bytes)
            if digest != current_digest:
                with self.store.connect() as conn:
                    if conn.execute("SELECT 1 FROM tombstones WHERE record_id=?", (record_id,)).fetchone():
                        raise Invalid("registro excluído ou em exclusão")
                    fresh = conn.execute(
                        "SELECT filename, revision, digest FROM records WHERE id=?", (record_id,)
                    ).fetchone()
                if not fresh or fresh[0] != fname or sha(raw_bytes) != fresh[2]:
                    raise Conflict("edição externa detectada; reconciliação necessária")
                current_rev, current_digest = fresh[1], fresh[2]
                if current_rev != rev:
                    return self._read_source_revision_snapshot(record_id, rev)
            parsed = parse(raw_bytes)
        else:
            hist_root = (self.system_root / "estado" / "revisoes").resolve()
            hist_file = self.system_root / "estado" / "revisoes" / record_id / f"{rev}.md"
            if (
                hist_file.is_symlink()
                or not hist_file.resolve().is_relative_to(hist_root)
                or not hist_file.is_file()
            ):
                raise Conflict(f"snapshot histórico da revisão {rev} ausente para {record_id}")
            raw_bytes = hist_file.read_bytes()
            digest = sha(raw_bytes)
            if hist_op and hist_op[0] and digest != hist_op[0]:
                raise Conflict("snapshot histórico divergiu do diário de operações")
            parsed = parse(raw_bytes)

        if parsed.get("id") != record_id or parsed.get("revision") != rev:
            raise Conflict("identidade ou revisão divergente no snapshot da fonte")

        return {
            "record_id": record_id,
            "revision": rev,
            "raw_bytes": raw_bytes,
            "sha256": digest,
            "content": str(parsed.get("payload", {}).get("content", "")),
            "record": parsed,
            "current_revision": current_rev,
        }

    def _read_knowledge_revision_snapshot(self, record_id: str, rev: int) -> dict[str, Any]:
        """Recupera bytes exatos, SHA-256 e payload de qualquer revisão (histórica ou atual) derivada."""
        from conhecimento import decode
        from nucleo import Conflict, Invalid, read_exclusive, sha

        if not isinstance(record_id, str) or not record_id.strip():
            raise Invalid("record_id inválido")
        if type(rev) is not int or rev < 1:
            raise Invalid("revisão deve ser inteiro positivo")

        with self.knowledge.connect() as conn:
            managed = conn.execute(
                "SELECT path, digest, revision FROM managed WHERE id=?", (record_id,)
            ).fetchone()

        if managed is not None:
            rel_path, current_digest, current_rev = managed
            if rev > current_rev:
                raise Invalid(f"revisão {rev} inexistente para registro {record_id}")
            if rev == current_rev:
                note_path = self.vault_root / rel_path
                resolved_note = note_path.resolve()
                if note_path.is_symlink() or not resolved_note.is_relative_to(self.vault_root) or not resolved_note.is_file():
                    raise Conflict("arquivo de conhecimento ausente ou redirecionado")
                raw_bytes = read_exclusive(resolved_note)
                digest = sha(raw_bytes)
                if current_digest and digest != current_digest:
                    raise Conflict("edição externa de conhecimento")
                parsed = decode(raw_bytes)
            else:
                hist_root = (self.system_root / "estado" / "conhecimento_revisoes").resolve()
                arc_path = self.system_root / "estado" / "conhecimento_revisoes" / record_id / f"{rev}.md"
                if (
                    arc_path.is_symlink()
                    or not arc_path.resolve().is_relative_to(hist_root)
                    or not arc_path.is_file()
                ):
                    raise Conflict(f"snapshot histórico da revisão {rev} ausente para {record_id}")
                raw_bytes = arc_path.read_bytes()
                digest = sha(raw_bytes)
                parsed = decode(raw_bytes)
        else:
            records, paths, _ = self.knowledge.catalog()
            if record_id not in records or record_id not in paths:
                raise Invalid("registro inexistente")
            current_rev = int(records[record_id]["revision"])
            if rev != current_rev:
                raise Conflict(f"snapshot histórico da revisão {rev} indisponível para {record_id}")
            raw_bytes = read_exclusive(paths[record_id])
            digest = sha(raw_bytes)
            parsed = decode(raw_bytes)

        if parsed.get("id") != record_id or parsed.get("revision") != rev:
            raise Conflict("identidade ou revisão divergente no snapshot de conhecimento")

        return {
            "record_id": record_id,
            "revision": rev,
            "raw_bytes": raw_bytes,
            "sha256": digest,
            "payload": copy.deepcopy(parsed.get("payload", {})),
            "record": parsed,
            "current_revision": current_rev,
        }

    def _try_read_record_at_revision(
        self,
        record_id: str | None,
        rev: int | None,
        records: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        if not isinstance(record_id, str) or not record_id:
            return None
        live = records.get(record_id)
        if live is None:
            return None
        target_rev = rev if (type(rev) is int and rev >= 1) else int(live.get("revision", 1))
        try:
            if live.get("record_type") == "source":
                return self._read_source_revision_snapshot(record_id, target_rev)["record"]
            return self._read_knowledge_revision_snapshot(record_id, target_rev)["record"]
        except Exception:
            return live if live.get("revision") == target_rev else None

    def _is_knowledge_op_confirmed(self, key: str) -> bool:
        with self.knowledge.connect() as conn:
            row = conn.execute("SELECT status FROM operations WHERE key=?", (key,)).fetchone()
        return bool(row and row[0] == "confirmed")

    def _build_source_current_state(self, record_id: str) -> dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute("SELECT revision FROM records WHERE id=?", (record_id,)).fetchone()
        if not row:
            from nucleo import Invalid

            raise Invalid("registro não encontrado")
        live_snap = self._read_source_revision_snapshot(record_id, int(row[0]))
        records, _, _ = self.knowledge.catalog()
        stale_set = self.knowledge.stale(records)
        radius = self.blast_radius(record_id, include_receipts=True)
        sorted_stale = sorted(stale_set)
        return {
            "current_revision": live_snap["revision"],
            "current_sha256": live_snap["sha256"],
            "total_revisions": live_snap["revision"],
            "validity": "needs_revalidation" if record_id in stale_set else "current_within_scope",
            "currently_stale_ids": sorted_stale,
            "currently_suspended_ids": list(radius["suspended_ids"]),
            "total_stale_records": len(sorted_stale),
            "currently_stale_receipt_ids": list(radius["stale_receipt_ids"]),
        }

    def _build_knowledge_current_state(self, record_id: str) -> dict[str, Any]:
        records, _, _ = self.knowledge.catalog()
        if record_id not in records:
            from nucleo import Invalid

            raise Invalid("registro inexistente")
        live_rev = int(records[record_id]["revision"])
        live_snap = self._read_knowledge_revision_snapshot(record_id, live_rev)
        stale_set = self.knowledge.stale(records)
        radius = self.blast_radius(record_id, include_receipts=True)
        sorted_stale = sorted(stale_set)
        return {
            "current_revision": live_snap["revision"],
            "current_sha256": live_snap["sha256"],
            "total_revisions": live_snap["revision"],
            "validity": "needs_revalidation" if record_id in stale_set else "current_within_scope",
            "currently_stale_ids": sorted_stale,
            "currently_suspended_ids": list(radius["suspended_ids"]),
            "total_stale_records": len(sorted_stale),
            "currently_stale_receipt_ids": list(radius["stale_receipt_ids"]),
        }

    def _infer_historical_suspended_for_source(
        self,
        record_id: str,
        pinned_rev: int,
        records: Mapping[str, Any],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        from conhecimento import refs

        suspended: set[str] = set()
        for rid, rec in records.items():
            if rec.get("record_type") == "source":
                continue
            for ref in refs(rec.get("payload", {})):
                if rec.get("record_type") == "question" and ref in rec.get("payload", {}).get("trigger_refs", []):
                    continue
                if ref.get("record_id") == record_id and ref.get("revision") == pinned_rev:
                    suspended.add(rid)
        for _ in range(len(records)):
            grown = {
                rid
                for rid, rec in records.items()
                if rec.get("record_type") != "source"
                and any(
                    not (rec.get("record_type") == "question" and ref in rec.get("payload", {}).get("trigger_refs", []))
                    and ref.get("record_id") in suspended
                    for ref in refs(rec.get("payload", {}))
                )
            }
            if grown <= suspended:
                break
            suspended |= grown
        ordered = sorted(suspended)
        details = [
            {
                "id": rid,
                "title": records[rid]["title"],
                "record_type": records[rid]["record_type"],
                "revision": records[rid]["revision"],
                "validity": "needs_revalidation",
            }
            for rid in ordered
            if rid in records
        ]
        return ordered, details

    def _infer_historical_stale_receipts_for_source(self, record_id: str, pinned_rev: int) -> list[str]:
        from evidencias import read_json

        resp_dir = self.system_root / "estado" / "comprovantes" / "respostas"
        if not resp_dir.is_dir():
            return []
        matched: list[str] = []
        for path in sorted(resp_dir.glob("*.json")):
            saved = read_json(path)
            packet = saved.get("packet", {})
            ev_rec = packet.get("evidence", {}).get(record_id)
            if isinstance(ev_rec, Mapping) and ev_rec.get("revision") == pinned_rev:
                matched.append(path.stem)
                continue
            pins = [
                ref
                for claim in packet.get("claims", [])
                for ref in claim.get("refs", [])
                if isinstance(ref, Mapping)
                and ref.get("record_id") == record_id
                and ref.get("revision") == pinned_rev
            ]
            if pins:
                matched.append(path.stem)
        return matched

    def set_owner_person(self, person_id: str | None) -> dict[str, Any]:
        """Configura `owner_person_id` em `execucao.json` para resolução de 1ª pessoa em conversas."""
        from atribuicao import persons
        from autonomia import atomic_json
        from execucao import DEFAULT, config
        from nucleo import Invalid, config_file

        self._check_access()
        if person_id is not None:
            records, _, _ = self.knowledge.catalog()
            if not isinstance(person_id, str) or person_id not in persons(records):
                raise Invalid("owner_person_id deve referenciar uma entidade person ativa no catálogo")
        cfg_path = config_file(self.system_root, "execucao.json")
        cfg = config(self.store) if cfg_path.exists() else copy.deepcopy(DEFAULT)
        cfg["owner_person_id"] = person_id
        atomic_json(cfg_path, cfg)
        return {"status": "ok", "owner_person_id": person_id}

    def remember_source(
        self,
        title: str,
        content: str,
        *,
        operation_key: str | None = None,
        source_kind: str = "conversation",
        origin_description: str | None = None,
        availability_status: str = "retained",
        retention_conditions: str = "cofre_local_controlado",
        reference_locator: str | None = None,
        publication_title: str | None = None,
        parent_source_ref: dict[str, Any] | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Registra uma fonte primária em `30_Fontes` com validação de metadados e hash SHA-256."""
        from nucleo import Conflict, Invalid

        self._check_access()
        if not isinstance(title, str) or not isinstance(content, str):
            raise Invalid("title e content devem ser strings")

        has_custom_meta = (
            source_kind != "conversation"
            or origin_description is not None
            or availability_status != "retained"
            or retention_conditions != "cofre_local_controlado"
            or reference_locator is not None
            or publication_title is not None
            or parent_source_ref is not None
            or bool(extra_metadata)
        )

        metadata: dict[str, Any] | None = None
        if has_custom_meta:
            metadata = {
                "source_kind": source_kind,
                "origin_description": (
                    origin_description or "Fonte primária registrada via Epistemic Agent Memory SDK"
                ),
                "availability_status": availability_status,
                "retention_conditions": retention_conditions,
            }
            if reference_locator is not None:
                metadata["reference_locator"] = reference_locator
            if publication_title is not None:
                metadata["publication_title"] = publication_title
            if parent_source_ref is not None:
                metadata["parent_source_ref"] = _validate_rev_ref(parent_source_ref, "parent_source_ref")
            if extra_metadata is not None:
                if not isinstance(extra_metadata, Mapping):
                    raise Invalid("extra_metadata deve ser um dicionário")
                metadata.update(extra_metadata)

        op_key = operation_key or make_operation_key(
            "src-create", title.strip(), content, source_kind, metadata
        )
        was_confirmed = self.store.status(op_key).get("status") == "confirmed"
        res = self.store.apply(
            op_key,
            "create",
            title=title,
            text=content,
            source_metadata=metadata,
        )
        sdk_fp = _canonical_fingerprint(
            {"op": "remember_source", "title": title, "content": content, "metadata": metadata}
        )
        cached = self._load_op_receipt("source", op_key)
        if cached is not None:
            stored_fp, historical_receipt = cached
            if stored_fp != sdk_fp:
                raise Conflict("chave reutilizada para outro pedido")
        else:
            snap = self._read_source_revision_snapshot(res["id"], int(res["revision"]))
            historical_receipt = self._save_op_receipt(
                "source",
                op_key,
                sdk_fp,
                res["id"],
                int(res["revision"]),
                {
                    "status": res["status"],
                    "id": res["id"],
                    "revision": int(res["revision"]),
                    "sha256": snap["sha256"],
                    "rev_ref": {"record_id": res["id"], "revision": int(res["revision"])},
                    "revision_count_at_operation": int(res["revision"]),
                    "operation_key": op_key,
                },
            )
        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": self._build_source_current_state(res["id"]),
        }

    def rectify_source(
        self,
        record_id: str,
        expected_revision: int,
        new_content: str,
        reason: str,
        *,
        operation_key: str | None = None,
        source_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Retifica uma fonte em `30_Fontes`, preserva histórico e retorna o comprovante exato da operação."""
        from nucleo import Conflict, Invalid

        self._check_access()
        if not isinstance(record_id, str) or not record_id.strip():
            raise Invalid("record_id inválido")
        if type(expected_revision) is not int or expected_revision < 1:
            raise Invalid("expected_revision deve ser inteiro positivo")
        if not isinstance(new_content, str) or not isinstance(reason, str):
            raise Invalid("new_content e reason devem ser strings")

        op_key = operation_key or make_operation_key(
            "src-rectify", record_id, expected_revision, new_content, reason, source_metadata
        )
        was_confirmed = self.store.status(op_key).get("status") == "confirmed"
        before_stale: set[str] = set()
        if not was_confirmed:
            before_records, _, _ = self.knowledge.catalog()
            before_stale = self.knowledge.stale(before_records)

        updated = self.store.apply(
            op_key,
            "correct",
            ident=record_id,
            expected=expected_revision,
            text=new_content,
            reason=reason,
            source_metadata=source_metadata,
        )

        sdk_fp = _canonical_fingerprint(
            {
                "op": "rectify_source",
                "record_id": record_id,
                "expected_revision": expected_revision,
                "new_content": new_content,
                "reason": reason,
                "source_metadata": source_metadata,
            }
        )
        cached = self._load_op_receipt("source", op_key)
        if cached is not None:
            stored_fp, historical_receipt = cached
            if stored_fp != sdk_fp:
                raise Conflict("chave reutilizada para outro pedido")
        else:
            to_rev = int(updated["revision"])
            old_snap = self._read_source_revision_snapshot(record_id, expected_revision)
            new_snap = self._read_source_revision_snapshot(record_id, to_rev)
            diff_lines = self._source_revision_diff(record_id, expected_revision, to_rev)
            after_records, _, _ = self.knowledge.catalog()
            after_stale = self.knowledge.stale(after_records)
            if not was_confirmed:
                newly_suspended = sorted(after_stale - before_stale)
                newly_suspended_records = [
                    {
                        "id": rid,
                        "title": after_records[rid]["title"],
                        "record_type": after_records[rid]["record_type"],
                        "revision": after_records[rid]["revision"],
                        "validity": "needs_revalidation",
                    }
                    for rid in newly_suspended
                    if rid in after_records
                ]
                radius = self.blast_radius(record_id, include_receipts=True)
                total_stale_at_op = len(after_stale)
                stale_receipts_at_op = list(radius["stale_receipt_ids"])
            else:
                newly_suspended, newly_suspended_records = self._infer_historical_suspended_for_source(
                    record_id, expected_revision, after_records
                )
                total_stale_at_op = len(newly_suspended)
                stale_receipts_at_op = self._infer_historical_stale_receipts_for_source(
                    record_id, expected_revision
                )

            historical_receipt = self._save_op_receipt(
                "source",
                op_key,
                sdk_fp,
                updated["id"],
                to_rev,
                {
                    "status": updated["status"],
                    "id": updated["id"],
                    "revision": to_rev,
                    "from_revision": expected_revision,
                    "to_revision": to_rev,
                    "sha256": new_snap["sha256"],
                    "old_sha256": old_snap["sha256"],
                    "new_sha256": new_snap["sha256"],
                    "rev_ref": {"record_id": updated["id"], "revision": to_rev},
                    "from_rev_ref": {"record_id": updated["id"], "revision": expected_revision},
                    "revision_count_at_operation": to_rev,
                    "operation_key": op_key,
                    "newly_suspended_ids": newly_suspended,
                    "newly_suspended_records": newly_suspended_records,
                    "total_stale_records": total_stale_at_op,
                    "stale_receipt_ids": stale_receipts_at_op,
                    "diff": diff_lines,
                },
            )

        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": self._build_source_current_state(record_id),
        }

    def _source_revision_diff(self, record_id: str, old_rev: int, new_rev: int) -> list[str]:
        old_snap = self._read_source_revision_snapshot(record_id, old_rev)
        new_snap = self._read_source_revision_snapshot(record_id, new_rev)
        return list(
            difflib.unified_diff(
                old_snap["content"].splitlines(),
                new_snap["content"].splitlines(),
                fromfile=f"revisao_{old_rev}",
                tofile=f"revisao_{new_rev}",
                lineterm="",
            )
        )

    def register_entity(
        self,
        title: str,
        entity_kind: str,
        origin_refs: list[dict[str, Any]],
        *,
        identity_status: str = "identified",
        fields: dict[str, Any] | None = None,
        operation_key: str | None = None,
        record_id: str | None = None,
        expected_revision: int | None = None,
        **extra_fields: Any,
    ) -> dict[str, Any]:
        """Registra ou atualiza uma entidade canônica em `10_Entidades`."""
        from nucleo import Conflict, Invalid

        self._check_access()
        if not isinstance(title, str) or not isinstance(entity_kind, str) or not entity_kind.strip():
            raise Invalid("title e entity_kind devem ser strings válidas")
        if not isinstance(origin_refs, list) or not origin_refs:
            raise Invalid("origin_refs exige ao menos uma referência versionada")
        if fields is not None and not isinstance(fields, Mapping):
            raise Invalid("fields deve ser um dicionário")

        cleaned_origins = [_validate_rev_ref(r, "origin_ref") for r in origin_refs]
        payload: dict[str, Any] = {}
        if fields:
            payload.update(copy.deepcopy(dict(fields)))
        if extra_fields:
            payload.update(copy.deepcopy(extra_fields))
        _reject_clinical_keys(payload)

        payload["entity_kind"] = entity_kind
        payload["origin_refs"] = cleaned_origins
        payload["identity_status"] = identity_status
        if entity_kind in ("person", "group", "organization", "place") and "display_name" not in payload:
            payload["display_name"] = title.strip()

        op_key = operation_key or make_operation_key(
            "ent", title.strip(), payload, record_id, expected_revision
        )
        was_confirmed = self._is_knowledge_op_confirmed(op_key)
        res = self.knowledge.apply(
            op_key, "entity", title, payload, ident=record_id, expected=expected_revision
        )
        sdk_fp = _canonical_fingerprint(
            {
                "op": "register_entity",
                "title": title,
                "payload": payload,
                "record_id": record_id,
                "expected_revision": expected_revision,
            }
        )
        cached = self._load_op_receipt("knowledge", op_key)
        if cached is not None:
            stored_fp, historical_receipt = cached
            if stored_fp != sdk_fp:
                raise Conflict("chave reutilizada para outro pedido")
        else:
            rev = int(res["revision"])
            snap = self._read_knowledge_revision_snapshot(res["id"], rev)
            receipt_body: dict[str, Any] = {
                "status": res["status"],
                "id": res["id"],
                "revision": rev,
                "sha256": snap["sha256"],
                "rev_ref": {"record_id": res["id"], "revision": rev},
                "revision_count_at_operation": rev,
                "operation_key": op_key,
            }
            if expected_revision is not None and rev > 1:
                old_snap = self._read_knowledge_revision_snapshot(res["id"], expected_revision)
                receipt_body["from_revision"] = expected_revision
                receipt_body["to_revision"] = rev
                receipt_body["old_sha256"] = old_snap["sha256"]
                receipt_body["new_sha256"] = snap["sha256"]
            historical_receipt = self._save_op_receipt(
                "knowledge", op_key, sdk_fp, res["id"], rev, receipt_body
            )
        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": self._build_knowledge_current_state(res["id"]),
        }

    def assert_fact(
        self,
        title: str,
        *,
        subject_ref: dict[str, Any],
        predicate: str,
        nature: str = "user_report",
        asserted_by: str = "agent_memory_sdk",
        source_refs: list[dict[str, Any]] | None = None,
        basis_refs: list[dict[str, Any]] | None = None,
        value: dict[str, Any] | None = None,
        object_ref: dict[str, Any] | None = None,
        evidence_quote: str | None = None,
        evidence_source_ref: dict[str, Any] | None = None,
        attribution_resolution_ref: dict[str, Any] | None = None,
        context_description: str = "Registro estruturado via Epistemic Agent Memory SDK",
        valid_time: dict[str, Any] | None = None,
        recorded_time: str | None = None,
        scope_note: str | None = None,
        limitations: list[str] | None = None,
        qualifiers: dict[str, Any] | None = None,
        operation_key: str | None = None,
        record_id: str | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        """Registra uma afirmação em `20_Afirmacoes` impondo o firewall `atribuicao.py`."""
        from atribuicao import AttributionError, owner_id, persons, validate_assertion
        from nucleo import Conflict, Invalid, NOW

        self._check_access()
        if not isinstance(title, str) or not isinstance(predicate, str):
            raise Invalid("title e predicate devem ser strings")
        cleaned_subject = _validate_rev_ref(subject_ref, "subject_ref")

        if nature == "inference":
            if not isinstance(basis_refs, list) or not basis_refs:
                raise Invalid("afirmação de natureza 'inference' exige basis_refs não vazio")
            cleaned_refs = [_validate_rev_ref(r, "basis_ref") for r in basis_refs]
        else:
            if not isinstance(source_refs, list) or not source_refs:
                raise Invalid("afirmação não inferida exige source_refs não vazio")
            cleaned_refs = [_validate_rev_ref(r, "source_ref") for r in source_refs]

        records, _, _ = self.knowledge.catalog()

        prior_rec = (
            self._try_read_record_at_revision(record_id, expected_revision, records)
            if record_id
            else None
        )
        if recorded_time is None:
            if prior_rec is not None:
                recorded_time = prior_rec.get("payload", {}).get("recorded_time")
            if not recorded_time:
                anchor_rec = self._try_read_record_at_revision(
                    cleaned_refs[0]["record_id"], cleaned_refs[0]["revision"], records
                ) or records.get(cleaned_refs[0]["record_id"], {})
                recorded_time = anchor_rec.get("updated_at") or anchor_rec.get("created_at") or NOW()

        existing_payload = (
            prior_rec.get("payload", {})
            if prior_rec is not None
            else (records.get(record_id, {}).get("payload", {}) if record_id else {})
        )
        review_status = existing_payload.get("review_status", "unreviewed")

        payload: dict[str, Any] = {
            "subject_ref": cleaned_subject,
            "predicate": predicate,
            "nature": nature,
            "asserted_by": asserted_by,
            "recorded_time": recorded_time,
            "context_description": context_description,
            "valid_time": copy.deepcopy(valid_time) if valid_time is not None else {"precision": "unknown"},
            "review_status": review_status,
        }
        if "review_events" in existing_payload:
            payload["review_events"] = copy.deepcopy(existing_payload["review_events"])
        if nature == "inference":
            payload["basis_refs"] = cleaned_refs
        else:
            payload["source_refs"] = cleaned_refs

        if value is not None:
            if not isinstance(value, Mapping):
                raise Invalid("value deve ser um dicionário {'type': ..., 'content': ...}")
            _reject_clinical_keys(value)
            payload["value"] = copy.deepcopy(dict(value))
        if object_ref is not None:
            payload["object_ref"] = _validate_rev_ref(object_ref, "object_ref")

        if scope_note is not None:
            payload["scope_note"] = scope_note
        if limitations is not None:
            if not isinstance(limitations, list) or any(not isinstance(x, str) for x in limitations):
                raise Invalid("limitations deve ser uma lista de strings")
            payload["limitations"] = list(limitations)
        if qualifiers is not None:
            if not isinstance(qualifiers, Mapping):
                raise Invalid("qualifiers deve ser um dicionário")
            allowed_qualifiers = {"role", "perspective", "conditions", "scope_note"}
            if set(qualifiers) - allowed_qualifiers:
                raise Invalid("qualifiers contém chaves fora do contrato canônico")
            payload.update(copy.deepcopy(dict(qualifiers)))

        if evidence_quote is not None:
            if not isinstance(evidence_quote, str) or not evidence_quote.strip():
                raise Invalid("evidence_quote deve ser trecho literal não vazio")
            ev_ref = (
                _validate_rev_ref(evidence_source_ref, "evidence_source_ref")
                if evidence_source_ref is not None
                else cleaned_refs[0]
            )
            payload["attribution_evidence"] = {
                "source_ref": {"record_id": ev_ref["record_id"], "revision": ev_ref["revision"]},
                "quote": evidence_quote,
            }

        if attribution_resolution_ref is not None:
            payload["attribution_resolution_ref"] = _validate_rev_ref(
                attribution_resolution_ref, "attribution_resolution_ref"
            )

        _reject_clinical_keys(payload)

        op_key = operation_key or make_operation_key(
            "fact", title.strip(), payload, record_id, expected_revision
        )
        was_confirmed = self._is_knowledge_op_confirmed(op_key)
        attribution_status: str | None = None

        if not was_confirmed:
            # Firewall estrito de atribuição para afirmações pessoais / vinculadas a interlocutor.
            person_catalog = persons(records)
            is_personal = cleaned_subject["record_id"] in person_catalog
            is_speaker_bound = is_personal and nature in (
                "user_report",
                "third_party_report",
                "documented_observation",
            )
            owner = owner_id(self.system_root, records)
            attribution_verdict = validate_assertion(payload, records, owner)
            attribution_status = attribution_verdict.get("status")
            if is_speaker_bound:
                if evidence_quote is None:
                    raise AttributionError(
                        "afirmação sobre pessoa exige evidence_quote literal na fonte primária"
                    )
                if attribution_status not in (
                    "checked_for_known_mentions",
                    "resolved_by_separate_source",
                ):
                    raise AttributionError(
                        attribution_verdict.get("reason", "sujeito não explicitado no trecho"),
                        ambiguous=(attribution_status == "unresolved"),
                    )

        res = self.knowledge.apply(
            op_key, "assertion", title, payload, ident=record_id, expected=expected_revision
        )
        sdk_fp = _canonical_fingerprint(
            {
                "op": "assert_fact",
                "title": title,
                "payload": payload,
                "record_id": record_id,
                "expected_revision": expected_revision,
            }
        )
        cached = self._load_op_receipt("knowledge", op_key)
        if cached is not None:
            stored_fp, historical_receipt = cached
            if stored_fp != sdk_fp:
                raise Conflict("chave reutilizada para outro pedido")
        else:
            rev = int(res["revision"])
            snap = self._read_knowledge_revision_snapshot(res["id"], rev)
            if attribution_status is None:
                hist_records = dict(records)
                for ref_item in cleaned_refs:
                    hist_target = self._try_read_record_at_revision(
                        ref_item["record_id"], ref_item["revision"], records
                    )
                    if hist_target is not None:
                        hist_records[ref_item["record_id"]] = hist_target
                try:
                    owner = owner_id(self.system_root, hist_records)
                    attribution_status = validate_assertion(payload, hist_records, owner).get("status")
                except Exception:
                    attribution_status = None
            receipt_body: dict[str, Any] = {
                "status": res["status"],
                "id": res["id"],
                "revision": rev,
                "sha256": snap["sha256"],
                "rev_ref": {"record_id": res["id"], "revision": rev},
                "attribution_status": attribution_status,
                "revision_count_at_operation": rev,
                "operation_key": op_key,
            }
            if expected_revision is not None and rev > 1:
                old_snap = self._read_knowledge_revision_snapshot(res["id"], expected_revision)
                receipt_body["from_revision"] = expected_revision
                receipt_body["to_revision"] = rev
                receipt_body["old_sha256"] = old_snap["sha256"]
                receipt_body["new_sha256"] = snap["sha256"]
            historical_receipt = self._save_op_receipt(
                "knowledge", op_key, sdk_fp, res["id"], rev, receipt_body
            )
        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": self._build_knowledge_current_state(res["id"]),
        }

    def synthesize(
        self,
        title: str,
        *,
        content: str,
        scope: str,
        basis_refs: list[dict[str, Any]],
        limitations: list[str],
        synthesis_kind: str = "knowledge_summary",
        coverage_status: str = "supported_within_scope",
        as_of: str | None = None,
        operation_key: str | None = None,
        record_id: str | None = None,
        expected_revision: int | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Registra uma síntese derivada em `50_Sinteses` com bases e limitações explícitas."""
        from nucleo import Conflict, Invalid, NOW

        self._check_access()
        if not isinstance(title, str) or not isinstance(content, str) or not content.strip():
            raise Invalid("title e content devem ser strings não vazias")
        if not isinstance(scope, str) or not scope.strip():
            raise Invalid("scope deve ser string não vazia")
        if not isinstance(basis_refs, list) or not basis_refs:
            raise Invalid("basis_refs exige ao menos uma referência versionada")
        if (
            not isinstance(limitations, list)
            or not limitations
            or any(not isinstance(item, str) or not item.strip() for item in limitations)
        ):
            raise Invalid("limitations exige ao menos uma limitação textual explícita")

        cleaned_bases = [_validate_rev_ref(r, "basis_ref") for r in basis_refs]
        records, _, _ = self.knowledge.catalog()
        resolved_as_of = as_of
        if resolved_as_of is None:
            anchor_rec = self._try_read_record_at_revision(
                cleaned_bases[0]["record_id"], cleaned_bases[0]["revision"], records
            ) or records.get(cleaned_bases[0]["record_id"], {})
            resolved_as_of = anchor_rec.get("updated_at") or anchor_rec.get("created_at") or NOW()

        payload: dict[str, Any] = {}
        if extra_fields:
            if not isinstance(extra_fields, Mapping):
                raise Invalid("extra_fields deve ser um dicionário")
            payload.update(copy.deepcopy(dict(extra_fields)))
        _reject_clinical_keys(payload)

        payload.update(
            {
                "synthesis_kind": synthesis_kind,
                "content": content,
                "scope": scope,
                "basis_refs": cleaned_bases,
                "limitations": list(limitations),
                "coverage_status": coverage_status,
                "as_of": resolved_as_of,
            }
        )
        op_key = operation_key or make_operation_key(
            "syn", title.strip(), payload, record_id, expected_revision
        )
        was_confirmed = self._is_knowledge_op_confirmed(op_key)
        res = self.knowledge.apply(
            op_key, "synthesis", title, payload, ident=record_id, expected=expected_revision
        )
        sdk_fp = _canonical_fingerprint(
            {
                "op": "synthesize",
                "title": title,
                "payload": payload,
                "record_id": record_id,
                "expected_revision": expected_revision,
            }
        )
        cached = self._load_op_receipt("knowledge", op_key)
        if cached is not None:
            stored_fp, historical_receipt = cached
            if stored_fp != sdk_fp:
                raise Conflict("chave reutilizada para outro pedido")
        else:
            rev = int(res["revision"])
            snap = self._read_knowledge_revision_snapshot(res["id"], rev)
            receipt_body: dict[str, Any] = {
                "status": res["status"],
                "id": res["id"],
                "revision": rev,
                "sha256": snap["sha256"],
                "rev_ref": {"record_id": res["id"], "revision": rev},
                "revision_count_at_operation": rev,
                "operation_key": op_key,
            }
            if expected_revision is not None and rev > 1:
                old_snap = self._read_knowledge_revision_snapshot(res["id"], expected_revision)
                receipt_body["from_revision"] = expected_revision
                receipt_body["to_revision"] = rev
                receipt_body["old_sha256"] = old_snap["sha256"]
                receipt_body["new_sha256"] = snap["sha256"]
            historical_receipt = self._save_op_receipt(
                "knowledge", op_key, sdk_fp, res["id"], rev, receipt_body
            )
        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": self._build_knowledge_current_state(res["id"]),
        }

    def prepare_decision(
        self,
        title: str,
        *,
        situation: str,
        options: list[dict[str, Any]],
        source_refs: list[dict[str, Any]],
        gaps: list[str] | None = None,
        operation_key: str | None = None,
    ) -> dict[str, Any]:
        """Prepara análise estruturada de apoio à decisão via `apoio_decisao.prepare`."""
        from apoio_decisao import prepare
        from nucleo import Conflict, Invalid

        self._check_access()
        if not isinstance(options, list):
            raise Invalid("options deve ser uma lista de alternativas")
        if not isinstance(source_refs, list) or not source_refs:
            raise Invalid("source_refs exige ao menos uma fonte primária atual")

        cleaned_sources = [_validate_rev_ref(r, "source_ref") for r in source_refs]
        normalized_options: list[dict[str, Any]] = []
        for raw_opt in options:
            if not isinstance(raw_opt, Mapping):
                raise Invalid("cada opção da decisão deve ser um objeto")
            opt = dict(raw_opt)
            if "description" in opt and "descricao" not in opt:
                opt["descricao"] = opt.pop("description")
            if "origin" in opt and "origem" not in opt:
                opt["origem"] = opt.pop("origin")
            if "uncertainties" in opt and "incertezas" not in opt:
                opt["incertezas"] = opt.pop("uncertainties")
            normalized_options.append(opt)

        gaps_list = list(gaps) if gaps is not None else []
        op_key = operation_key or make_operation_key(
            "dec",
            title.strip() if isinstance(title, str) else title,
            situation,
            normalized_options,
            cleaned_sources,
            gaps_list,
            max_length=52,
        )
        sdk_fp = _canonical_fingerprint(
            {
                "op": "prepare_decision",
                "title": title,
                "situation": situation,
                "options": normalized_options,
                "source_refs": cleaned_sources,
                "gaps": gaps_list,
            }
        )
        cached = self._load_op_receipt("decision", op_key)
        if cached is not None:
            stored_fp, historical_receipt = cached
            if stored_fp != sdk_fp:
                raise Conflict("chave reutilizada para outro pedido")
            dec_id = historical_receipt["decision"]["id"]
            ana_id = historical_receipt["analysis"]["id"]
            dec_current = self._build_knowledge_current_state(dec_id)
            ana_current = self._build_knowledge_current_state(ana_id)
            return {
                **copy.deepcopy(historical_receipt),
                "replayed": True,
                "current_state": {
                    **dec_current,
                    "analysis_current_revision": ana_current["current_revision"],
                    "analysis_current_sha256": ana_current["current_sha256"],
                    "analysis_validity": ana_current["validity"],
                },
            }

        sub_keys = [f"{op_key}-decisao", f"{op_key}-analise"] + [
            f"{op_key}-lacuna-{idx}" for idx in range(len(gaps_list))
        ]
        has_extra_gap = self._is_knowledge_op_confirmed(f"{op_key}-lacuna-{len(gaps_list)}")
        was_confirmed = all(self._is_knowledge_op_confirmed(k) for k in sub_keys) and not has_extra_gap

        if has_extra_gap and all(self._is_knowledge_op_confirmed(k) for k in sub_keys):
            raise Conflict("chave reutilizada para outro pedido")

        if was_confirmed:
            reported = [
                opt["descricao"]
                for opt in normalized_options
                if isinstance(opt, Mapping) and opt.get("origem") == "relatada_pelo_usuario"
            ]
            if not reported:
                raise Conflict("chave reutilizada para outro pedido")
            decision_res = self.knowledge.apply(
                f"{op_key}-decisao",
                "entity",
                title,
                {
                    "entity_kind": "decision",
                    "identity_status": "provisional",
                    "origin_refs": cleaned_sources,
                    "situation": situation,
                    "perceived_options": reported,
                    "decision_status": "considering",
                },
            )
            decision_ref = {"record_id": decision_res["id"], "revision": decision_res["revision"]}
            lines = ["Análise provisória fornecida pela IA, ainda não confirmada pelo usuário.", situation]
            for option in normalized_options:
                lines.extend(
                    [
                        "Opção: " + str(option["descricao"]),
                        "Origem: " + str(option["origem"]),
                        "Prós propostos: " + ("; ".join(option["pros"]) or "não informados"),
                        "Contras propostos: " + ("; ".join(option["contras"]) or "não informados"),
                        "Incertezas: " + ("; ".join(option["incertezas"]) or "não informadas"),
                    ]
                )
            if gaps_list:
                lines.append("Lacunas: " + "; ".join(gaps_list))
            src0_snap = self._read_source_revision_snapshot(
                cleaned_sources[0]["record_id"], cleaned_sources[0]["revision"]
            )
            as_of_hist = src0_snap["record"]["updated_at"]
            analysis_res = self.knowledge.apply(
                f"{op_key}-analise",
                "synthesis",
                "Análise — " + title,
                {
                    "synthesis_kind": "knowledge_summary",
                    "content": "\n".join(lines),
                    "scope": "Apoio à decisão; escolha e execução permanecem pendentes.",
                    "basis_refs": cleaned_sources + [decision_ref],
                    "limitations": [
                        "Prós e contras são formulações da IA, não evidência independente.",
                        "Não estima probabilidade de sucesso, diagnóstico ou retorno financeiro.",
                        "Não executa ações externas.",
                    ],
                    "coverage_status": "limited" if gaps_list else "provisional",
                    "as_of": as_of_hist,
                },
            )
            questions_res = []
            for idx, gap in enumerate(gaps_list):
                q_res = self.knowledge.apply(
                    f"{op_key}-lacuna-{idx}",
                    "question",
                    f"Lacuna {idx + 1} — {title}",
                    {
                        "question_text": gap,
                        "purpose": "Esclarecer base da decisão",
                        "trigger_refs": [decision_ref],
                        "information_needed": gap,
                        "impact": "Pode alterar a análise ou viabilidade das opções.",
                        "question_status": "open",
                        "resolution_status": "unresolved",
                    },
                )
                questions_res.append(q_res)
            res = {
                "status": "confirmed",
                "decision": decision_res,
                "analysis": analysis_res,
                "questions": questions_res,
                "choice": "not_made",
                "external_actions": False,
                "limits": "Resultado da ferramenta confirma os registros, não a verdade ou suficiência da análise.",
            }
        else:
            res = prepare(
                self.knowledge,
                op_key,
                title,
                situation,
                normalized_options,
                cleaned_sources,
                gaps_list,
            )
        if res.get("status") != "confirmed":
            return dict(res, operation_key=op_key, replayed=False)

        dec_id = res["decision"]["id"]
        dec_rev = int(res["decision"]["revision"])
        ana_id = res["analysis"]["id"]
        ana_rev = int(res["analysis"]["revision"])
        dec_snap = self._read_knowledge_revision_snapshot(dec_id, dec_rev)
        ana_snap = self._read_knowledge_revision_snapshot(ana_id, ana_rev)
        enriched_questions = []
        for q_item in res.get("questions", []):
            q_snap = self._read_knowledge_revision_snapshot(q_item["id"], int(q_item["revision"]))
            enriched_questions.append({**q_item, "sha256": q_snap["sha256"]})

        receipt_body = {
            **res,
            "id": dec_id,
            "revision": dec_rev,
            "sha256": dec_snap["sha256"],
            "analysis_sha256": ana_snap["sha256"],
            "decision": {**res["decision"], "sha256": dec_snap["sha256"]},
            "analysis": {**res["analysis"], "sha256": ana_snap["sha256"]},
            "questions": enriched_questions,
            "decision_rev_ref": {"record_id": dec_id, "revision": dec_rev},
            "analysis_rev_ref": {"record_id": ana_id, "revision": ana_rev},
            "revision_count_at_operation": dec_rev,
            "operation_key": op_key,
        }
        historical_receipt = self._save_op_receipt(
            "decision", op_key, sdk_fp, dec_id, dec_rev, receipt_body
        )
        dec_current = self._build_knowledge_current_state(dec_id)
        ana_current = self._build_knowledge_current_state(ana_id)
        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": {
                **dec_current,
                "analysis_current_revision": ana_current["current_revision"],
                "analysis_current_sha256": ana_current["current_sha256"],
                "analysis_validity": ana_current["validity"],
            },
        }

    def verify_claims(
        self,
        claims: list[dict[str, Any]],
        *,
        answer: str | None = None,
        answer_format: str = "controlled",
        citations: list[dict[str, Any]] | None = None,
        context_ids: list[str] | None = None,
        max_context: int = 24,
        expected_generation: str | None = None,
        operation_key: str | None = None,
    ) -> dict[str, Any]:
        """Emite e verifica comprovante determinístico `lab-assurance-2` (`field`, `sum`, `chain`)."""
        from evidencias import digest as ev_digest, inspect_response, read_json, safe_folder
        from nucleo import Invalid
        from verificador_evidencias import encode

        self._check_access()
        if not isinstance(claims, list) or not claims or any(not isinstance(c, Mapping) for c in claims):
            raise Invalid("claims exige uma lista não vazia de objetos de alegação")
        if answer_format not in ("controlled", "free_text"):
            raise Invalid("answer_format deve ser 'controlled' ou 'free_text'")

        cleaned_claims: list[dict[str, Any]] = []
        for raw_claim in claims:
            if not {"id", "kind", "refs", "value"} <= set(raw_claim.keys()):
                raise Invalid("cada alegação exige id, kind, refs e value")
            cleaned_claims.append(copy.deepcopy(dict(raw_claim)))

        if answer is None:
            if answer_format == "free_text":
                raise Invalid("answer_format='free_text' exige texto explícito em answer")
            rendered_lines = [
                f"{c['id']} = {encode(c['value']).decode('utf-8')}" for c in cleaned_claims
            ]
            resolved_answer = "\n".join(rendered_lines)
        else:
            if not isinstance(answer, str):
                raise Invalid("answer deve ser string")
            resolved_answer = answer

        draft: dict[str, Any] = {
            "answer_format": answer_format,
            "answer": resolved_answer,
            "claims": cleaned_claims,
        }
        if citations is not None:
            if not isinstance(citations, list):
                raise Invalid("citations deve ser uma lista")
            draft["citations"] = copy.deepcopy(citations)

        op_key = operation_key or make_operation_key("verify", draft, context_ids, max_context)
        pre_ident = ev_digest([self.scope, op_key])
        pre_existed = (safe_folder(self.store, "respostas") / f"{pre_ident}.json").is_file()
        verdict = inspect_response(
            self.store,
            op_key,
            draft,
            context_ids=context_ids,
            max_context=max_context,
            expected_generation=expected_generation,
            scope=self.scope,
        )
        out = dict(verdict, operation_key=op_key, replayed=pre_existed)
        receipt_id = verdict.get("receipt_id")
        if isinstance(receipt_id, str) and receipt_id:
            receipt_path = safe_folder(self.store, "respostas") / f"{receipt_id}.json"
            if receipt_path.is_file():
                saved = read_json(receipt_path)
                packet = saved.get("packet", {})
                out["assurance_format"] = packet.get("format", "lab-assurance-2")
                out["manifest_anchor"] = saved.get("manifest_anchor")
                out["receipt_sha256"] = packet.get("receipt_sha256")
        return out

    def check_attribution(self, answer: str, citations: list[dict[str, Any]]) -> dict[str, Any]:
        """Verifica se um texto narrativo não mistura ou troca sujeitos das citações."""
        from atribuicao import check_answer, owner_id

        self._check_access()
        records, _, _ = self.knowledge.catalog()
        owner = owner_id(self.system_root, records)
        return check_answer(answer, citations, records, owner)

    def register_human_review(
        self,
        assertion_id: str,
        expected_revision: int,
        review_status: str,
        source_ref: dict[str, Any],
        quote: str,
        scope: str,
        *,
        operation_key: str | None = None,
    ) -> dict[str, Any]:
        """Registra confirmação ou contestação humana explícita via `revisoes.register`.

        Intencionalmente restrita à API Python controlada pela interface/operador humano;
        nunca é exposta ao catálogo autônomo de Function Calling de modelos.
        """
        from nucleo import Conflict, Invalid, canon, sha
        from revisoes import register

        self._check_access()
        if type(expected_revision) is not int or expected_revision < 1:
            raise Invalid("expected_revision deve ser inteiro positivo")
        cleaned_src = _validate_rev_ref(source_ref, "source_ref")
        op_key = operation_key or make_operation_key(
            "rev-human", assertion_id, expected_revision, review_status, cleaned_src, quote, scope
        )
        sdk_fp = _canonical_fingerprint(
            {
                "op": "register_human_review",
                "assertion_id": assertion_id,
                "expected_revision": expected_revision,
                "review_status": review_status,
                "source_ref": cleaned_src,
                "quote": quote,
                "scope": scope,
            }
        )
        cached = self._load_op_receipt("human_review", op_key)
        if cached is not None and cached[0] != sdk_fp:
            raise Conflict("chave reutilizada para outro pedido")

        rev_internal_key = sha(
            canon([op_key, assertion_id, expected_revision, review_status, cleaned_src, quote, scope]).encode()
        )
        was_confirmed = self._is_knowledge_op_confirmed(rev_internal_key)
        res = register(
            self.store,
            op_key,
            assertion_id,
            expected_revision,
            review_status,
            cleaned_src,
            quote,
            scope,
        )
        if cached is not None:
            historical_receipt = cached[1]
        else:
            rev = int(res["revision"])
            old_snap = self._read_knowledge_revision_snapshot(res["id"], expected_revision)
            new_snap = self._read_knowledge_revision_snapshot(res["id"], rev)
            historical_receipt = self._save_op_receipt(
                "human_review",
                op_key,
                sdk_fp,
                res["id"],
                rev,
                {
                    **res,
                    "from_revision": expected_revision,
                    "to_revision": rev,
                    "sha256": new_snap["sha256"],
                    "old_sha256": old_snap["sha256"],
                    "new_sha256": new_snap["sha256"],
                    "rev_ref": {"record_id": res["id"], "revision": rev},
                    "revision_count_at_operation": rev,
                    "operation_key": op_key,
                },
            )
        return {
            **copy.deepcopy(historical_receipt),
            "replayed": bool(was_confirmed),
            "current_state": self._build_knowledge_current_state(res["id"]),
        }

    def recall_context(
        self,
        query: str,
        *,
        limit: int = 12,
        depth: int = 1,
        include_records: bool = True,
    ) -> dict[str, Any]:
        """Recupera contexto vigente por RRF híbrido (lexical + ONNX E5 quando ativo + grafo)."""
        from atribuicao import owner_id

        self._check_access()
        raw = copy.deepcopy(self.retrieval.search(query, limit=limit, depth=depth))
        if not include_records:
            raw["results"] = [
                {k: v for k, v in item.items() if k != "record"} for item in raw.get("results", [])
            ]
        records, _, _ = self.knowledge.catalog()
        raw["status"] = "ok"
        raw["embeddings_active"] = self.embedder is not None
        raw["identity_policy"] = {
            "owner_person_id": owner_id(self.system_root, records),
            "before_personal_description": "validar citações literais atuais via verify_claims/check_attribution",
        }
        return raw

    def blast_radius(
        self,
        record_id: str | None = None,
        *,
        include_receipts: bool = True,
    ) -> dict[str, Any]:
        """Lista registros derivados ativos vs suspensos (`needs_revalidation`) e recibos afetados."""
        from conhecimento import refs
        from nucleo import Invalid

        self._check_access()
        records, _, issues = self.knowledge.catalog()
        if record_id is not None:
            if not isinstance(record_id, str) or record_id not in records:
                raise Invalid("registro de origem inexistente no catálogo")

        stale_ids = self.knowledge.stale(records)
        dependents_of: dict[str, list[str]] = {}
        all_edges: list[dict[str, Any]] = []

        for rid in sorted(records):
            rec = records[rid]
            if rec["record_type"] == "source" and "parent_source_ref" not in rec.get("payload", {}):
                continue
            for ref in refs(rec["payload"]):
                dep_id = ref.get("record_id")
                if not isinstance(dep_id, str) or not dep_id:
                    continue
                dependents_of.setdefault(dep_id, [])
                if rid not in dependents_of[dep_id]:
                    dependents_of[dep_id].append(rid)
                target_rev = records.get(dep_id, {}).get("revision")
                pinned_rev = ref.get("revision")
                all_edges.append(
                    {
                        "from": rid,
                        "to": dep_id,
                        "pinned_revision": pinned_rev,
                        "current_revision": target_rev,
                        "outdated": target_rev is None or (pinned_rev is not None and pinned_rev != target_rev),
                    }
                )

        distances: dict[str, int] = {}
        if record_id is not None:
            queue: deque[tuple[str, int]] = deque([(record_id, 0)])
            visited = {record_id}
            while queue:
                current_id, dist = queue.popleft()
                for child_id in sorted(dependents_of.get(current_id, ())):
                    if child_id in visited:
                        continue
                    visited.add(child_id)
                    distances[child_id] = dist + 1
                    queue.append((child_id, dist + 1))
            candidate_ids = sorted(distances, key=lambda cid: (distances[cid], records[cid]["record_type"], cid))
            relevant_nodes = visited
            relevant_edges = [
                edge for edge in all_edges if edge["from"] in relevant_nodes and edge["to"] in relevant_nodes
            ]
            target_rec = records[record_id]
            target_info: dict[str, Any] | None = {
                "id": record_id,
                "title": target_rec["title"],
                "record_type": target_rec["record_type"],
                "revision": target_rec["revision"],
                "validity": "needs_revalidation" if record_id in stale_ids else "current_within_scope",
            }
        else:
            candidate_ids = sorted(
                (rid for rid, rec in records.items() if rec["record_type"] != "source"),
                key=lambda cid: (records[cid]["record_type"], records[cid]["title"], cid),
            )
            relevant_edges = all_edges
            target_info = None

        active_downstream: list[dict[str, Any]] = []
        suspended_downstream: list[dict[str, Any]] = []
        for cid in candidate_ids:
            rec = records[cid]
            is_stale = cid in stale_ids
            entry: dict[str, Any] = {
                "id": cid,
                "title": rec["title"],
                "record_type": rec["record_type"],
                "revision": rec["revision"],
                "validity": "needs_revalidation" if is_stale else "current_within_scope",
            }
            if cid in distances:
                entry["distance"] = distances[cid]
            if is_stale:
                suspended_downstream.append(entry)
            else:
                active_downstream.append(entry)

        verified_receipt_ids: list[str] = []
        stale_receipt_ids: list[str] = []
        if include_receipts:
            for item in self.reverify_receipts(filter_record_id=record_id):
                if item.get("status") == "stale":
                    stale_receipt_ids.append(item["receipt_id"])
                elif item.get("status") in ("verified", "claims_verified"):
                    verified_receipt_ids.append(item["receipt_id"])

        return {
            "status": "ok",
            "target": target_info,
            "active_downstream": active_downstream,
            "suspended_downstream": suspended_downstream,
            "active_ids": [item["id"] for item in active_downstream],
            "suspended_ids": [item["id"] for item in suspended_downstream],
            "total_downstream": len(active_downstream) + len(suspended_downstream),
            "verified_receipt_ids": verified_receipt_ids,
            "stale_receipt_ids": stale_receipt_ids,
            "lineage_edges": relevant_edges,
            "issues": issues,
        }

    def read_source(self, record_id: str) -> dict[str, Any]:
        """Lê diretamente uma fonte primária em `30_Fontes` conferindo SHA-256 e tombstone."""
        self._check_access()
        return self.store.read(record_id)

    def list_sources(self) -> list[dict[str, Any]]:
        """Lista as fontes primárias ativas em `30_Fontes`."""
        self._check_access()
        return self.store.list()

    def read_record(self, record_id: str) -> dict[str, Any]:
        """Lê um registro canônico sinalizando `needs_revalidation` se estiver suspenso."""
        from nucleo import Invalid

        self._check_access()
        if not isinstance(record_id, str) or not record_id.strip():
            raise Invalid("record_id inválido")
        return {"status": "ok", **self.knowledge.read(record_id)}

    def read_receipt(self, receipt_id: str) -> dict[str, Any]:
        """Revalida um comprovante `lab-assurance-2` contra a geração atual do cofre."""
        from evidencias import read_receipt

        self._check_access()
        return read_receipt(self.store, receipt_id, scope=self.scope)

    def reverify_receipts(self, *, filter_record_id: str | None = None) -> list[dict[str, Any]]:
        """Reconfere todos os comprovantes persistidos em `estado/comprovantes/respostas`."""
        from evidencias import read_json, read_receipt

        self._check_access()
        resp_dir = self.system_root / "estado" / "comprovantes" / "respostas"
        if not resp_dir.is_dir():
            return []
        results: list[dict[str, Any]] = []
        for path in sorted(resp_dir.glob("*.json")):
            ident = path.stem
            if filter_record_id is not None:
                saved = read_json(path)
                packet = saved.get("packet", {})
                ev_ids = set(packet.get("evidence", {}).keys())
                ref_ids = {
                    ref.get("record_id")
                    for claim in packet.get("claims", [])
                    for ref in claim.get("refs", [])
                    if isinstance(ref, Mapping)
                } | {
                    cit.get("record_id")
                    for cit in packet.get("citations", [])
                    if isinstance(cit, Mapping)
                }
                if filter_record_id not in (ev_ids | ref_ids):
                    continue
            verdict = read_receipt(self.store, ident, scope=self.scope)
            results.append({"receipt_id": ident, **verdict})
        return results

    def audit(self) -> dict[str, Any]:
        """Executa auditoria estrutural e de vigência sobre o catálogo atual."""
        self._check_access()
        return self.knowledge.audit()

    # ------------------------------------------------------------------
    # LLM Function-Calling Adapter (OpenAI Tools & Gemini Declarations)
    # ------------------------------------------------------------------

    @classmethod
    def as_openai_tools(
        cls,
        *,
        strict: bool = False,
        names: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Exporta as ferramentas governadas no formato `tools` da OpenAI API."""
        selected = cls._select_tool_specs(names)
        tools: list[dict[str, Any]] = []
        for spec in selected:
            fn_def: dict[str, Any] = {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": copy.deepcopy(spec["parameters"]),
            }
            if strict:
                fn_def["strict"] = True
            tools.append({"type": "function", "function": fn_def})
        return tools

    @classmethod
    def as_gemini_declarations(
        cls,
        *,
        names: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Exporta as ferramentas governadas no formato `FunctionDeclaration` do Google Gemini SDK."""
        selected = cls._select_tool_specs(names)
        return [
            {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": _to_gemini_schema(spec["parameters"]),
            }
            for spec in selected
        ]

    @staticmethod
    def _select_tool_specs(names: Sequence[str] | None) -> list[dict[str, Any]]:
        from nucleo import Invalid

        if names is None:
            return list(_TOOL_DEFINITIONS)
        selected: list[dict[str, Any]] = []
        for name in names:
            if name not in _TOOL_MAP:
                raise Invalid(f"ferramenta desconhecida ou não exposta ao modelo: {name}")
            selected.append(_TOOL_MAP[name])
        return selected

    def dispatch_tool_call(
        self,
        name: str,
        arguments: str | bytes | Mapping[str, Any] | None = None,
        *,
        call_id: str | None = None,
        as_json: bool = False,
    ) -> dict[str, Any] | str:
        """Despacha uma chamada de ferramenta de LLM com saída JSON estruturada e código determinístico."""
        try:
            self._check_access()
        except BaseException as exc:
            return self._finalize_tool_envelope(
                self._error_envelope(name, exc, call_id=call_id), as_json=as_json
            )

        if not isinstance(name, str) or name not in _TOOL_MAP:
            return self._finalize_tool_envelope(
                {
                    "ok": False,
                    "status": "unknown_tool",
                    "tool": str(name),
                    "error_code": ErrorCode.UNKNOWN_TOOL,
                    "error": {
                        "code": ErrorCode.UNKNOWN_TOOL,
                        "message": f"Ferramenta não registrada ou vedada ao modelo: {name!r}",
                        "retryable": False,
                        "ambiguous": False,
                    },
                    "result": None,
                    **({"call_id": call_id} if call_id is not None else {}),
                },
                as_json=as_json,
            )

        try:
            parsed_args = self._parse_and_validate_tool_args(name, arguments)
        except ValueError as exc:
            return self._finalize_tool_envelope(
                {
                    "ok": False,
                    "status": "malformed_arguments",
                    "tool": name,
                    "error_code": ErrorCode.MALFORMED_ARGUMENTS,
                    "error": {
                        "code": ErrorCode.MALFORMED_ARGUMENTS,
                        "message": str(exc),
                        "retryable": False,
                        "ambiguous": False,
                    },
                    "result": None,
                    **({"call_id": call_id} if call_id is not None else {}),
                },
                as_json=as_json,
            )

        handler = getattr(self, name)
        try:
            result = handler(**parsed_args)
            envelope: dict[str, Any] = {
                "ok": True,
                "status": result.get("status", "ok") if isinstance(result, Mapping) else "ok",
                "tool": name,
                "error_code": None,
                "result": result,
            }
            if call_id is not None:
                envelope["call_id"] = call_id
        except BaseException as exc:
            envelope = self._error_envelope(name, exc, call_id=call_id)

        return self._finalize_tool_envelope(envelope, as_json=as_json)

    @staticmethod
    def _parse_and_validate_tool_args(
        name: str,
        arguments: str | bytes | Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        def _reject_nonfinite(const: str) -> Any:
            raise ValueError(f"número JSON não finito inválido: {const}")

        if arguments is None:
            parsed: Any = {}
        elif isinstance(arguments, (str, bytes)):
            text = arguments.decode("utf-8") if isinstance(arguments, bytes) else arguments
            if not text.strip():
                parsed = {}
            else:
                try:
                    parsed = json.loads(text, parse_constant=_reject_nonfinite)
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                    raise ValueError(f"JSON de argumentos inválido: {exc}") from exc
        elif isinstance(arguments, Mapping):
            parsed = dict(arguments)
            try:
                json.dumps(parsed, ensure_ascii=False, allow_nan=False)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"argumentos contêm valor não serializável ou NaN/Inf: {exc}") from exc
        else:
            raise ValueError("arguments deve ser string JSON, bytes, mapeamento ou None")

        if not isinstance(parsed, dict):
            raise ValueError("arguments da ferramenta deve representar um objeto JSON")

        spec = _TOOL_MAP[name]["parameters"]
        allowed_props = set(spec.get("properties", {}).keys())
        required_props = set(spec.get("required", ()))

        unknown = set(parsed.keys()) - allowed_props
        if unknown:
            raise ValueError(f"argumentos desconhecidos para {name}: {', '.join(sorted(unknown))}")

        missing = [req for req in sorted(required_props) if req not in parsed or parsed[req] is None]
        if missing:
            raise ValueError(f"argumentos obrigatórios ausentes para {name}: {', '.join(missing)}")

        props_schema = spec.get("properties", {})
        for key, val in parsed.items():
            if val is None:
                continue
            expected_type = props_schema.get(key, {}).get("type")
            if expected_type == "string" and not isinstance(val, str):
                raise ValueError(f"argumento '{key}' exige string")
            if expected_type == "integer" and type(val) is not int:
                raise ValueError(f"argumento '{key}' exige integer estrito")
            if expected_type == "boolean" and type(val) is not bool:
                raise ValueError(f"argumento '{key}' exige boolean")
            if expected_type == "array" and not isinstance(val, list):
                raise ValueError(f"argumento '{key}' exige array")
            if expected_type == "object" and not isinstance(val, Mapping):
                raise ValueError(f"argumento '{key}' exige object")

        return parsed

    @staticmethod
    def _error_envelope(
        name: str,
        exc: BaseException,
        *,
        call_id: str | None = None,
    ) -> dict[str, Any]:
        code, status_label, retryable, ambiguous = _classify_exception(exc)
        envelope: dict[str, Any] = {
            "ok": False,
            "status": status_label,
            "tool": str(name),
            "error_code": code,
            "error": {
                "code": code,
                "message": str(exc),
                "retryable": retryable,
                "ambiguous": ambiguous,
            },
            "result": None,
        }
        if call_id is not None:
            envelope["call_id"] = call_id
        return envelope

    @staticmethod
    def _finalize_tool_envelope(envelope: dict[str, Any], *, as_json: bool) -> dict[str, Any] | str:
        serialized = json.dumps(envelope, ensure_ascii=False, sort_keys=True, allow_nan=False)
        if as_json:
            return serialized
        return json.loads(serialized)
