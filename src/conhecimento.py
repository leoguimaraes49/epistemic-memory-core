"""Extensão de conhecimento: não altera o armazenamento legado de fontes.

A IA fornece extrações explícitas. O serviço valida estrutura e proveniência;
não extrai significado com regras lexicais nem inventa biografia.
"""
import json
import os
import re
import sqlite3
import time
import unicodedata
import uuid
from collections import deque
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
# Este alias adquire conteúdo; mutexes continuam usando nucleo.exclusive, imediato.
from nucleo import Store, Invalid, Conflict, Uncertain, NOW, sha, canon, render, acquire_content as exclusive, read_exclusive, verify_posix_file, _has_visible_text
import esquemas

FOLDERS = {'entity': '10_Entidades', 'assertion': '20_Afirmacoes',
           'synthesis': '50_Sinteses', 'question': '60_Questoes',
           'process_definition': '70_Operacao'}
FOLDERS.update(esquemas.FOLDERS)

PREDICATES = {'participates_in', 'member_of', 'has_relationship_with', 'occurs_at',
              'occurs_during', 'concerns_topic', 'pursues_goal', 'uses_method',
              'implements_decision', 'relates_outcome_to', 'prerequisite_for',
              'reports_preference', 'reports_value', 'reports_feeling',
              'reports_difficulty', 'hypothesized_pattern', 'reports_diagnosis',
              'supports', 'contradicts', 'limits_scope_of'}

def decode(data):
    match = re.match(r'\A---\r?\n(.*?)\r?\n---\r?\n```brain-json\r?\n(.*?)\r?\n```', data.decode('utf-8-sig'), re.S)
    if not match:
        raise Invalid('nota sem envelope canônico')
    header = {}
    for raw_line in match[1].split('\n'):
        line = raw_line[:-1] if raw_line.endswith('\r') else raw_line
        key, sep, value = line.partition(': ')
        if not sep or key in header:
            raise Invalid('cabeçalho inválido')
        header[key] = json.loads(value)
    header['payload'] = json.loads(match[2])
    return header

def refs(payload):
    return esquemas.references(payload)


def _named_refs(payload):
    items = []
    if not isinstance(payload, dict):
        return items
    for name in esquemas.LIST_REFS:
        if name in payload and isinstance(payload[name], list):
            for ref in payload[name]:
                if isinstance(ref, dict) and isinstance(ref.get('record_id'), str) and ref['record_id']:
                    items.append((name, ref))
    for name in esquemas.SINGLE_REFS:
        if name in payload and isinstance(payload[name], dict):
            ref = payload[name]
            if isinstance(ref.get('record_id'), str) and ref['record_id']:
                items.append((name, ref))
    if payload.get('review_status') in ('confirmed_by_user', 'disputed_by_user'):
        events = payload.get('review_events', [])
        if isinstance(events, list) and events and isinstance(events[-1], dict):
            ref = events[-1].get('source_ref')
            if isinstance(ref, dict) and isinstance(ref.get('record_id'), str) and ref['record_id']:
                items.append(('review_events[-1].source_ref', ref))
    return items


def _is_orphan_tmp(name):
    return bool(re.search(r'\.tmp(?:-[A-Za-z0-9_-]+)?\Z', name))


def norm(text):
    return ''.join(c for c in unicodedata.normalize('NFD', text.casefold()) if not unicodedata.combining(c))


def _request_json(value):
    try:return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
    except (TypeError,ValueError,OverflowError,RecursionError) as error:
        raise Invalid('pedido exige JSON válido com números finitos') from error


def _legacy_request(data):
    if data is None:raise Uncertain('proposta antiga sem conteúdo; reconciliação necessária')
    record=decode(data);revision=record['revision']
    if type(revision) is not int or revision<1:raise Invalid('revisão da proposta inválida')
    return {'kind':record['record_type'],'title':record['title'],'payload':record['payload'],
            'id':record['id'] if revision>1 else None,'expected':revision-1 if revision>1 else None}


def _business_key(kind,payload):
    if kind not in ('assessment_response','assessment_score'):return None
    application=payload.get('assessment_ref',{})
    if not isinstance(application,dict) or not isinstance(application.get('record_id'),str) or not application['record_id']:
        return None
    item=payload.get('item_ref',{})
    fragment=item.get('fragment') if isinstance(item,dict) else None
    if kind=='assessment_response' and (not isinstance(fragment,str) or not fragment):return None
    return kind,application['record_id'],fragment if kind=='assessment_response' else ''


class Knowledge:
    def __init__(self, sources=None):
        self.sources = sources or Store()
        self.root, self.vault = self.sources.root, self.sources.vault
        self.db = self.root / 'estado' / 'conhecimento.sqlite3'
        with self.connect() as c:
            c.execute('CREATE TABLE IF NOT EXISTS operations(key TEXT PRIMARY KEY, fingerprint TEXT, status TEXT, path TEXT, data BLOB, result TEXT)')
            c.execute('CREATE TABLE IF NOT EXISTS managed(id TEXT PRIMARY KEY, path TEXT UNIQUE, digest TEXT, revision INTEGER)')
            c.execute('CREATE TABLE IF NOT EXISTS searches(id TEXT PRIMARY KEY, created_at TEXT, query TEXT, result TEXT)')
            c.execute('CREATE TABLE IF NOT EXISTS business_reservations(record_type TEXT NOT NULL, assessment_id TEXT NOT NULL, item_id TEXT NOT NULL, record_id TEXT, PRIMARY KEY(record_type,assessment_id,item_id))')
            c.execute('CREATE TABLE IF NOT EXISTS prepared_requests(key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, request TEXT, review_authorized INTEGER NOT NULL DEFAULT 0)')

    @contextmanager
    def connect(self):
        c = sqlite3.connect(self.db, timeout=15)
        c.execute('PRAGMA synchronous=FULL')
        try:
            with c: yield c
        finally: c.close()

    def _load_db_state(self):
        with self.connect() as c:
            managed_rows = c.execute('SELECT id, path, digest, revision FROM managed').fetchall()
            proposed_rows = c.execute("SELECT path, data, result FROM operations WHERE status='proposed'").fetchall()
        managed_map = {row[0]: row[2] for row in managed_rows}
        managed_by_path = {
            unicodedata.normalize('NFC', row[1].replace('\\', '/')): (row[0], row[2], row[3])
            for row in managed_rows if isinstance(row[1], str)
        }
        proposed_by_path = {}
        proposed_meta_by_path = {}
        for op_path, op_data, op_result in proposed_rows:
            if isinstance(op_path, str):
                norm_op_path = unicodedata.normalize('NFC', op_path.replace('\\', '/'))
                proposed_by_path.setdefault(norm_op_path, []).append(op_data)
                try:
                    parsed_res = json.loads(op_result) if op_result else {}
                except (ValueError, TypeError):
                    parsed_res = {}
                proposed_meta_by_path.setdefault(norm_op_path, []).append(parsed_res)
        return managed_rows, managed_map, managed_by_path, proposed_by_path, proposed_meta_by_path

    def catalog(self, recovering=None):
        records, paths, issues = {}, {}, []
        # Fontes são lidas pela autoridade já existente: hash, revisão e tombstone.
        sources_loader = getattr(self.sources, 'read_all', None)
        if sources_loader is not None:
            for record in sources_loader():
                records[record['id']] = record
        else:
            for item in self.sources.list():
                record = self.sources.read(item['id'])
                records[record['id']] = record
        managed_rows, managed_map, managed_by_path, proposed_by_path, proposed_meta_by_path = self._load_db_state()
        for kind, folder in FOLDERS.items():
            directory = self.vault / folder
            if directory.is_symlink() or not directory.resolve().is_relative_to(self.vault):
                raise Invalid('pasta de conhecimento redirecionada')
            for path in directory.glob('*.md'):
                if path.is_symlink():
                    raise Invalid('nota redirecionada')
                rel_path = unicodedata.normalize('NFC', path.relative_to(self.vault).as_posix())
                path_owner = managed_by_path.get(rel_path)
                pending_list = proposed_by_path.get(rel_path)
                try:
                    data = read_exclusive(path); record = decode(data)
                except FileNotFoundError:
                    continue
                except (Invalid, ValueError, KeyError, TypeError):
                    if path_owner is not None:
                        raise Conflict('edição externa de conhecimento')
                    if pending_list:
                        metas = proposed_meta_by_path.get(rel_path, [])
                        if (recovering is not None and len(metas) == 1
                                and isinstance(metas[0], dict)
                                and metas[0].get('id') == recovering
                                and metas[0].get('revision') == 1):
                            continue
                        raise Conflict('criação de conhecimento ainda não confirmada; reconciliar antes de usar')
                    issues.append({'file': path.name, 'reason': 'formato não reconhecido'})
                    continue
                ident = record.get('id')
                if not isinstance(ident, str) or not ident:
                    if path_owner is not None:
                        raise Conflict('edição externa de conhecimento')
                    if pending_list:
                        raise Conflict('criação de conhecimento ainda não confirmada; reconciliar antes de usar')
                    issues.append({'file': path.name, 'reason': 'formato não reconhecido'})
                    continue
                actual_sha = sha(data)
                known_digest = managed_map.get(ident)
                # Evita falso Conflict por leitura entre o fechamento do arquivo e o commit no SQLite em outro processo.
                if recovering is None and ((known_digest is None and pending_list) or (known_digest is not None and known_digest != actual_sha)):
                    time.sleep(0.025)
                    managed_rows, managed_map, managed_by_path, proposed_by_path, proposed_meta_by_path = self._load_db_state()
                    path_owner = managed_by_path.get(rel_path)
                    pending_list = proposed_by_path.get(rel_path)
                    known_digest = managed_map.get(ident)
                if path_owner is not None and path_owner[0] != ident:
                    raise Conflict('identidade divergente no caminho controlado')
                if ident in records:
                    raise Conflict('identidade duplicada no cofre')
                if known_digest is None and pending_list and recovering != ident:
                    raise Conflict('criação de conhecimento ainda não confirmada; reconciliar antes de usar')
                if known_digest is not None and known_digest != actual_sha:
                    if recovering != ident:
                        raise Conflict('edição externa ou efeito pendente; reconciliar antes de usar')
                    if not pending_list or not any(op_data == data for op_data in pending_list):
                        raise Conflict('edição externa de conhecimento')
                records[ident] = record; paths[ident] = path
        for m_id, m_path, _, _ in managed_rows:
            norm_m_path = unicodedata.normalize('NFC', m_path.replace('\\', '/'))
            found_path = paths.get(m_id)
            if found_path is None or unicodedata.normalize('NFC', found_path.relative_to(self.vault).as_posix()) != norm_m_path:
                raise Conflict('arquivo de conhecimento ausente ou movido externamente; reconciliar antes de usar')
        return records, paths, issues

    def _validate(self, kind, payload, records, current_id=None, *, review_authorized=False):
        if kind not in FOLDERS or not isinstance(payload, dict):
            raise Invalid('família ou payload inválido')
        if len(_request_json(payload)) > 20000: raise Invalid('payload excede limite')
        if kind=='assertion' or 'review_events' in payload or 'review_status' in payload:
            esquemas.validate_review(payload,records,current_id,review_authorized=review_authorized)
        absent=payload.get('field_states',{})
        if not isinstance(absent,dict) or any(not isinstance(key,str) or value not in ('unknown','not_asked','not_applicable','declined') or key in payload and payload[key] is not None for key,value in absent.items()):
            raise Invalid('ausência explícita não pode contradizer um valor informado')
        for key in ('origin_refs','source_refs','basis_refs','trigger_refs','answer_refs','opposing_refs','alternative_refs','dependency_refs','resolution_refs','personal_basis_refs','external_basis_refs','pattern_basis_refs'):
            if key in payload and not isinstance(payload[key],list): raise Invalid('lista de referências inválida')
        for ref in refs(payload):
            if not isinstance(ref, dict) or ref.get('record_id') not in records:
                raise Invalid('referência inexistente')
            target = records[ref['record_id']]
            historical=(kind=='question' and ref in payload.get('trigger_refs',[]) and type(ref.get('revision')) is int and 1<=ref['revision']<=target['revision'])
            if type(ref.get('revision')) is not int or (ref['revision'] != target['revision'] and not historical):
                raise Conflict('referência precisa da revisão atual explícita')
            if ref['record_id'] == current_id:
                raise Invalid('derivação de si próprio não permitida')
        if kind != 'question' and any(r['record_id'] in self.stale(records) for r in refs(payload)):
            raise Conflict('base indireta precisa de revalidação')
        if kind in esquemas.FOLDERS:
            esquemas.validate(kind,payload,records,current_id)
            return
        required = {
            'entity': ['entity_kind', 'origin_refs', 'identity_status'],
            'assertion': ['subject_ref', 'predicate', 'nature', 'asserted_by', 'recorded_time', 'context_description', 'valid_time', 'review_status'],
            'synthesis': ['synthesis_kind', 'content', 'scope', 'basis_refs', 'limitations', 'coverage_status', 'as_of'],
            'question': ['question_text', 'purpose', 'trigger_refs', 'information_needed', 'impact', 'question_status', 'resolution_status'],
            'process_definition': ['process_key','purpose','triggers','input_contract','output_contract','preconditions','allowed_effects','calls','stop_conditions','failure_modes','resource_limits','basis_refs','acceptance_criteria','adoption_status']
        }[kind]
        if any(key not in payload or payload[key] is None for key in required):
            raise Invalid('campos obrigatórios ausentes')
        if kind == 'entity' and (not payload['origin_refs'] or payload['identity_status'] not in ('provisional','identified','ambiguous','merged')):
            raise Invalid('entidade precisa de origem e identidade')
        if kind == 'entity':
            if payload['identity_status']=='merged':
                dest=payload.get('merged_into_ref')
                if not dest or records.get(dest.get('record_id'),{}).get('record_type')!='entity' or not payload.get('identity_change_reason'):
                    raise Invalid('fusão exige destino, origem e motivo explícitos')
            subtypes={'person':['display_name'],'group':['display_name'],'organization':['display_name'],'place':['display_name'],'life_period':['period_description','time'],'experience':['event_description','occurred_time'],'decision':['situation','perceived_options','decision_status'],'action':['action_description','action_status'],'outcome':['outcome_description','observation_kind','observed_time','source_refs'],'goal':['desired_outcome','goal_status'],'project':['purpose','project_status'],'task':['task_description','task_status'],'habit':['behavior_description','context_description','pattern_basis_refs'],'learning_topic':['topic_description'],'study_method':['method_description'],'study_session':['topic_refs','session_status'],'idea':['content','idea_scope'],'concept':['content','idea_scope'],'recommendation':['suggestion','purpose','personal_basis_refs','limitations','recommendation_status'],'trial':['recommendation_ref','trial_description','trial_status']}
            subtype=payload['entity_kind']
            if subtype not in subtypes or any(k not in payload for k in subtypes[subtype]):
                raise Invalid('subtipo ou campos da entidade incompatíveis com o catálogo')
        if kind == 'assertion':
            if payload['predicate'] not in PREDICATES or ('value' in payload) == ('object_ref' in payload):
                raise Invalid('predicado ou alvo inválido')
            esquemas.validate_relation(payload,records)
            if 'value' in payload and (not isinstance(payload['value'],dict) or 'type' not in payload['value'] or 'content' not in payload['value']):
                raise Invalid('valor precisa de tipo e conteúdo')
            if payload['predicate']=='pursues_goal':
                if 'object_ref' not in payload or records[payload['object_ref']['record_id']]['payload'].get('entity_kind')!='goal':
                    raise Invalid('objetivo precisa de uma entidade goal')
            if payload['nature'] not in ('user_report','third_party_report','documented_observation','instrument_result','inference'):
                raise Invalid('natureza inválida')
            base = payload.get('basis_refs') if payload['nature'] == 'inference' else payload.get('source_refs')
            if not base:
                raise Invalid('afirmação sem base')
            if payload['nature'] != 'inference' and any(records[r['record_id']]['record_type'] not in (('source','assessment_score') if payload['nature']=='instrument_result' else ('source',)) for r in base):
                raise Invalid('relato exige fonte primária')
            if payload['predicate'] == 'reports_diagnosis' and payload['nature'] not in ('user_report','documented_observation'):
                raise Invalid('instrumento ou inferência não cria diagnóstico')
            if payload['nature']=='inference' and payload['predicate'].startswith('reports_'):
                raise Invalid('inferência não pode se apresentar como relato pessoal')
        if kind == 'assertion':
            from atribuicao import validate_assertion,owner_id,AttributionError
            attribution=validate_assertion(payload,records,owner_id(self.sources.root,records))
            if payload.get('attribution_evidence') and attribution['status']=='unresolved':
                raise AttributionError('sujeito não explicitado no trecho',ambiguous=True)
        if kind == 'question' and payload['question_status'] == 'answered' and not payload.get('answer_refs'):
            raise Invalid('questão respondida exige fonte de resposta')
        if kind == 'question' and (payload['question_status'] not in ('open','awaiting_answer','answered','deferred','closed_without_answer') or payload['resolution_status'] not in ('unresolved','partially_resolved','resolved')):
            raise Invalid('estado de questão inválido')
        if kind == 'question' and payload['resolution_status']=='resolved' and not payload.get('resolution_refs'):
            raise Invalid('resolução exige base própria além da resposta')
        if kind == 'synthesis' and payload['coverage_status'] not in ('provisional','supported_within_scope','limited','conflicting','needs_revalidation'):
            raise Invalid('estado de cobertura inválido')
        if kind in ('synthesis','process_definition') and not payload['basis_refs']:
            raise Invalid('derivação sem bases')
        if kind == 'process_definition' and payload['adoption_status'] != 'candidate':
            raise Invalid('uma proposta não pode se autoaprovar ou ampliar permissões')

    def _pending_requests(self, kind):
        """Inspeciona o diário, não o cofre: também funciona após efeito ainda não confirmado."""
        with self.connect() as c:
            rows=c.execute("SELECT o.key,o.data,p.request FROM operations o LEFT JOIN prepared_requests p ON p.key=o.key WHERE o.status='proposed' UNION ALL SELECT p.key,NULL,p.request FROM prepared_requests p LEFT JOIN operations o ON o.key=p.key WHERE o.key IS NULL ORDER BY 1").fetchall()
        result=[]
        for key,data,serialized in rows:
            request=json.loads(serialized) if serialized is not None else _legacy_request(data)
            if request['kind']==kind:result.append((key,request))
        return result

    def _resume(self, key, *, review_authorized=False):
        with self.connect() as c:
            op=c.execute('SELECT fingerprint,status,data,result FROM operations WHERE key=?',(key,)).fetchone()
            prepared=c.execute('SELECT fingerprint,request,review_authorized FROM prepared_requests WHERE key=?',(key,)).fetchone()
        if not op and not prepared:return None
        if prepared and prepared[2] and not review_authorized:
            raise Invalid('operação humana exige a rota de revisão autorizada')
        if op and op[1]=='confirmed':return json.loads(op[3])
        request=json.loads(prepared[1]) if prepared and prepared[1] is not None else _legacy_request(op[2] if op else None)
        fingerprint=sha(_request_json(request).encode())
        if (op and fingerprint!=op[0]) or (prepared and fingerprint!=prepared[0]):
            raise Uncertain('pedido antigo não pode ser reconstruído exatamente; repetir pedido original')
        return self._apply_prepared(key,request,review_authorized)

    def _apply_prepared(self, key, request, review_authorized):
        try:
            return self.apply(key,request['kind'],request['title'],request['payload'],request['id'],request['expected'],
                              review_authorized=review_authorized)
        except (Invalid,Conflict):
            # Rejeição antes de existir proposta não deve imobilizar um planejamento já inválido.
            with self.connect() as c:
                c.execute('BEGIN IMMEDIATE')
                c.execute('DELETE FROM prepared_requests WHERE key=? AND NOT EXISTS(SELECT 1 FROM operations WHERE key=?)',(key,key))
            raise

    def _frozen_apply(self, key, kind, title, payload, ident=None, expected=None, *, review_authorized=False):
        """Wrappers internos congelam o pedido antes do efeito, inclusive seus timestamps."""
        request={'kind':kind,'title':title,'payload':payload,'id':ident,'expected':expected}
        serialized=_request_json(request)
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            op=c.execute('SELECT fingerprint,status,data,result FROM operations WHERE key=?',(key,)).fetchone()
            prepared=c.execute('SELECT fingerprint,request,review_authorized FROM prepared_requests WHERE key=?',(key,)).fetchone()
            if prepared and prepared[2] and not review_authorized:
                raise Invalid('operação humana exige a rota de revisão autorizada')
            if op and op[1]=='confirmed':return json.loads(op[3])
            if prepared:
                if prepared[1] is None:raise Uncertain('pedido congelado indisponível')
                frozen=json.loads(prepared[1])
                if any(_request_json(frozen[name])!=_request_json(request[name]) for name in ('kind','title','id','expected')):
                    raise Conflict('operação congelada pertence a outro pedido')
                request=frozen
            else:
                if op:
                    request=_legacy_request(op[2]);serialized=_request_json(request)
                    if sha(serialized.encode())!=op[0]:raise Uncertain('pedido antigo não pode ser reconstruído exatamente')
                c.execute('INSERT INTO prepared_requests VALUES(?,?,?,?)',(key,sha(serialized.encode()),serialized,int(review_authorized)))
        return self._apply_prepared(key,request,review_authorized)

    def _sync_business_reservations(self, c, records):
        """Índice aditivo: legados e todas as propostas reservam a chave, não só arquivos presentes."""
        owners={}
        entries=list(records.values())+[decode(row[0]) for row in c.execute("SELECT data FROM operations WHERE status='proposed' AND data IS NOT NULL")]
        for record in entries:
            key=_business_key(record['record_type'],record['payload'])
            if key is not None:owners.setdefault(key,set()).add(record['id'])
        c.execute('DELETE FROM business_reservations')
        for key,identifiers in sorted(owners.items()):
            # NULL bloqueia colisões legadas sem escolher nem modificar uma das identidades.
            owner=next(iter(identifiers)) if len(identifiers)==1 else None
            c.execute('INSERT INTO business_reservations VALUES(?,?,?,?)',(*key,owner))

    def _reserve_business(self, c, kind, payload, ident):
        key=_business_key(kind,payload)
        if key is None:
            if kind in ('assessment_response','assessment_score'):raise Invalid('chave de negócio da avaliação inválida')
            return
        row=c.execute('SELECT record_id FROM business_reservations WHERE record_type=? AND assessment_id=? AND item_id=?',key).fetchone()
        if row and row[0]!=ident:raise Conflict('chave de avaliação já reservada por outra identidade ou proposta')
        if not row:c.execute('INSERT INTO business_reservations VALUES(?,?,?,?)',(*key,ident))

    def _replay_records(self, c, records, result, expected):
        records=dict(records);ident=result['id']
        known=c.execute('SELECT digest,revision FROM managed WHERE id=?',(ident,)).fetchone()
        if result['revision']==1:
            if known:raise Conflict('criação pendente já possui outra confirmação')
            records.pop(ident,None)
            return records,None
        if not known or known[1]!=expected:raise Conflict('revisão anterior mudou desde a proposta')
        current=records.get(ident)
        if current is None:raise Conflict('registro pendente indisponível')
        if current['revision']==result['revision']:
            archive=self.root/'estado'/'conhecimento_revisoes'/ident/(str(expected)+'.md')
            if archive.is_symlink() or not archive.resolve().is_relative_to(self.root) or not archive.is_file():
                raise Conflict('revisão examinada indisponível para replay')
            previous=archive.read_bytes()
            if sha(previous)!=known[0]:raise Conflict('revisão examinada divergiu do histórico')
            current=decode(previous)
            records[ident]=current
        if current.get('id')!=ident or current.get('revision')!=expected:
            raise Conflict('revisão examinada não corresponde ao pedido')
        return records,ident

    def apply(self, key, kind, title, payload, ident=None, expected=None, *, review_authorized=False):
        """review_authorized é capacidade interna da revisão humana, nunca um campo vindo do modelo."""
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', key)
                or not _has_visible_text(title) or len(title) > 120 or any(x in title for x in '[]|#')):
            raise Invalid('chave ou título inválido')
        if type(review_authorized) is not bool or review_authorized and kind!='assertion':
            raise Invalid('autorização de revisão interna inválida')
        request = {'kind': kind, 'title': title, 'payload': payload, 'id': ident, 'expected': expected}
        serialized=_request_json(request)
        fingerprint = sha(serialized.encode())
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            prior = c.execute('SELECT fingerprint,status,path,data,result FROM operations WHERE key=?', (key,)).fetchone()
            prepared=c.execute('SELECT fingerprint,review_authorized FROM prepared_requests WHERE key=?',(key,)).fetchone()
            if prepared:
                if prepared[0]!=fingerprint:raise Conflict('chave reutilizada para outro pedido congelado')
                if prepared[1] and not review_authorized:raise Invalid('operação humana exige a rota de revisão autorizada')
            if prior:
                if fingerprint != prior[0]: raise Conflict('chave reutilizada para outro pedido')
                if prior[1] == 'confirmed': return json.loads(prior[4])
                path, data, result = self.vault / prior[2], prior[3], json.loads(prior[4])
                records, _, _ = self.catalog(recovering=result['id'])
                validation_records,current_id=self._replay_records(c,records,result,expected)
                self._validate(kind,payload,validation_records,current_id,review_authorized=review_authorized)
                self._sync_business_reservations(c,records)
                self._reserve_business(c,kind,payload,result['id'])
            else:
                records, paths, _ = self.catalog()
                self._validate(kind,payload,records,ident,review_authorized=review_authorized)
                self._sync_business_reservations(c,records)
                if ident:
                    pending = [r['record_id'] for r in esquemas.derivation_refs(payload)]; visited = set()
                    while pending:
                        dependency = pending.pop()
                        if dependency == ident: raise Invalid('ciclo de derivação ou referência não permitido nesta extensão')
                        if dependency in visited: continue
                        visited.add(dependency)
                        pending.extend(r['record_id'] for r in esquemas.derivation_refs(records[dependency]['payload']))
                now = NOW()
                if ident:
                    with self.connect() as read:
                        managed = read.execute('SELECT path,digest,revision FROM managed WHERE id=?', (ident,)).fetchone()
                    if not managed: raise Invalid('registro legado não pode ser sobrescrito por esta extensão')
                    if type(expected) is not int or managed[2] != expected: raise Conflict('revisão esperada não corresponde')
                    record = records[ident]
                    if record['record_type'] != kind: raise Invalid('família não pode mudar')
                    path = paths[ident]; record['revision'] += 1; record['updated_at'] = now
                else:
                    ident = str(uuid.uuid4())
                    from nucleo import filename
                    directory = self.vault / FOLDERS[kind]; directory.mkdir(parents=True,exist_ok=True)
                    reserved=[PurePosixPath(row[0].replace('\\', '/')).name for row in c.execute("SELECT path FROM operations WHERE status!='confirmed'").fetchall()
                              if row[0] and PurePosixPath(row[0].replace('\\', '/')).parent.as_posix()==FOLDERS[kind]]
                    existing_names = [f.name for f in directory.iterdir() if not _is_orphan_tmp(f.name)] + reserved
                    path = directory / filename(title, ident, existing_names)
                    record = {'id':ident,'record_type':kind,'schema_version':'0.1','revision':1,'title':title,'created_at':now,'updated_at':now,'created_by':'extensao_conhecimento','access_policy_ref':'proprietario_local','lifecycle_status':'active','payload_format':'brain_json_v1'}
                self._reserve_business(c,kind,payload,ident)
                record['title'] = title; record['payload'] = payload
                data = self._render(record, records, paths)
                result = {'status':'confirmed','id':ident,'revision':record['revision']}
                c.execute('INSERT INTO operations VALUES(?,?,?,?,?,?)', (key,fingerprint,'proposed',path.relative_to(self.vault).as_posix(),data,json.dumps(result)))
            if not prepared:
                c.execute('INSERT INTO prepared_requests VALUES(?,?,?,?)',(key,fingerprint,serialized,int(review_authorized)))
        # Um pedido proposto pode ser retomado, mas efeitos parciais nunca são sucesso.
        with self.connect() as c:
            c.execute('BEGIN IMMEDIATE')
            op = c.execute('SELECT status FROM operations WHERE key=?',(key,)).fetchone()
            if op[0] == 'confirmed': return result
            known = c.execute('SELECT digest,revision FROM managed WHERE id=?',(result['id'],)).fetchone()
            with exclusive(path, create=not path.exists()) as stream:
                fd = stream.fileno()
                old = stream.read()
                if old != data:
                    if result['revision'] == 1 and old: raise Uncertain('arquivo inesperado em criação')
                    if result['revision'] > 1 and (not known or known[1] != expected or sha(old) != known[0]): raise Conflict('registro mudou; não sobrescrito')
                    if old:
                        hist = self.root / 'estado' / 'conhecimento_revisoes' / result['id']; hist.mkdir(parents=True,exist_ok=True)
                        archive = hist / (str(expected)+'.md')
                        if archive.exists() and archive.read_bytes() != old: raise Conflict('histórico divergente')
                        if not archive.exists():
                            tmp_arc = hist / f'{expected}.md.tmp-{uuid.uuid4().hex}'
                            try:
                                tmp_arc.write_bytes(old)
                                os.replace(tmp_arc, archive)
                            except BaseException:
                                if tmp_arc.exists():
                                    try: tmp_arc.unlink()
                                    except OSError: pass
                                raise
                    if os.name != 'nt':
                        verify_posix_file(path, fd, old)
                    stream.seek(0); stream.write(data); stream.truncate(); stream.flush(); os.fsync(fd)
                if os.name != 'nt':
                    verify_posix_file(path, fd, data)
            c.execute('INSERT OR REPLACE INTO managed VALUES(?,?,?,?)',(result['id'],path.relative_to(self.vault).as_posix(),sha(data),result['revision']))
            c.execute("UPDATE operations SET status='confirmed',data=NULL WHERE key=?",(key,))
            c.execute('UPDATE prepared_requests SET request=NULL WHERE key=?',(key,))
        return result

    def _render(self, record, records, paths):
        links = []
        for ref in refs(record['payload']):
            target = records[ref['record_id']]
            if ref['record_id'] in paths:
                path = paths[ref['record_id']]
            else:
                with self.sources.connect() as c:
                    filename = c.execute('SELECT filename FROM records WHERE id=?',(ref['record_id'],)).fetchone()[0]
                path = self.sources.folder / filename
            links.append('[['+path.relative_to(self.vault).with_suffix('').as_posix()+']]')
        return render(record) + ('\n## Navegação derivada\n\n'+'\n'.join('- '+x for x in dict.fromkeys(links))+'\n').encode('utf-8')

    def stale(self, records):
        invalid = {ident for ident,record in records.items() if record['payload'].get('score_validity_status') in ('invalid','needs_revalidation') or record['payload'].get('coverage_status')=='needs_revalidation'}
        for ident, record in records.items():
            if record['record_type'] == 'source': continue
            for ref in refs(record['payload']):
                if record['record_type']=='question' and ref in record['payload'].get('trigger_refs',[]):continue
                other = records.get(ref.get('record_id'))
                if not other or ('revision' in ref and ref['revision'] != other['revision']): invalid.add(ident)
        for _ in range(len(records)):
            new = {i for i,n in records.items() if any(r.get('record_id') in invalid for r in refs(n['payload']))}
            if new <= invalid: break
            invalid |= new
        return invalid

    def audit(self):
        records, _, issues = self.catalog()
        return {'status':'ok','records':len(records),'needs_revalidation':sorted(self.stale(records)),'issues':issues,
                'limits':['índice reconstruído na consulta','esta auditoria verifica estrutura e vigência; recuperação vetorial é executada pela busca','sem validação clínica','sem execução autônoma de código proposto']}

    def read(self, ident):
        records, _, _ = self.catalog()
        if ident not in records: raise Invalid('registro inexistente')
        if ident in self.stale(records):
            return {'record':None,'validity':'needs_revalidation','reason':'Conteúdo derivado suspenso até revalidar bases corrigidas ou indisponíveis.'}
        return {'record':records[ident],'validity':'current_within_scope'}

    def lineage(self, record_id: str) -> dict:
        if not isinstance(record_id, str) or not record_id.strip():
            raise Invalid('registro inexistente')
        records, paths, issues = self.catalog()
        if record_id not in records:
            raise Invalid('registro inexistente')
        stale_ids = self.stale(records)
        source_digests = {}
        tombstoned_ids = set()
        sources_connect = getattr(self.sources, 'connect', None)
        if sources_connect is not None:
            with sources_connect() as sc:
                source_digests = {r[0]: r[1] for r in sc.execute('SELECT id, digest FROM records').fetchall()}
                tombstoned_ids = {r[0] for r in sc.execute('SELECT record_id FROM tombstones').fetchall()}
        with self.connect() as kc:
            managed_digests = {r[0]: r[1] for r in kc.execute('SELECT id, digest FROM managed').fetchall()}

        integrity_cache = {}
        def _integrity(ident):
            if ident in integrity_cache:
                return integrity_cache[ident]
            rec = records.get(ident)
            if rec is None:
                res = (None, None, False)
            else:
                rec_sha = sha(_request_json(rec).encode('utf-8'))
                if rec['record_type'] == 'source':
                    if ident in source_digests:
                        res = (source_digests[ident], rec_sha, True)
                    else:
                        res = (rec_sha, rec_sha, True)
                elif ident in paths:
                    raw = read_exclusive(paths[ident])
                    file_sha = sha(raw)
                    expected_sha = managed_digests.get(ident)
                    res = (file_sha, rec_sha, (file_sha == expected_sha) if expected_sha is not None else True)
                else:
                    res = (rec_sha, rec_sha, True)
            integrity_cache[ident] = res
            return res

        outgoing = {}
        incoming = {}
        for ident, rec in sorted(records.items()):
            edges_out = []
            for field, ref in _named_refs(rec.get('payload', {})):
                target_id = ref['record_id']
                pinned_rev = ref.get('revision') if type(ref.get('revision')) is int else None
                edges_out.append((target_id, field, pinned_rev))
                if target_id in records:
                    incoming.setdefault(target_id, []).append((ident, field, pinned_rev))
            outgoing[ident] = edges_out

        # Upstream BFS (record -> bases)
        up_hop = {}
        up_pins = {}
        up_edges = []
        seen_up_edges = set()
        q = deque([(record_id, 0)])
        while q:
            cur, dist = q.popleft()
            for tgt_id, field, pinned_rev in outgoing.get(cur, ()):
                tgt_rec = records.get(tgt_id)
                cur_rev = tgt_rec['revision'] if tgt_rec is not None else None
                rev_ok = cur_rev is not None and pinned_rev == cur_rev
                edge_key = (cur, tgt_id, field, pinned_rev)
                if edge_key not in seen_up_edges:
                    seen_up_edges.add(edge_key)
                    up_edges.append({
                        'from': cur,
                        'to': tgt_id,
                        'field': field,
                        'pinned_revision': pinned_rev,
                        'current_revision': cur_rev,
                        'revision_valid': rev_ok,
                        'outdated': not rev_ok,
                    })
                if tgt_id != record_id:
                    if pinned_rev is not None:
                        up_pins.setdefault(tgt_id, []).append(pinned_rev)
                    else:
                        up_pins.setdefault(tgt_id, [])
                    if tgt_id not in up_hop:
                        up_hop[tgt_id] = dist + 1
                        if tgt_rec is not None:
                            q.append((tgt_id, dist + 1))

        # Downstream BFS (dependents -> record)
        down_hop = {}
        down_edges = []
        seen_down_edges = set()
        q = deque([(record_id, 0)])
        while q:
            cur, dist = q.popleft()
            for dep_id, field, pinned_rev in incoming.get(cur, ()):
                cur_rec = records.get(cur)
                cur_rev = cur_rec['revision'] if cur_rec is not None else None
                rev_ok = cur_rev is not None and pinned_rev == cur_rev
                edge_key = (dep_id, cur, field, pinned_rev)
                if edge_key not in seen_down_edges:
                    seen_down_edges.add(edge_key)
                    down_edges.append({
                        'from': dep_id,
                        'to': cur,
                        'field': field,
                        'pinned_revision': pinned_rev,
                        'current_revision': cur_rev,
                        'revision_valid': rev_ok,
                        'outdated': not rev_ok,
                    })
                if dep_id != record_id and dep_id not in down_hop:
                    down_hop[dep_id] = dist + 1
                    q.append((dep_id, dist + 1))

        # 3-color iterative DFS cycle detection (distinguishes genuine directed cycles from diamond DAGs)
        cycle_edges = []
        seen_cycles = set()
        def _detect_cycles(adj_fn, direction):
            color = {}
            stack = [(record_id, 0)]
            color[record_id] = 1
            while stack:
                node, idx = stack[-1]
                neighbors = adj_fn(node)
                if idx < len(neighbors):
                    stack[-1] = (node, idx + 1)
                    nxt = neighbors[idx]
                    st = color.get(nxt, 0)
                    if st == 1:
                        ck = (node, nxt, direction)
                        if ck not in seen_cycles:
                            seen_cycles.add(ck)
                            cycle_edges.append({'from': node, 'to': nxt, 'direction': direction})
                    elif st == 0 and nxt in records:
                        color[nxt] = 1
                        stack.append((nxt, 0))
                else:
                    color[node] = 2
                    stack.pop()

        _detect_cycles(lambda n: [t for t, _, _ in outgoing.get(n, ())], 'upstream')
        _detect_cycles(lambda n: [d for d, _, _ in incoming.get(n, ())], 'downstream')

        upstream_all = []
        for uid, hop in sorted(up_hop.items(), key=lambda kv: (kv[1], kv[0])):
            urec = records.get(uid)
            u_sha, u_rec_sha, u_sha_valid = _integrity(uid)
            cur_rev = urec['revision'] if urec is not None else None
            pins_raw = up_pins.get(uid, [])
            pinned_revs = sorted(set(pins_raw))
            mismatches = [r for r in pins_raw if cur_rev is None or r != cur_rev]
            chosen_pin = mismatches[0] if mismatches else (pins_raw[0] if pins_raw else None)
            rev_valid = (urec is not None and bool(pinned_revs) and all(r == cur_rev for r in pinned_revs))
            is_src = (urec is not None and urec['record_type'] == 'source') or (urec is None and uid in tombstoned_ids)
            upstream_all.append({
                'id': uid,
                'title': urec['title'] if urec is not None else None,
                'record_type': urec['record_type'] if urec is not None else ('source' if uid in tombstoned_ids else 'unknown'),
                'folder': '30_Fontes' if is_src else (FOLDERS.get(urec['record_type']) if urec is not None else None),
                'hop': hop,
                'direct': hop == 1,
                'pinned_revision': chosen_pin,
                'pinned_revisions': pinned_revs,
                'current_revision': cur_rev,
                'revision_valid': rev_valid,
                'outdated': not rev_valid,
                'sha256': u_sha,
                'record_sha256': u_rec_sha,
                'sha256_valid': u_sha_valid,
                'status': ('excluded' if uid in tombstoned_ids else 'missing' if urec is None
                           else 'suspended' if uid in stale_ids else 'active'),
                'validity': ('unavailable' if urec is None
                             else 'needs_revalidation' if uid in stale_ids else 'current_within_scope'),
            })

        upstream_direct = [item for item in upstream_all if item['hop'] == 1]
        upstream_transitive = [item for item in upstream_all if item['hop'] >= 2]
        upstream_sources = [item for item in upstream_all if item['record_type'] == 'source']
        upstream_intermediate = [item for item in upstream_all if item['record_type'] != 'source']

        downstream_all = []
        for did, hop in sorted(down_hop.items(), key=lambda kv: (kv[1], kv[0])):
            drec = records[did]
            d_sha, d_rec_sha, d_sha_valid = _integrity(did)
            is_stale = did in stale_ids
            downstream_all.append({
                'id': did,
                'title': drec['title'],
                'record_type': drec['record_type'],
                'folder': '30_Fontes' if drec['record_type'] == 'source' else FOLDERS.get(drec['record_type']),
                'revision': drec['revision'],
                'hop': hop,
                'direct': hop == 1,
                'status': 'suspended' if is_stale else 'active',
                'validity': 'needs_revalidation' if is_stale else 'current_within_scope',
                'sha256': d_sha,
                'record_sha256': d_rec_sha,
                'sha256_valid': d_sha_valid,
            })

        downstream_active = [item for item in downstream_all if item['status'] == 'active']
        downstream_suspended = [item for item in downstream_all if item['status'] == 'suspended']
        downstream_direct = [item for item in downstream_all if item['hop'] == 1]
        downstream_transitive = [item for item in downstream_all if item['hop'] >= 2]

        target_rec = records[record_id]
        t_sha, t_rec_sha, t_sha_valid = _integrity(record_id)
        t_stale = record_id in stale_ids
        return {
            'status': 'ok',
            'record_id': record_id,
            'target': {
                'id': record_id,
                'title': target_rec['title'],
                'record_type': target_rec['record_type'],
                'folder': '30_Fontes' if target_rec['record_type'] == 'source' else FOLDERS.get(target_rec['record_type']),
                'revision': target_rec['revision'],
                'status': 'suspended' if t_stale else 'active',
                'validity': 'needs_revalidation' if t_stale else 'current_within_scope',
                'lifecycle_status': target_rec.get('lifecycle_status', 'active'),
                'sha256': t_sha,
                'record_sha256': t_rec_sha,
                'sha256_valid': t_sha_valid,
                'created_at': target_rec.get('created_at'),
                'updated_at': target_rec.get('updated_at'),
            },
            'upstream': {
                'direct': upstream_direct,
                'transitive': upstream_transitive,
                'all': upstream_all,
                'sources': upstream_sources,
                'intermediate': upstream_intermediate,
                'edges': up_edges,
                'counts': {
                    'total': len(upstream_all),
                    'direct': len(upstream_direct),
                    'transitive': len(upstream_transitive),
                    'sources': len(upstream_sources),
                    'intermediate': len(upstream_intermediate),
                    'outdated': sum(1 for item in upstream_all if item['outdated']),
                },
            },
            'downstream': {
                'active': downstream_active,
                'suspended': downstream_suspended,
                'direct': downstream_direct,
                'transitive': downstream_transitive,
                'all': downstream_all,
                'edges': down_edges,
                'counts': {
                    'total': len(downstream_all),
                    'direct': len(downstream_direct),
                    'transitive': len(downstream_transitive),
                    'active': len(downstream_active),
                    'suspended': len(downstream_suspended),
                },
            },
            'blast_radius': {
                'total_dependents': len(downstream_all),
                'direct_count': len(downstream_direct),
                'transitive_count': len(downstream_transitive),
                'active_count': len(downstream_active),
                'suspended_count': len(downstream_suspended),
                'active_ids': [item['id'] for item in downstream_active],
                'suspended_ids': [item['id'] for item in downstream_suspended],
                'active': downstream_active,
                'suspended': downstream_suspended,
            },
            'cycles_detected': bool(cycle_edges),
            'cycle_edges': cycle_edges,
            'issues': issues,
            'limits': [
                'Linhagem determinística baseada nas revisões e hashes registrados; não certifica veracidade factual nem diagnóstico.'
            ],
        }

    def search(self, query, limit=12, depth=1):
        if (not isinstance(query, str) or not query.strip() or len(query)>500
                or type(limit) is not int or not 1<=limit<=50
                or type(depth) is not int or not 0<=depth<=2):
            raise Invalid('busca fora dos limites')
        records, _, issues = self.catalog(); tokens=set(re.findall(r'\w+',norm(query)))
        stale=self.stale(records)
        ranked=[]
        for ident,record in records.items():
            if ident in stale: continue
            words=set(re.findall(r'\w+',norm(record['title']+' '+canon(record['payload']))))
            score=len(tokens & words)
            if score: ranked.append((score,ident))
        ranked.sort(key=lambda pair:(-pair[0],pair[1])); ordered=[i for _,i in ranked[:limit]]
        selected=set(ordered);frontier=set(selected)
        for _ in range(depth):
            related=set()
            for ident,record in records.items():
                targets={r.get('record_id') for r in refs(record['payload'])}
                if ident in stale: continue
                if ident in frontier: related |= (targets & records.keys()) - stale
                if targets & frontier: related.add(ident)
            additions=sorted(related-selected)[:max(0,limit-len(selected))]
            ordered.extend(additions);selected.update(additions);frontier=set(additions)
        stale=self.stale(records)
        result={'status':'ok','mode':'lexical_and_graph','results':[{'id':i,'title':records[i]['title'],'revision':records[i]['revision'],'record_type':records[i]['record_type'],'validity':'current_within_scope'} for i in ordered],'issues':issues,'complete':False,'stop_reason':'bounded_retrieval','limits':'Sem vetores; relevância e suficiência exigem avaliação da IA.'}
        ident=str(uuid.uuid4());result['search_id']=ident
        with self.connect() as c:c.execute('INSERT INTO searches VALUES(?,?,?,?)',(ident,NOW(),query,canon(result)))
        return result

    def contribution(self, key, title, original, extractions):
        """Entrega parcial explícita; repetir o mesmo pedido retoma sem duplicar."""
        if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,60}',key) or not isinstance(extractions,list) or len(extractions)>20:
            raise Invalid('pedido de contribuição fora dos limites')
        for item in extractions:
            if not isinstance(item,dict) or not {'tipo','titulo','payload'} <= item.keys():raise Invalid('extração incompleta')
        source=self.sources.apply(key+'-fonte','create',title=title,text=original)
        mapping={'$fonte':{'record_id':source['id'],'revision':source['revision']}}
        completed=[]
        def resolve(value):
            if isinstance(value,dict):
                if value.get('record_id') in mapping:
                    rev=value.get('revision',1)
                    if type(rev) is not int or rev!=1:raise Invalid('revisão de placeholder inválida')
                    return dict(value,**mapping[value['record_id']])
                return {k:resolve(v) for k,v in value.items()}
            if isinstance(value,list):return [resolve(x) for x in value]
            return value
        for index,item in enumerate(extractions):
            try:
                record=self.apply(key+'-'+str(index),item['tipo'],item['titulo'],resolve(item['payload']))
                mapping['$'+str(index)]={'record_id':record['id'],'revision':record['revision']};completed.append(record)
            except (Invalid,Conflict,Uncertain,ValueError,KeyError,TypeError,OSError,sqlite3.Error) as e:
                return {'status':'partial','source':source,'completed':completed,'pending_from':index,'reason':str(e)}
        return {'status':'confirmed','source':source,'completed':completed,'limits':'extração fornecida pela IA; não há leitura automática de pensamento nem garantia de completude'}
