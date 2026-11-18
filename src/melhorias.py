"""Ajustes delimitados com avaliação determinística, intenções retomáveis e auditoria de cadeia."""
import array,copy,json,math,os,re,stat,sys
from pathlib import Path
from contextlib import contextmanager
from nucleo import Invalid,Conflict,NOW,sha,canon
from conhecimento import Knowledge
from autonomia import atomic_json


KEY_PATTERN=r'[A-Za-z0-9_-]{1,80}'
PHASES=('adopt_intent','adopt_config','adopt_candidate','adopted',
        'rollback_intent','rollback_config','rollback_candidate','rolled_back')
ADOPTABLE_KINDS=('message_codec','retrieval_policy','vector_storage','batch_limits')
VECTOR_STORAGE_FORMATS=('packed_f64','packed_f32','json')
BATCH_LIMIT_BOUNDS={'max_actions':(1,64),'max_model_calls':(0,16),'max_seconds':(1,3600)}
CANDIDATE_METADATA={
    'message_codec':{
        'purpose':'Avaliar ajuste sem perda do conteúdo',
        'acceptance_criteria':['preservar o pacote completo','melhorar custo medido','manter contratos'],
        'rollback_plan':'Restaurar configuração anterior registrada.',
    },
    'retrieval_policy':{
        'purpose':'Alinhar política de recuperação aos canais ativos sem perda lexical',
        'acceptance_criteria':['preservar âncoras lexicais exatas','melhorar revocação ou eliminar sobrecarga sem canal semântico ativo','manter permissões inalteradas'],
        'rollback_plan':'Restaurar retrieval_policy anterior registrada.',
    },
    'vector_storage':{
        'purpose':'Compactar vetores locais preservando precisão IEEE-754 de 64 bits',
        'acceptance_criteria':['preservar dimensão e finitude numérica','roundtrip exato sem perda de precisão','reduzir bytes armazenados mantendo permissões'],
        'rollback_plan':'Restaurar embeddings.vector_storage anterior registrada.',
    },
    'batch_limits':{
        'purpose':'Delimitar exposição máxima por demanda preservando fluxos canônicos',
        'acceptance_criteria':['manter viabilidade integral dos perfis canônicos','reduzir exposição operacional máxima','nunca ampliar franquia de modelo ou permissões'],
        'rollback_plan':'Restaurar limites operacionais anteriores registrados.',
    },
}
_RETRIEVAL_DOCS=(
    {'id':'doc-insonia','tokens':('relato','insonia','despertar','noturno'),'vec':(0.95,0.20,0.10,0.21)},
    {'id':'doc-fadiga','tokens':('exaustao','persistente','amanhecer','corpo'),'vec':(0.15,0.96,0.12,0.20)},
    {'id':'doc-estudo','tokens':('registro','estudo','espacado','revisao'),'vec':(0.10,0.12,0.97,0.18)},
    {'id':'doc-ruido','tokens':('nota','administrativa','calendario','anual'),'vec':(0.05,0.08,0.09,0.99)},
)
_RETRIEVAL_QUERIES=(
    {'tokens':('insonia','despertar'),'vec':(0.96,0.18,0.08,0.19),'expected':'doc-insonia','lexical_anchor':True},
    {'tokens':('fadiga','matinal'),'vec':(0.14,0.97,0.10,0.18),'expected':'doc-fadiga','lexical_anchor':False},
    {'tokens':('estudo','espacado'),'vec':(0.09,0.11,0.98,0.15),'expected':'doc-estudo','lexical_anchor':True},
)


def _validate_key(key):
    if not isinstance(key,str) or not re.fullmatch(KEY_PATTERN,key):raise Invalid('chave de operação inválida')


def _safe_path(sources,*parts,create_parent=False):
    root=Path(sources.root).absolute()
    if not root.is_dir():raise Invalid('raiz de estado inexistente')
    paths=[root];path=root
    for part in parts:
        if not isinstance(part,str) or part in ('','.','..') or '/' in part or '\\' in part or Path(part).anchor:
            raise Invalid('caminho de estado inválido')
        path=path/part;paths.append(path)
    def check():
        for item in paths:
            try:
                info=item.lstat()
            except FileNotFoundError:info=None
            if item.is_symlink() or getattr(item,'is_junction',lambda:False)() or (info and getattr(info,'st_file_attributes',0)&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',0x400)):
                raise Invalid('caminho de estado redirecionado')
            try:resolved=item.resolve()
            except (OSError,RuntimeError) as error:raise Invalid('caminho de estado não resolvido') from error
            if resolved!=item or not resolved.is_relative_to(root):raise Invalid('caminho fora da raiz de estado')
    check()
    if create_parent:
        path.parent.mkdir(parents=True,exist_ok=True);check()
    return path


@contextmanager
def _state_lock(sources,namespace='adocoes'):
    _validate_key(namespace)
    path=_safe_path(sources,'estado',namespace+'.lock',create_parent=True)
    flags=os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0)
    with os.fdopen(os.open(path,flags,0o600),'r+b') as stream:
        _safe_path(sources,'estado',namespace+'.lock')
        opened=os.fstat(stream.fileno());named=path.stat()
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
            raise Invalid('arquivo de bloqueio mudou')
        if not opened.st_size:stream.write(b'\0');stream.flush()
        if os.name=='nt':
            import msvcrt
            def acquire():
                stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_NBLCK,1)
            def unlock():
                stream.seek(0);msvcrt.locking(stream.fileno(),msvcrt.LK_UNLCK,1)
        else:
            import fcntl
            def acquire():fcntl.flock(stream.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            def unlock():fcntl.flock(stream.fileno(),fcntl.LOCK_UN)
        try:acquire()
        except OSError as error:raise Conflict('outra operação de estado está em andamento') from error
        try:yield
        finally:unlock()


def _read_json(path):
    value=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value,dict):raise Invalid('estado JSON inválido')
    return value


def _same(left,right):return canon(left)==canon(right)


def _valid_batch_limits_value(value):
    if not isinstance(value,dict) or not value or set(value)-set(BATCH_LIMIT_BOUNDS):
        return False
    for name,number in value.items():
        low,high=BATCH_LIMIT_BOUNDS[name]
        if type(number) is not int or not low<=number<=high:
            return False
    return True


def _validated_config(raw):
    # config() só recebe um arquivo; validar a proposta em memória evita gravá-la para testá-la.
    from execucao import DEFAULT
    if not isinstance(raw,dict) or set(raw)-set(DEFAULT):raise Invalid('opção de execução não reconhecida')
    try:json.dumps(raw,allow_nan=False)
    except (TypeError,ValueError) as error:raise Invalid('configuração não JSON') from error
    cfg=copy.deepcopy(DEFAULT);cfg.update(copy.deepcopy(raw))
    for name,low,high in (('max_actions',1,64),('max_model_calls',0,16),('max_seconds',1,3600)):
        if type(cfg[name]) is not int or not low<=cfg[name]<=high:raise Invalid('limite de execução inválido: '+name)
    for name in ('enabled','auto_process_sources','auto_adopt_config'):
        if type(cfg[name]) is not bool:raise Invalid('permissão de execução inválida: '+name)
    for name in ('model','embeddings'):
        if not isinstance(cfg[name],dict) or type(cfg[name].get('enabled',False)) is not bool:
            raise Invalid('configuração de provedor inválida: '+name)
    if cfg['embeddings'].get('vector_storage','packed_f64') not in VECTOR_STORAGE_FORMATS:
        raise Invalid('formato de armazenamento vetorial desconhecido')
    if cfg['message_codec'] not in ('compact','pretty') or cfg['retrieval_policy'] not in ('hybrid','lexical'):
        raise Invalid('política de comunicação ou recuperação desconhecida')
    if cfg.get('owner_person_id') is not None and (not isinstance(cfg['owner_person_id'],str) or not cfg['owner_person_id'].strip()):
        raise Invalid('identidade do proprietário inválida')
    return cfg


def _apply_config_change(previous,candidate):
    base=_validated_config(previous)
    if not isinstance(candidate,dict):raise Invalid('candidata não elegível')
    following=copy.deepcopy(previous)
    kind=candidate.get('kind');value=candidate.get('value')
    if kind=='message_codec':
        if value not in ('compact','pretty'):raise Invalid('candidata não elegível')
        following['message_codec']=value
    elif kind=='retrieval_policy':
        if value not in ('hybrid','lexical'):raise Invalid('candidata não elegível')
        following['retrieval_policy']=value
    elif kind=='vector_storage':
        if value not in VECTOR_STORAGE_FORMATS:raise Invalid('candidata não elegível')
        emb=copy.deepcopy(following.get('embeddings',{'enabled':False}))
        if not isinstance(emb,dict):raise Invalid('configuração de provedor inválida: embeddings')
        emb['vector_storage']=value
        following['embeddings']=emb
    elif kind=='batch_limits':
        if not _valid_batch_limits_value(value):raise Invalid('candidata não elegível')
        for name,number in value.items():following[name]=number
    else:
        raise Invalid('candidata não elegível')
    after=_validated_config(following)
    for perm in ('enabled','auto_process_sources','auto_adopt_config'):
        if after[perm]!=base[perm]:raise Invalid('intenção não pode alterar permissões de execução')
    for provider in ('model','embeddings'):
        if after[provider].get('enabled',False)!=base[provider].get('enabled',False):
            raise Invalid('intenção não pode habilitar ou alterar permissão de provedor')
    if after.get('owner_person_id')!=base.get('owner_person_id'):
        raise Invalid('intenção não pode alterar identidade do proprietário')
    if after['max_model_calls']>base['max_model_calls']:
        raise Invalid('intenção não pode ampliar franquia de chamadas ao modelo')
    return following


def _config_path(sources):
    direct=_safe_path(sources,'execucao.json')
    if direct.exists():return direct
    nested=_safe_path(sources,'config','execucao.json')
    return nested if nested.exists() else direct


def _read_config(sources,allow_missing=False):
    path=_config_path(sources)
    raw={} if allow_missing and not path.exists() else _read_json(path)
    _validated_config(raw)
    return raw


def _score_retrieval_policy(policy,embeddings_enabled):
    semantic_active=policy=='hybrid' and embeddings_enabled
    hits=0;rr_sum=0.0;anchors_ok=True
    for query in _RETRIEVAL_QUERIES:
        q_tokens=set(query['tokens'])
        lex=sorted([(len(q_tokens&set(doc['tokens'])),doc['id']) for doc in _RETRIEVAL_DOCS if q_tokens&set(doc['tokens'])],
                   key=lambda item:(-item[0],item[1]))
        scores={}
        for rank,(_,doc_id) in enumerate(lex,1):
            scores[doc_id]=scores.get(doc_id,0.0)+1.0/(60+rank)
        if semantic_active:
            sem=sorted([(sum(a*b for a,b in zip(query['vec'],doc['vec'])),doc['id']) for doc in _RETRIEVAL_DOCS],
                       key=lambda item:(-item[0],item[1]))
            for rank,(sim,doc_id) in enumerate((item for item in sem if item[0]>=0.50),1):
                scores[doc_id]=scores.get(doc_id,0.0)+1.0/(60+rank)
        ordered=[doc_id for doc_id,_ in sorted(scores.items(),key=lambda item:(-item[1],item[0]))]
        top=ordered[0] if ordered else None
        if top==query['expected']:hits+=1
        if query['lexical_anchor'] and top!=query['expected']:anchors_ok=False
        if query['expected'] in ordered:
            rr_sum+=1.0/(ordered.index(query['expected'])+1)
    return {
        'hits_at_1':hits,
        'mrr_x1000':round((rr_sum/len(_RETRIEVAL_QUERIES))*1000),
        'lexical_anchors_preserved':anchors_ok,
        'configured_channels':2 if policy=='hybrid' else 1,
        'unbacked_hybrid_channel':bool(policy=='hybrid' and not embeddings_enabled),
    }


def _benchmark_vector(dim=384):
    raw=[((i*73+19)%251-125)/127.0+(1.0/(i+3.0))*1e-6 for i in range(dim)]
    norm=math.sqrt(sum(x*x for x in raw))
    return [x/norm for x in raw]


def _roundtrip_vector(fmt,vector):
    if fmt=='json':
        encoded=canon(vector).encode('utf-8')
        return encoded,json.loads(encoded.decode('utf-8'))
    code='d' if fmt=='packed_f64' else 'f'
    arr=array.array(code,vector)
    if sys.byteorder!='little':arr.byteswap()
    encoded=arr.tobytes()
    out=array.array(code);out.frombytes(encoded)
    if sys.byteorder!='little':out.byteswap()
    return encoded,out.tolist()


def _batch_workloads(model_calls):
    return (
        ('improvement_cycle',4,90),
        ('question_research',5,max(120,model_calls*90+30)),
        ('clarification_resume',16,max(150,model_calls*110+30)),
        ('chunked_contribution',24,max(180,model_calls*130+60)),
    )


def _measure(candidate,current):
    if not isinstance(candidate,dict):raise Invalid('candidata inválida')
    candidate=copy.deepcopy(candidate)
    try:json.dumps(candidate,allow_nan=False)
    except (TypeError,ValueError) as error:raise Invalid('candidata não JSON') from error
    cfg=_validated_config(current)
    kind=candidate.get('kind');value=candidate.get('value')
    config_hash=sha(canon(current).encode())
    if kind=='message_codec' and value in ('compact','pretty'):
        fixture={'version':1,'records':[{'text':'  Texto completo, com exceção e dúvida.\nNão é zero.','unknown':None,
                'revision':2,'origin_refs':[{'record_id':'ficticio','revision':1}]}]}
        encodings={'pretty':json.dumps(fixture,ensure_ascii=False,indent=2),'compact':canon(fixture)}
        previous=cfg['message_codec'];selected=value
        intact=json.loads(encodings[selected])==fixture
        return {'status':'completed','candidate':candidate,'eligible':intact and len(encodings[selected])<len(encodings[previous]),
            'checks':{'roundtrip_equal':intact,'original_text_preserved':json.loads(encodings[selected])['records'][0]['text']==fixture['records'][0]['text']},
            'comparison':{'previous':previous,'selected':selected,'previous_chars':len(encodings[previous]),'selected_chars':len(encodings[selected])},
            'scope':'JSON completo; não é prova de equivalência universal entre respostas de modelos.',
            'previous_config_hash':config_hash}
    if kind=='retrieval_policy' and value in ('hybrid','lexical'):
        previous=cfg['retrieval_policy'];selected=value
        embeddings_enabled=bool(cfg['embeddings'].get('enabled',False))
        prev_m=_score_retrieval_policy(previous,embeddings_enabled)
        sel_m=_score_retrieval_policy(selected,embeddings_enabled)
        improved=(sel_m['hits_at_1']>prev_m['hits_at_1'] or
                  (sel_m['hits_at_1']==prev_m['hits_at_1'] and sel_m['configured_channels']<prev_m['configured_channels']))
        no_regression=(sel_m['hits_at_1']>=prev_m['hits_at_1'] and sel_m['mrr_x1000']>=prev_m['mrr_x1000']
                       and not sel_m['unbacked_hybrid_channel'])
        eligible=bool(selected!=previous and sel_m['lexical_anchors_preserved'] and improved and no_regression)
        return {'status':'completed','candidate':candidate,'eligible':eligible,
            'checks':{'lexical_anchors_preserved':sel_m['lexical_anchors_preserved'],
                      'semantic_channel_backed':not sel_m['unbacked_hybrid_channel'],
                      'permissions_unchanged':True},
            'comparison':{'previous':previous,'selected':selected,'embeddings_enabled':embeddings_enabled,
                          'previous_hits_at_1':prev_m['hits_at_1'],'selected_hits_at_1':sel_m['hits_at_1'],
                          'previous_mrr_x1000':prev_m['mrr_x1000'],'selected_mrr_x1000':sel_m['mrr_x1000'],
                          'previous_channels':prev_m['configured_channels'],'selected_channels':sel_m['configured_channels']},
            'scope':'Benchmark determinístico RRF local; não substitui avaliação em consultas reais do usuário.',
            'previous_config_hash':config_hash}
    if kind=='vector_storage' and value in VECTOR_STORAGE_FORMATS:
        previous=cfg['embeddings'].get('vector_storage','packed_f64');selected=value
        vector=_benchmark_vector(384)
        prev_bytes,_=_roundtrip_vector(previous,vector)
        sel_bytes,sel_decoded=_roundtrip_vector(selected,vector)
        dim_ok=len(sel_decoded)==len(vector)
        finite_ok=all(type(x) in (int,float) and math.isfinite(x) for x in sel_decoded)
        lossless_ok=dim_ok and sel_decoded==vector
        cosine_ok=dim_ok and finite_ok and abs(sum(a*b for a,b in zip(vector,sel_decoded))-1.0)<=1e-12
        eligible=bool(dim_ok and finite_ok and lossless_ok and cosine_ok and len(sel_bytes)<len(prev_bytes))
        return {'status':'completed','candidate':candidate,'eligible':eligible,
            'checks':{'dimension_preserved':dim_ok,'all_finite':finite_ok,
                      'lossless_roundtrip':lossless_ok,'cosine_preserved':cosine_ok,
                      'permissions_unchanged':True},
            'comparison':{'previous':previous,'selected':selected,'dimensions':len(vector),
                          'previous_bytes':len(prev_bytes),'selected_bytes':len(sel_bytes)},
            'scope':'Vetor IEEE-754 local de 384 dimensões; não habilita embeddings nem altera modelo.',
            'previous_config_hash':config_hash}
    if kind=='batch_limits' and _valid_batch_limits_value(value):
        prev_limits={name:cfg[name] for name in ('max_actions','max_model_calls','max_seconds')}
        sel_limits=dict(prev_limits);sel_limits.update(value)
        prev_workloads=_batch_workloads(prev_limits['max_model_calls'])
        sel_workloads=_batch_workloads(sel_limits['max_model_calls'])
        prev_viable=sum(1 for _,act,sec in prev_workloads if prev_limits['max_actions']>=act and prev_limits['max_seconds']>=sec)
        sel_viable=sum(1 for _,act,sec in sel_workloads if sel_limits['max_actions']>=act and sel_limits['max_seconds']>=sec)
        min_calls=min(prev_limits['max_model_calls'],3) if cfg['model'].get('enabled',False) else 0
        repair_viable=sel_limits['max_model_calls']>=min_calls
        model_not_expanded=sel_limits['max_model_calls']<=prev_limits['max_model_calls']
        limits_not_expanded=all(sel_limits[name]<=prev_limits[name] for name in ('max_actions','max_model_calls','max_seconds'))
        workloads_viable=sel_viable==len(sel_workloads) and repair_viable
        prev_exposure=prev_limits['max_actions']*100+prev_limits['max_seconds']+prev_limits['max_model_calls']*500
        sel_exposure=sel_limits['max_actions']*100+sel_limits['max_seconds']+sel_limits['max_model_calls']*500
        eligible=bool(workloads_viable and model_not_expanded and limits_not_expanded and sel_exposure<prev_exposure)
        return {'status':'completed','candidate':candidate,'eligible':eligible,
            'checks':{'all_workloads_viable':workloads_viable,'model_budget_not_expanded':model_not_expanded,
                      'limits_not_expanded':limits_not_expanded,'permissions_unchanged':True},
            'comparison':{'previous':prev_limits,'selected':sel_limits,'total_workloads':len(sel_workloads),
                          'previous_viable_workloads':prev_viable,'selected_viable_workloads':sel_viable,
                          'previous_exposure':prev_exposure,'selected_exposure':sel_exposure},
            'scope':'Perfis determinísticos de demandas locais; não altera permissões nem habilita provedores.',
            'previous_config_hash':config_hash}
    return {'status':'limited','candidate':candidate,'eligible':False,
            'reason':'Mudança exige um avaliador específico antes da adoção.'}


def _verify_evaluation(evaluation,current):
    if not isinstance(evaluation,dict):raise Invalid('avaliação inválida')
    expected=_measure(evaluation.get('candidate'),current)
    supplied=copy.deepcopy(evaluation);supplied.pop('evaluated_at',None)
    if expected['status']=='completed' and supplied.get('previous_config_hash')!=expected['previous_config_hash']:
        raise Conflict('configuração mudou após a comparação')
    if canon(supplied)!=canon(expected):raise Invalid('avaliação não corresponde ao cálculo determinístico')
    return expected


def evaluate(sources,key,candidate):
    _validate_key(key)
    with _state_lock(sources):
        path=_safe_path(sources,'estado','melhorias',key+'.json',create_parent=True)
        current=_read_config(sources,allow_missing=True);result=_measure(candidate,current)
        if path.exists():
            previous=_read_json(path);verified=_verify_evaluation(previous,current)
            if not _same(verified,result):raise Conflict('chave de avaliação reutilizada para outra candidata')
            return previous
        if result['status']=='completed':
            result['evaluated_at']=NOW();atomic_json(path,result)
        return result


def record(sources,key,evaluation):
    _validate_key(key)
    with _state_lock(sources):
        verified=_verify_evaluation(evaluation,_read_config(sources,allow_missing=True));k=Knowledge(sources)
        text='Resultado técnico de comparação de candidata: '+canon(evaluation)
        source=sources.apply(sha((key+'source').encode()),'create',title='Comparação de melhoria',text=text,
            source_metadata={'source_kind':'tool_output','origin_description':'Avaliador determinístico do serviço',
                             'limitations':['Resultado técnico; não é nova experiência do usuário.']})
        ref={'record_id':source['id'],'revision':source['revision']}
        kind=evaluation.get('candidate',{}).get('kind')
        meta=CANDIDATE_METADATA.get(kind,CANDIDATE_METADATA['message_codec'])
        problem=evaluation.get('candidate',{}).get('reason')
        if not isinstance(problem,str) or not problem.strip():problem='Oportunidade técnica'
        payload={'purpose':meta['purpose'],'problem':problem,
                 'basis_refs':[ref],'acceptance_criteria':copy.deepcopy(meta['acceptance_criteria']),
                 'comparison':copy.deepcopy(evaluation),'comparison_refs':[ref],
                 'adoption_status':'tested' if verified['eligible'] else ('candidate' if verified['status']=='limited' else 'rejected'),
                 'rollback_plan':meta['rollback_plan']}
        result=k.apply(sha((key+'candidate').encode()),'improvement_candidate','Candidata de melhoria',payload)
        return {'status':'confirmed','candidate_record':result,'evaluation':evaluation}


def _candidate(k,ident):
    read=k.read(ident)
    if read['validity']!='current_within_scope':raise Conflict('candidata precisa de revisão')
    record=read['record']
    if record['record_type']!='improvement_candidate' or type(record['revision']) is not int or record['revision']<1:
        raise Invalid('registro não é candidata de melhoria')
    return {name:copy.deepcopy(record[name]) for name in ('id','revision','record_type','title','payload')}


def _next_candidate(snapshot,status):
    result=copy.deepcopy(snapshot);result['revision']+=1;result['payload']['adoption_status']=status
    return result


def _require_candidate(k,expected):
    if canon(_candidate(k,expected['id']))!=canon(expected):raise Conflict('candidata mudou durante a operação')


def _apply_candidate(k,key,snapshot,status):
    expected=_next_candidate(snapshot,status)
    result=k.apply(sha((key+('adopt' if status=='adopted' else 'rollback')).encode()),'improvement_candidate',
        snapshot['title'],expected['payload'],snapshot['id'],snapshot['revision'])
    if result['id']!=expected['id'] or result['revision']!=expected['revision']:raise Conflict('resultado da candidata divergente')
    _require_candidate(k,expected)


def _intent(state):
    return {name:state[name] for name in ('version','candidate_id','before','after','previous_revision','candidate_before')}


def _check_journal(state):
    try:
        if state['version']!=2 or state['intent_hash']!=sha(canon(_intent(state)).encode()):raise Invalid('intenção de adoção divergente')
        snapshot=state['candidate_before'];payload=snapshot['payload']
        if snapshot['id']!=state['candidate_id'] or snapshot['record_type']!='improvement_candidate' or type(snapshot['revision']) is not int or snapshot['revision']<1 or type(state['previous_revision']) is not int or snapshot['revision']!=state['previous_revision'] or payload['adoption_status']!='tested':
            raise Invalid('base da candidata divergente')
        proof=_verify_evaluation(payload['comparison'],state['before'])
        if not proof['eligible']:raise Invalid('candidata não melhora o custo medido')
        try:following=_apply_config_change(state['before'],proof['candidate'])
        except Invalid as error:raise Invalid('intenção altera configuração fora do escopo') from error
        if canon(following)!=canon(state['after']):raise Invalid('intenção altera configuração fora do escopo')
        allowed={'proposed':PHASES[:3],'adopted':('adopted',),'rollback_proposed':PHASES[4:7],'rolled_back':('rolled_back',)}
        if state['phase'] not in allowed.get(state['status'],()):raise Invalid('fase de adoção inválida')
        if state['status'] in ('rollback_proposed','rolled_back'):
            intent=state['rollback_intent'];base=intent['candidate_before']
            original=canon(base)==canon(snapshot);adopted=canon(base)==canon(_next_candidate(snapshot,'adopted'))
            if not (original or adopted) or canon(intent['config_from'])!=canon(state['before'] if original else state['after']) or state['rollback_hash']!=sha(canon(intent).encode()):
                raise Invalid('intenção de reversão divergente')
    except (KeyError,TypeError) as error:raise Invalid('journal de adoção incompleto') from error


def _available(sources,key):
    path=_safe_path(sources,'estado','adocoes-intent.json')
    if not path.exists():return None
    owner=_read_json(path);_validate_key(owner.get('key'))
    if owner['key']==key:return owner
    other=_safe_path(sources,'estado','adocoes',owner['key']+'.json')
    if not other.is_file():raise Conflict('intenção de outra adoção exige conciliação')
    state=_read_json(other);_check_journal(state)
    if owner.get('intent_hash')!=state['intent_hash'] or state['status'] not in ('adopted','rolled_back'):
        raise Conflict('outra adoção ou reversão ainda não foi concluída')
    return owner


def _claim(sources,key,state):
    owner=_available(sources,key)
    desired={'key':key,'intent_hash':state['intent_hash']}
    if owner and owner['key']==key:
        if owner!=desired:raise Conflict('intenção ativa divergente')
    else:atomic_json(_safe_path(sources,'estado','adocoes-intent.json',create_parent=True),desired)


def _release(sources,key,state):
    path=_safe_path(sources,'estado','adocoes-intent.json')
    if path.exists():
        if _read_json(path)!={'key':key,'intent_hash':state['intent_hash']}:raise Conflict('intenção ativa mudou')
        path.unlink()


def _advance(path,state,phase):
    if PHASES.index(state['phase'])>=PHASES.index(phase):return
    state['phase']=phase
    if phase=='adopted':state.update(status='adopted',adopted_at=NOW())
    elif phase=='rolled_back':state.update(status='rolled_back',rolled_back_at=NOW())
    atomic_json(path,state)


def _write_config(sources,expected,following):
    _validated_config(following)
    if canon(_read_config(sources))!=canon(expected):raise Conflict('configuração concorrente não foi sobrescrita')
    atomic_json(_config_path(sources),following)
    if canon(_read_config(sources))!=canon(following):raise Conflict('configuração mudou durante a escrita')


def _upgrade_legacy_dict(raw_state,k,current):
    state=copy.deepcopy(raw_state)
    if state.get('status') not in ('proposed','adopted','rolled_back'):raise Conflict('journal legado exige conciliação manual')
    try:
        snapshot=_candidate(k,state['candidate_id']);revision=state['previous_revision']
        if snapshot['revision']==revision and snapshot['payload']['adoption_status']=='tested' and state['status']=='proposed':pass
        elif snapshot['revision']==revision+1 and snapshot['payload']['adoption_status']=='adopted' and state['status'] in ('proposed','adopted'):
            snapshot['revision']=revision;snapshot['payload']['adoption_status']='tested'
        elif snapshot['revision']==revision+2 and snapshot['payload']['adoption_status']=='rolled_back' and state['status']=='rolled_back':
            snapshot['revision']=revision;snapshot['payload']['adoption_status']='tested'
        else:raise Conflict('candidata legada não permite reconstruir a intenção')
        if not any(_same(current,value) for value in (state['before'],state['after'])) or state['status']=='adopted' and not _same(current,state['after']) or state['status']=='rolled_back' and not _same(current,state['before']):
            raise Conflict('configuração legada exige conciliação manual')
        state.update(version=2,candidate_before=snapshot,phase='adopt_intent' if state['status']=='proposed' else state['status'])
        if state['status']=='rolled_back':
            state['rollback_intent']={'candidate_before':_next_candidate(snapshot,'adopted'),'config_from':copy.deepcopy(state['after'])}
            state['rollback_hash']=sha(canon(state['rollback_intent']).encode())
        state['intent_hash']=sha(canon(_intent(state)).encode());_check_journal(state)
        return state
    except (KeyError,TypeError) as error:raise Invalid('journal legado incompleto') from error


def _load_journal(sources,path,k):
    state=_read_json(path)
    if 'version' not in state:
        # O legado não guardava o payload da intenção. Só reconstruir quando o estado atual o comprova.
        state=_upgrade_legacy_dict(state,k,_read_config(sources))
        atomic_json(path,state)
    _check_journal(state)
    return state


def _resume_adoption(sources,key,path,state,k):
    if state['status'] not in ('proposed','adopted'):raise Conflict('adoção já entrou em reversão; usar nova demanda')
    current=_read_config(sources)
    if not _validated_config(current)['auto_adopt_config']:raise Invalid('adoção de configuração não habilitada')
    if not any(_same(current,value) for value in (state['before'],state['after'])):raise Conflict('configuração concorrente não foi sobrescrita')
    _claim(sources,key,state)
    if state['status']=='adopted':
        if not _same(current,state['after']):raise Conflict('configuração mudou após adoção')
        _require_candidate(k,_next_candidate(state['candidate_before'],'adopted'));_release(sources,key,state)
        return state
    if _same(current,state['before']):
        _require_candidate(k,state['candidate_before']);_write_config(sources,current,state['after'])
    _advance(path,state,'adopt_config')
    # Repetir o pedido congelado também reconcilia Knowledge.apply() interrompido antes da confirmação.
    _apply_candidate(k,key,state['candidate_before'],'adopted')
    _advance(path,state,'adopt_candidate');_advance(path,state,'adopted');_release(sources,key,state)
    return state


def adopt(sources,key,candidate_id):
    _validate_key(key)
    with _state_lock(sources):
        _available(sources,key)
        path=_safe_path(sources,'estado','adocoes',key+'.json',create_parent=True);k=Knowledge(sources)
        if path.exists():
            state=_load_journal(sources,path,k)
            if state['candidate_id']!=candidate_id:raise Conflict('chave de adoção reutilizada')
        else:
            previous=_read_config(sources)
            if not _validated_config(previous)['auto_adopt_config']:raise Invalid('adoção de configuração não habilitada')
            snapshot=_candidate(k,candidate_id);payload=snapshot['payload']
            if payload.get('adoption_status')!='tested':raise Invalid('candidata não testada')
            proof=_verify_evaluation(payload.get('comparison'),previous)
            if not proof['eligible'] or proof['candidate'].get('kind') not in ADOPTABLE_KINDS:raise Invalid('candidata não elegível')
            following=_apply_config_change(previous,proof['candidate'])
            state={'version':2,'status':'proposed','phase':'adopt_intent','candidate_id':candidate_id,
                   'before':previous,'after':following,'previous_revision':snapshot['revision'],
                   'candidate_before':snapshot,'created_at':NOW()}
            state['intent_hash']=sha(canon(_intent(state)).encode());atomic_json(path,state)
        return _resume_adoption(sources,key,path,state,k)


def rollback(sources,key):
    _validate_key(key)
    with _state_lock(sources):
        _available(sources,key)
        path=_safe_path(sources,'estado','adocoes',key+'.json')
        if not path.is_file():raise Invalid('adoção não encontrada')
        k=Knowledge(sources);state=_load_journal(sources,path,k)
        if state['status']=='rolled_back':
            if not _same(_read_config(sources),state['before']):raise Conflict('configuração mudou após reversão')
            _require_candidate(k,_next_candidate(state['rollback_intent']['candidate_before'],'rolled_back'))
            _claim(sources,key,state);_release(sources,key,state);return state
        if state['status']!='rollback_proposed':
            current=_read_config(sources)
            if state['status']=='proposed' and _same(current,state['before']):
                base=state['candidate_before'];_require_candidate(k,base)
            else:
                if not _same(current,state['after']):raise Conflict('configuração mudou; reversão exige conciliação')
                state=_resume_adoption(sources,key,path,state,k);base=_next_candidate(state['candidate_before'],'adopted')
            state['rollback_intent']={'candidate_before':copy.deepcopy(base),'config_from':current}
            state['rollback_hash']=sha(canon(state['rollback_intent']).encode())
            state.update(status='rollback_proposed',phase='rollback_intent');atomic_json(path,state)
        _check_journal(state);_claim(sources,key,state)
        current=_read_config(sources);intent=state['rollback_intent']
        if not any(_same(current,value) for value in (intent['config_from'],state['before'])):raise Conflict('configuração mudou; reversão exige conciliação')
        if not _same(current,state['before']):
            _require_candidate(k,intent['candidate_before']);_write_config(sources,current,state['before'])
        _advance(path,state,'rollback_config');_apply_candidate(k,key,intent['candidate_before'],'rolled_back')
        _advance(path,state,'rollback_candidate');_advance(path,state,'rolled_back');_release(sources,key,state)
        return state


def _solve_transition_chain(completed_entries):
    events=[]
    for entry in completed_entries:
        st=entry['state']
        b_hash=sha(canon(st['before']).encode())
        a_hash=sha(canon(st['after']).encode())
        kind=st['candidate_before']['payload']['comparison']['candidate'].get('kind','unknown')
        created=st.get('created_at') or ''
        if st['status']=='adopted':
            at=st.get('adopted_at') or created
            events.append({'id':len(events),'key':entry['key'],'action':'adopt','kind':kind,
                           'candidate_id':st['candidate_id'],'at':at,
                           'order_hint':(at,created,entry['mtime_ns'],entry['key'],0),
                           'before_hash':b_hash,'after_hash':a_hash,'after_config':st['after'],'depends_on':None})
        elif st['status']=='rolled_back':
            from_cfg=st['rollback_intent']['config_from']
            rb_at=st.get('rolled_back_at') or st.get('adopted_at') or created
            if _same(from_cfg,st['after']):
                ad_at=st.get('adopted_at') or created
                adopt_id=len(events)
                events.append({'id':adopt_id,'key':entry['key'],'action':'adopt','kind':kind,
                               'candidate_id':st['candidate_id'],'at':ad_at,
                               'order_hint':(ad_at,created,entry['mtime_ns'],entry['key'],0),
                               'before_hash':b_hash,'after_hash':a_hash,'after_config':st['after'],'depends_on':None})
                events.append({'id':len(events),'key':entry['key'],'action':'rollback','kind':kind,
                               'candidate_id':st['candidate_id'],'at':rb_at,
                               'order_hint':(rb_at,created,entry['mtime_ns'],entry['key'],1),
                               'before_hash':a_hash,'after_hash':b_hash,'after_config':st['before'],'depends_on':adopt_id})
            else:
                events.append({'id':len(events),'key':entry['key'],'action':'cancel_proposed','kind':kind,
                               'candidate_id':st['candidate_id'],'at':rb_at,
                               'order_hint':(rb_at,created,entry['mtime_ns'],entry['key'],0),
                               'before_hash':b_hash,'after_hash':b_hash,'after_config':st['before'],'depends_on':None})
    if not events:
        return [],None
    out_deg={};in_deg={};nodes=set()
    for ev in events:
        u,v=ev['before_hash'],ev['after_hash']
        nodes.add(u);nodes.add(v)
        out_deg[u]=out_deg.get(u,0)+1
        in_deg[v]=in_deg.get(v,0)+1
    starts=[n for n in nodes if out_deg.get(n,0)-in_deg.get(n,0)==1]
    ends=[n for n in nodes if in_deg.get(n,0)-out_deg.get(n,0)==1]
    bad_degree=any(abs(out_deg.get(n,0)-in_deg.get(n,0))>1 for n in nodes) or len(starts)>1 or len(ends)>1
    ordered_hints=sorted(events,key=lambda item:item['order_hint'])
    if not bad_degree:
        timestamps=sorted({ev['at'] for ev in ordered_hints})
        buckets=[[ev for ev in ordered_hints if ev['at']==ts] for ts in timestamps]
        initial_candidates=starts if len(starts)==1 else list(dict.fromkeys(
            ev['before_hash'] for ev in buckets[0] if ev['depends_on'] is None))
        budget=[5000]
        def walk_bucket(b_idx,remaining,cur_hash,used_ids,acc):
            if budget[0]<=0:return None
            budget[0]-=1
            if not remaining:
                if b_idx+1==len(buckets):return acc
                return walk_bucket(b_idx+1,buckets[b_idx+1],cur_hash,used_ids,acc)
            for pos,ev in enumerate(remaining):
                if ev['before_hash']!=cur_hash:continue
                if ev['depends_on'] is not None and ev['depends_on'] not in used_ids:continue
                nxt=remaining[:pos]+remaining[pos+1:]
                found=walk_bucket(b_idx,nxt,ev['after_hash'],used_ids|{ev['id']},acc+[ev])
                if found is not None:return found
            return None
        for start_hash in initial_candidates:
            solution=walk_bucket(0,buckets[0],start_hash,set(),[])
            if solution is not None:
                return solution,None
    # Localiza o primeiro ponto observável de ruptura para diagnóstico determinístico.
    gap={'code':'broken_chain','key':ordered_hints[0]['key'],
         'detail':'Cadeia histórica de adoções apresenta lacuna ou edição externa intermediária.'}
    for prev_ev,next_ev in zip(ordered_hints,ordered_hints[1:]):
        if prev_ev['after_hash']!=next_ev['before_hash']:
            gap={'code':'broken_chain','key':next_ev['key'],
                 'expected_before_hash':prev_ev['after_hash'],'actual_before_hash':next_ev['before_hash'],
                 'detail':'Cadeia histórica de adoções apresenta lacuna ou edição externa intermediária.'}
            break
    return None,gap


def audit_adoption_chain(sources):
    _safe_path(sources,'execucao.json')
    _safe_path(sources,'config','execucao.json')
    intent_path=_safe_path(sources,'estado','adocoes-intent.json')
    adocoes_dir=_safe_path(sources,'estado','adocoes')
    issues=[]
    try:
        current_raw=_read_config(sources,allow_missing=True)
        config_valid=True
        current_hash=sha(canon(current_raw).encode())
    except (Invalid,ValueError,OSError) as error:
        current_raw=None;config_valid=False;current_hash=None
        issues.append({'code':'invalid_current_config','detail':str(error)})
    active_intent=None
    if intent_path.exists():
        try:
            owner=_read_json(intent_path);_validate_key(owner.get('key'))
            if not isinstance(owner.get('intent_hash'),str) or not owner['intent_hash']:
                raise Invalid('hash de intenção ativa ausente')
            active_intent={'key':owner['key'],'intent_hash':owner['intent_hash']}
        except (Invalid,ValueError,OSError) as error:
            issues.append({'code':'invalid_active_intent','detail':str(error)})
    k=Knowledge(sources)
    entries=[];counts_by_status={};seen_candidates={}
    if adocoes_dir.exists():
        if not adocoes_dir.is_dir():raise Invalid('diretório de adoções inválido')
        for item in sorted(adocoes_dir.iterdir(),key=lambda p:p.name):
            safe_item=_safe_path(sources,'estado','adocoes',item.name)
            if not safe_item.is_file() or not item.name.endswith('.json'):
                issues.append({'code':'unexpected_state_file','file':item.name,
                               'detail':'Arquivo fora do padrão de journal JSON.'})
                continue
            key=item.name[:-5]
            if not re.fullmatch(KEY_PATTERN,key):
                issues.append({'code':'invalid_journal_key','key':key,'detail':'Chave de journal inválida.'})
                continue
            raw_state=None
            try:
                raw_state=_read_json(safe_item)
                if 'version' not in raw_state:
                    if not config_valid:raise Conflict('configuração atual inválida impede reconciliar journal legado')
                    state=_upgrade_legacy_dict(raw_state,k,current_raw)
                else:
                    state=raw_state;_check_journal(state)
            except (Invalid,Conflict,ValueError,OSError) as error:
                issues.append({'code':'invalid_journal','key':key,'detail':str(error)})
                entries.append({'key':key,'valid':False,
                                'status':raw_state.get('status') if isinstance(raw_state,dict) else 'corrupted'})
                continue
            status=state['status']
            counts_by_status[status]=counts_by_status.get(status,0)+1
            cand_id=state['candidate_id']
            if cand_id in seen_candidates:
                issues.append({'code':'duplicate_candidate_journal','key':key,'other_key':seen_candidates[cand_id],
                               'candidate_id':cand_id,'detail':'Mesma candidata referenciada em múltiplos journals.'})
            else:
                seen_candidates[cand_id]=key
            if status in ('proposed','rollback_proposed'):
                issues.append({'code':'incomplete_intent','key':key,'status':status,'phase':state['phase'],
                               'detail':'Operação de adoção ou reversão interrompida antes da conclusão.'})
            try:
                actual_cand=_candidate(k,cand_id)
                if status=='adopted':
                    expected_cand=_next_candidate(state['candidate_before'],'adopted')
                    if not _same(actual_cand,expected_cand):
                        issues.append({'code':'candidate_state_mismatch','key':key,'candidate_id':cand_id,
                                       'detail':'Registro da candidata no catálogo diverge do estado adotado.'})
                elif status=='rolled_back':
                    expected_cand=_next_candidate(state['rollback_intent']['candidate_before'],'rolled_back')
                    if not _same(actual_cand,expected_cand):
                        issues.append({'code':'candidate_state_mismatch','key':key,'candidate_id':cand_id,
                                       'detail':'Registro da candidata no catálogo diverge do estado revertido.'})
            except (Invalid,Conflict,KeyError) as error:
                issues.append({'code':'candidate_invalid_or_missing','key':key,'candidate_id':cand_id,'detail':str(error)})
            entries.append({'key':key,'valid':True,'status':status,'state':state,
                            'mtime_ns':safe_item.stat().st_mtime_ns})
    if active_intent is not None:
        matched=next((e for e in entries if e['key']==active_intent['key'] and e['valid']),None)
        if matched is None:
            issues.append({'code':'orphan_active_intent','key':active_intent['key'],
                           'detail':'Reserva ativa aponta para journal inexistente ou inválido.'})
        elif matched['state']['intent_hash']!=active_intent['intent_hash']:
            issues.append({'code':'active_intent_hash_mismatch','key':active_intent['key'],
                           'detail':'Hash da reserva ativa diverge do journal.'})
        elif matched['status'] in ('adopted','rolled_back'):
            issues.append({'code':'unreleased_active_intent','key':active_intent['key'],
                           'detail':'Reserva ativa permaneceu gravada após conclusão do journal.'})
    structural_clean=all(e['valid'] and e['status'] in ('adopted','rolled_back') for e in entries) and not any(
        i['code']=='duplicate_candidate_journal' for i in issues)
    expected_config_hash=None;config_matches_chain=config_valid;external_drift=False;drifted_keys=[]
    chain_public=[];chain_valid=False
    if structural_clean:
        completed=[e for e in entries if e['valid'] and e['status'] in ('adopted','rolled_back')]
        walk,gap=_solve_transition_chain(completed)
        if gap is not None:
            issues.append(gap)
            config_matches_chain=False
        else:
            chain_valid=True
            chain_public=[{name:ev[name] for name in ('key','action','kind','candidate_id','at','before_hash','after_hash')}
                          for ev in walk]
            if walk:
                expected_cfg=walk[-1]['after_config']
                expected_config_hash=walk[-1]['after_hash']
                if config_valid:
                    config_matches_chain=(current_hash==expected_config_hash)
                    if not config_matches_chain:
                        external_drift=True
                        drifted_keys=sorted(name for name in (set(expected_cfg)|set(current_raw))
                                            if not _same(expected_cfg.get(name),current_raw.get(name)))
                        issues.append({'code':'external_config_drift','key':walk[-1]['key'],
                                       'expected_config_hash':expected_config_hash,'current_config_hash':current_hash,
                                       'drifted_keys':drifted_keys,
                                       'detail':'execucao.json diverge do estado esperado pelo histórico de adoções.'})
                else:
                    config_matches_chain=False
    else:
        config_matches_chain=False
    return {
        'status':'healthy' if not issues else 'degraded',
        'healthy':not issues,
        'config_valid':config_valid,
        'current_config_hash':current_hash,
        'expected_config_hash':expected_config_hash,
        'config_matches_chain':config_matches_chain,
        'external_drift':external_drift,
        'drifted_keys':drifted_keys,
        'chain_valid':chain_valid,
        'journal_count':len(entries),
        'counts_by_status':counts_by_status,
        'active_intent':active_intent,
        'chain':chain_public,
        'issues':issues,
    }


def diagnostics_summary(sources):
    audit=audit_adoption_chain(sources)
    cfg_path=_config_path(sources)
    root=Path(sources.root).absolute()
    rel_cfg=cfg_path.relative_to(root).as_posix()
    if audit['config_valid']:
        raw=_read_config(sources,allow_missing=True)
        cfg=_validated_config(raw)
        config_summary={
            'valid':True,
            'path':rel_cfg,
            'exists':cfg_path.exists(),
            'config_hash':audit['current_config_hash'],
            'auto_adopt_config':cfg['auto_adopt_config'],
            'active_tunables':{
                'message_codec':cfg['message_codec'],
                'retrieval_policy':cfg['retrieval_policy'],
                'vector_storage':cfg['embeddings'].get('vector_storage','packed_f64'),
                'batch_limits':{name:cfg[name] for name in ('max_actions','max_model_calls','max_seconds')},
            },
            'permissions':{
                'enabled':cfg['enabled'],
                'auto_process_sources':cfg['auto_process_sources'],
                'model_enabled':bool(cfg['model'].get('enabled',False)),
                'embeddings_enabled':bool(cfg['embeddings'].get('enabled',False)),
            },
        }
    else:
        raw=None
        config_summary={'valid':False,'path':rel_cfg,'exists':cfg_path.exists(),'config_hash':None}
    melhorias_dir=_safe_path(sources,'estado','melhorias')
    total_evals=0;eligible_now=0;stale_now=0;by_kind={};eval_issues=[]
    if melhorias_dir.exists():
        if not melhorias_dir.is_dir():raise Invalid('diretório de avaliações inválido')
        for item in sorted(melhorias_dir.iterdir(),key=lambda p:p.name):
            safe_item=_safe_path(sources,'estado','melhorias',item.name)
            if not safe_item.is_file() or not item.name.endswith('.json'):
                eval_issues.append({'code':'unexpected_evaluation_file','file':item.name,
                                    'detail':'Arquivo fora do padrão de avaliação JSON.'})
                continue
            key=item.name[:-5]
            if not re.fullmatch(KEY_PATTERN,key):
                eval_issues.append({'code':'invalid_evaluation_key','key':key,'detail':'Chave de avaliação inválida.'})
                continue
            total_evals+=1
            try:
                ev=_read_json(safe_item)
                kind=ev.get('candidate',{}).get('kind','unknown') if isinstance(ev.get('candidate'),dict) else 'unknown'
                by_kind[kind]=by_kind.get(kind,0)+1
                if raw is not None:
                    if ev.get('previous_config_hash')!=audit['current_config_hash']:
                        stale_now+=1
                    else:
                        verified=_verify_evaluation(ev,raw)
                        if verified.get('eligible'):eligible_now+=1
            except (Invalid,Conflict,ValueError,OSError) as error:
                eval_issues.append({'code':'invalid_evaluation','key':key,'detail':str(error)})
    healthy=bool(audit['healthy'] and not eval_issues)
    return {
        'status':'healthy' if healthy else 'degraded',
        'healthy':healthy,
        'checked_at':NOW(),
        'supported_evaluators':list(ADOPTABLE_KINDS),
        'config':config_summary,
        'evaluations':{
            'total':total_evals,
            'eligible_for_current_config':eligible_now,
            'stale_for_current_config':stale_now,
            'invalid_files':len(eval_issues),
            'by_kind':by_kind,
            'issues':eval_issues,
        },
        'adoption_audit':audit,
    }
