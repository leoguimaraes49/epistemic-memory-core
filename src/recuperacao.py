"""Busca lexical, semântica local e grafo; cache vinculado à geração observada."""
import array,hashlib,json,math,sqlite3,struct,sys
from pathlib import Path
from contextlib import contextmanager
from nucleo import Invalid,Conflict,canon,sha,NOW
from conhecimento import Knowledge,refs


def _pack_vector(vector):
    arr=array.array('d',(float(x) for x in vector))
    if sys.byteorder!='little':arr.byteswap()
    return arr.tobytes()


def _unpack_vector(raw,expected_dim=None):
    try:
        if isinstance(raw,(bytes,bytearray,memoryview)):
            buf=bytes(raw)
            if not buf or len(buf)%8!=0:
                return None
            arr=array.array('d')
            arr.frombytes(buf)
            if sys.byteorder!='little':arr.byteswap()
            if expected_dim is not None and len(arr)!=expected_dim:
                return None
            if not all(math.isfinite(x) for x in arr):
                return None
            return arr
        if isinstance(raw,str):
            parsed=json.loads(raw)
            if not isinstance(parsed,list) or not parsed:
                return None
            if expected_dim is not None and len(parsed)!=expected_dim:
                return None
            arr=array.array('d')
            for x in parsed:
                if type(x) not in (int,float):
                    return None
                fx=float(x)
                if not math.isfinite(fx):
                    return None
                arr.append(fx)
            return arr
        return None
    except (ValueError,TypeError,OverflowError,struct.error):
        return None


def _score_vectors(eligible_rows,queries):
    if not eligible_rows or not queries:return {}
    valid_queries=[]
    dim=None
    for q in queries:
        if not isinstance(q,(list,tuple,array.array)) or not q:
            continue
        try:
            qf=[float(x) for x in q]
        except (TypeError,ValueError,OverflowError):
            continue
        if not all(math.isfinite(x) for x in qf):
            continue
        if dim is None:
            dim=len(qf)
        elif len(qf)!=dim:
            continue
        valid_queries.append(qf)
    if not valid_queries or not dim:
        return {}
    np=sys.modules.get('numpy')
    if np is not None:
        try:
            q_mat=np.asarray(valid_queries,dtype=np.float64)
            if q_mat.ndim==2 and q_mat.shape[1]==dim:
                fast_ids=[];fast_vecs=[];fallback=[]
                for ident,raw in eligible_rows:
                    if isinstance(raw,(bytes,bytearray,memoryview)) and len(raw)==dim*8:
                        vec=np.frombuffer(raw,dtype='<f8')
                        if np.isfinite(vec).all():
                            fast_ids.append(ident);fast_vecs.append(vec)
                    else:
                        unpacked=_unpack_vector(raw,expected_dim=dim)
                        if unpacked is not None:
                            fallback.append((ident,unpacked))
                scores={}
                if fast_vecs:
                    mat=np.vstack(fast_vecs)
                    max_per_row=(mat @ q_mat.T).max(axis=1)
                    for ident,val in zip(fast_ids,max_per_row.tolist()):
                        fval=float(val)
                        if math.isfinite(fval):
                            scores[ident]=max(scores.get(ident,float('-inf')),fval)
                for ident,vec in fallback:
                    val=max(sum(a*b for a,b in zip(vec,q)) for q in valid_queries)
                    if math.isfinite(val):
                        scores[ident]=max(scores.get(ident,float('-inf')),val)
                return scores
        except (TypeError,ValueError,struct.error):
            pass
    scores={}
    for ident,raw in eligible_rows:
        vector=_unpack_vector(raw,expected_dim=dim)
        if vector is None:
            continue
        score=max(sum(a*b for a,b in zip(vector,q)) for q in valid_queries)
        if math.isfinite(score):
            scores[ident]=max(scores.get(ident,float('-inf')),score)
    return scores


class LocalEmbeddings:
    def __init__(self,folder):
        import onnxruntime as ort
        from tokenizers import Tokenizer
        self.np=__import__('numpy');folder=Path(folder)
        checks={'model.onnx':'ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665',
                'tokenizer.json':'0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39'}
        for name,digest in checks.items():
            if sha((folder/name).read_bytes())!=digest:raise Invalid('modelo local diferente da revisão validada')
        options=ort.SessionOptions();options.intra_op_num_threads=2;options.inter_op_num_threads=1
        self.session=ort.InferenceSession(str(folder/'model.onnx'),sess_options=options,providers=['CPUExecutionProvider'])
        self.tokenizer=Tokenizer.from_file(str(folder/'tokenizer.json'))
        self.tokenizer.enable_truncation(max_length=256,stride=32);self.tokenizer.enable_padding()
    def chunks(self,text,kind='passage'):
        np=self.np;encoding=self.tokenizer.encode(kind+': '+text)
        encodings=[encoding]+encoding.overflowing;vectors=[]
        for e in encodings:
            ids=np.array([e.ids],dtype=np.int64);mask=np.array([e.attention_mask],dtype=np.int64)
            candidates={'input_ids':ids,'attention_mask':mask,'token_type_ids':np.array([e.type_ids],dtype=np.int64)}
            output=self.session.run(None,{i.name:candidates[i.name] for i in self.session.get_inputs()})[0]
            vector=(output*mask[:,:,None]).sum(axis=1)/np.maximum(mask.sum(axis=1)[:,None],1)
            vector=vector/np.maximum(np.linalg.norm(vector,axis=1,keepdims=True),1e-12)
            vectors.append(vector[0].astype(np.float32).tolist())
        return vectors


class Retrieval:
    def __init__(self,sources,embedder=None,scope='proprietario_local'):
        self.sources=sources;self.k=Knowledge(sources);self.embedder=embedder;self.scope=scope
        self.db=sources.root/'estado'/'recuperacao.sqlite3'
        with self.connect() as c:
            c.executescript('''CREATE TABLE IF NOT EXISTS vectors(id TEXT,part INTEGER,digest TEXT,value TEXT,PRIMARY KEY(id,part));
              CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT);
              CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY,generation TEXT,result TEXT);
              CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT,query TEXT,generation TEXT,reused INTEGER,result_ids TEXT);
              CREATE TABLE IF NOT EXISTS recipes(key TEXT PRIMARY KEY,query TEXT,steps TEXT,uses INTEGER,last_generation TEXT);''')
    @contextmanager
    def connect(self):
        c=sqlite3.connect(self.db,timeout=30)
        try:
            with c:yield c
        finally:c.close()
    def snapshot(self):
        records,_,issues=self.k.catalog();invalid=self.k.stale(records)
        generation=sha(canon({'records':records,'issues':issues,'scope':self.scope}).encode())
        return generation,records,invalid,issues
    def search(self,query,limit=12,depth=1):
        if not isinstance(query,str) or not query.strip() or len(query)>500 or type(limit)is not int or not 1<=limit<=50 or type(depth)is not int or not 0<=depth<=2:
            raise Invalid('consulta fora dos limites')
        generation,records,invalid,issues=self.snapshot()
        key=sha(canon([query,limit,depth,self.scope,bool(self.embedder),'rrf-v3-lexical-ranked-context-reserved']).encode())
        with self.connect() as c:cached=c.execute('SELECT generation,result FROM cache WHERE key=?',(key,)).fetchone()
        if cached and cached[0]==generation:
            result=json.loads(cached[1]);result['cache_reused']=True
            self.log(query,generation,result,True);return result
        eligible={i:r for i,r in records.items() if i not in invalid and r.get('lifecycle_status')!='excluded'}
        # Expansões do grafo não são posições no ranking lexical do RRF.
        lexical=self.k.search(query,limit=limit,depth=0)
        exact=list(dict.fromkeys(r['id'] for r in lexical['results'] if r['id'] in eligible))
        semantic=[]
        if self.embedder and eligible:
            queries=self.embedder.chunks(query,'query')
            expected_dim=len(queries[0]) if queries and queries[0] else None
            with self.connect() as c:
                stored_rows=c.execute('SELECT id,part,digest,value FROM vectors ORDER BY id,part').fetchall()
            grouped={}
            for row_id,part,row_digest,raw_val in stored_rows:
                grouped.setdefault(row_id,[]).append((part,row_digest,raw_val))
            updates={}
            for ident,record in eligible.items():
                text=record['title']+'\n'+canon(record['payload']);digest=sha(text.encode())
                existing_parts=grouped.get(ident)
                valid_stored=(
                    bool(existing_parts)
                    and [p for p,_,_ in existing_parts]==list(range(len(existing_parts)))
                    and all(d==digest and _unpack_vector(v,expected_dim=expected_dim) is not None for _,d,v in existing_parts)
                )
                if not valid_stored:
                    updates[ident]=(digest,self.embedder.chunks(text))
            stale_ids=set(grouped)-set(eligible)
            if updates or stale_ids:
                if self.snapshot()[0]!=generation:raise Conflict('base mudou durante atualização do índice')
                with self.connect() as c:
                    c.execute('BEGIN IMMEDIATE')
                    for ident in stale_ids:c.execute('DELETE FROM vectors WHERE id=?',(ident,))
                    for ident,(digest,vectors_list) in updates.items():
                        c.execute('DELETE FROM vectors WHERE id=?',(ident,))
                        for part,vector in enumerate(vectors_list):c.execute('INSERT INTO vectors VALUES(?,?,?,?)',(ident,part,digest,_pack_vector(vector)))
                    c.execute('INSERT OR REPLACE INTO metadata VALUES(?,?)',('generation',generation))
                    vectors=list(c.execute('SELECT id,value FROM vectors'))
            else:
                vectors=[(row_id,raw_val) for row_id,_,_,raw_val in stored_rows]
            eligible_rows=[(ident,raw) for ident,raw in vectors if ident in eligible]
            scores=_score_vectors(eligible_rows,queries)
            semantic=sorted(scores,key=lambda i:(-scores[i],i))[:limit]
        ranks={}
        for channel in (exact,semantic):
            for position,ident in enumerate(channel):ranks[ident]=ranks.get(ident,0)+1/(60+position+1)
        lexical_positions={ident:position for position,ident in enumerate(exact)}
        semantic_positions={ident:position for position,ident in enumerate(semantic)}
        ranked=sorted(ranks,key=lambda i:(-ranks[i],lexical_positions.get(i,limit),
                                         semantic_positions.get(i,limit),i))
        reserve=min(3,max(1,limit//3)) if depth and limit>1 else 0
        selected=ranked[:max(1,limit-reserve)]
        visited=set(selected)
        for _ in range(depth):
            extra=[];frontier=set(selected)
            for ident in selected:
                for ref in refs(records[ident]['payload']):
                    target=ref.get('record_id')
                    if target in eligible and target not in visited:visited.add(target);extra.append(target)
            for ident in sorted(eligible):
                if ident not in visited and any(ref.get('record_id') in frontier for ref in refs(records[ident]['payload'])):
                    visited.add(ident);extra.append(ident)
            selected=(selected+extra)[:limit]
        selected=(selected+[ident for ident in ranked if ident not in selected])[:limit]
        if self.snapshot()[0]!=generation:raise Conflict('base mudou antes de concluir recuperação')
        result={'mode':'hybrid_lexical_vector_graph' if self.embedder else 'lexical_and_graph',
                'generation':generation,'cache_reused':False,'scope':self.scope,
                'results':[{'id':ident,'revision':records[ident]['revision'],'title':records[ident]['title'],
                            'record_type':records[ident]['record_type'],'record':records[ident]} for ident in selected],
                'issues':issues,'excluded_stale':len(invalid),
                'limits':['Ranking não comprova identidade, veracidade ou causalidade.','A resposta usa a nota canônica completa, não somente o vetor.']}
        with self.connect() as c:
            c.execute('INSERT OR REPLACE INTO cache VALUES(?,?,?)',(key,generation,canon(result)))
            recipe=sha(canon([query,self.scope]).encode())
            c.execute('INSERT INTO recipes VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET uses=uses+1,last_generation=excluded.last_generation',
                      (recipe,query,canon(['lexical','vector' if self.embedder else 'vector_unavailable','graph']),1,generation))
        self.log(query,generation,result,False);return result
    def log(self,query,generation,result,reused):
        with self.connect() as c:c.execute('INSERT INTO history(at,query,generation,reused,result_ids) VALUES(?,?,?,?,?)',
                   (NOW(),query,generation,int(reused),canon([r['id'] for r in result['results']])))
