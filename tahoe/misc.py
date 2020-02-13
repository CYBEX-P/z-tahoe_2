from collections import defaultdict

def dtresolve(start, end):
    d = defaultdict(dict)
    if start: d['timestamp']['$gte'] = start
    if end: d['timestamp']['$lte'] = end
    return dict(d)
    
def limitskip(limit=10, skip=0, page=1):
    if page>1: skip = (page-1)*limit
    return {'limit': max(limit,10), 'skip':max(skip,0)}
    
def branches(d):
    def branch(val, old=[]):
        b = []
        if isinstance(val, dict):
            for k in val: b += branch(val[k], old+[str(k)])
        elif isinstance(val, list):
            for k in val: b += branch(k, old)
        else:
            b.append(old + [val])
        return b

    return branch(d)

def features(d, sub_type=None, data=None, sep='.', root_only=False):
    brn = branches(d)
    r = defaultdict(list)
    for b in brn:
        if (sub_type and data) and not (b[-2]==sub_type and b[-1]==data): continue
        k, v = b[:-1], b[-1]
        if root_only:
            r[sep.join(k)].append(v)
        else:
            for i in range(len(k)):
                r[sep.join(k[-i:])].append(v)
    return {k : list(set(v)) for k,v in r.items()} 
    
