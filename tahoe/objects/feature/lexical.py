
"""
===================================================
================= Lexical Features ================
===================================================
"""
from furl import furl
from collections import Counter
import logging, math, re, posixpath
from tahoe import *


e = "http://globesecurityservices.com/BzJoVeo0/index.html"
u = furl(e)

with open('D:\\mal_url\\feature\\tld.txt', encoding='utf8') as f: content = f.readlines()
_TLD = set([x.strip() for x in content])
_EXT = {'html', 'htm', 'php', 'css', 'js'}
_SYMBOL = r"[~$&+,:;=?@#|'<>.^*()%!-]"
_VOWEL =  r"[aeiou]"
_LETTER = r"[a-zA-Z]"
_IP_RE = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
_BRAND = [
    'alaska',
    'alibaba',
    'alipay',
    'allianz',
    'allied',
    'amazon',
    'americanexpress',
    'amex',
    'apple',
    'banca',
    'banco',
    'bank',
    'banque',
    'bankofamerica',
    'chase',
    'comcast',
    'docusign',
    'dropbox',
    'facebok',
    'gmail',
    'google',
    'hotmail',
    'icloud',
    'linkedin',
    'master',
    'microsoft',
    'netflix',
    'office',
    'paypal',
    'visa',
    'walmart',
    'wellsfargo',
    'windows',
    'xoom'
    'yahoo'
]

## # String based

def count_char(s): return len(s)

def count_digit(s): return sum(c.isdigit() for c in s)

def count_dot(s): return s.count('.')

def count_symbol(s): return len(re.findall(_SYMBOL, s))

def count_vowel(s): return len(re.findall(_VOWEL, s.lower()))

def entropy(s):
    p, lns = Counter(s), float(len(s))
    return sum( count/lns * math.log(count/lns, 2) for count in p.values())

def max_seq_digit(s): return max((len(k) for k in re.findall(r'\d+', s)), default=0)

def max_seq_letter(s): return max((len(k) for k in re.findall(_LETTER+'+', s)), default=0)

def max_seq_symbol(s): return max((len(k) for k in re.findall(_SYMBOL+'+', s)), default=0)

def token_list(s): return re.split('\W+', s)


## # Token Based

def count_token(s): return len(token_list(s))

def max_token_length(s): return  max(len(token) for token in token_list(s))

def max_token_entropy(s): return max(entropy(token) for token in token_list(s))

def pre(u):
    if not isinstance(u, furl): raise TypeError("url must of be of type furl")
    u.features = {}
    u.token_list = re.split('\W+',u.url)
    u.domain_token_list = re.split('\W+',u.host)
    return u


#### Lexical Features

def get_lexical_att(u):
    assert isinstance(u, str), "u must be type str!"
    
    u = furl(u)
    
    url = u.url
    domain = (u.host or '')
    path = str(u.path)
    file = posixpath.basename(path)
    query = str(u.query)
    fragment = str(u.fragment)
    if file.find('.') == -1: file = ''
    
    ## URL Based
    aul = Attribute('url_length', len(url))
    aue = Attribute('url_entropy', entropy(url))
    audc = Attribute('url_dot_count', count_dot(url))
    ausc = Attribute('url_symbol_count', count_symbol(url))
    augc = Attribute('url_digit_count', count_digit(url))
    auvc = Attribute('url_vowel_count', count_vowel(url))
    aumls = Attribute('url_max_letter_sequence', max_seq_letter(url))
    aumds = Attribute('url_max_digit_sequence', max_seq_digit(url))
    aumsc = Attribute('url_max_symbol_sequence', max_seq_symbol(url))

    autc = Attribute('url_token_count', count_token(url))
    aumtl = Attribute('url_max_token_length', max_token_length(url))
    aumte = Attribute('url_max_token_entropy', max_token_entropy(url))

    
    ## Domain Based
    adl = Attribute('domain_length', len(domain))
    ade = Attribute('domain_entropy', entropy(domain))
    addc = Attribute('domain_dot_count', count_dot(domain))
    adsc = Attribute('domain_symbol_count', count_symbol(domain))
    adgc = Attribute('domain_digit_count', count_digit(domain))
    advc = Attribute('domain_vowel_count', count_vowel(domain))
    admls = Attribute('domain_max_letter_sequence', max_seq_letter(domain))
    admds = Attribute('domain_max_digit_sequence', max_seq_digit(domain))
    admsc = Attribute('domain_max_symbol_sequence', max_seq_symbol(domain))

    adtc = Attribute('domain_token_count', count_token(domain))
    admtl = Attribute('domain_max_token_length', max_token_length(domain))
    admte = Attribute('domain_max_token_entropy', max_token_entropy(domain))

    isdomip = re.search(_IP_RE, domain)
    if isdomip: isdomip=1
    else: isdomip=0
    aisdomip = Attribute('is_domain_ip', isdomip)
    

    ## Path Based
    apl = Attribute('path_length', len(path))
    ape = Attribute('path_entropy', entropy(path))
    apdc = Attribute('path_dot_count', count_dot(path))
    apsc = Attribute('path_symbol_count', count_symbol(path))
    apgc = Attribute('path_digit_count', count_digit(path))
    apvc = Attribute('path_vowel_count', count_vowel(path))
    apmls = Attribute('path_max_letter_sequence', max_seq_letter(path))
    apmds = Attribute('path_max_digit_sequence', max_seq_digit(path))
    apmsc = Attribute('path_max_symbol_sequence', max_seq_symbol(path))

    aptc = Attribute('path_token_count', count_token(path))
    apmtl = Attribute('path_max_token_length', max_token_length(path))
    apmte = Attribute('path_max_token_entropy', max_token_entropy(path))

    ## File Based
    afl = Attribute('file_length', len(file))
    afe = Attribute('file_entropy', entropy(file))
    afdc = Attribute('file_dot_count', count_dot(file))
    afsc = Attribute('file_symbol_count', count_symbol(file))
    afgc = Attribute('file_digit_count', count_digit(file))
    afvc = Attribute('file_vowel_count', count_vowel(file))
    afmls = Attribute('file_max_letter_sequence', max_seq_letter(file))
    afmds = Attribute('file_max_digit_sequence', max_seq_digit(file))
    afmsc = Attribute('file_max_symbol_sequence', max_seq_symbol(file))
     
    aftc = Attribute('file_token_count', count_token(file))
    afmtl = Attribute('file_max_token_length', max_token_length(file))
    afmte = Attribute('file_max_token_entropy', max_token_entropy(file))

    ## Query Based
    aql = Attribute('query_length', len(query))
    aqe = Attribute('query_entropy', entropy(query))
    aqdc = Attribute('query_dot_count', count_dot(query))
    aqsc = Attribute('query_symbol_count', count_symbol(query))
    aqgc = Attribute('query_digit_count', count_digit(query))
    aqvc = Attribute('query_vowel_count', count_vowel(query))
    aqmls = Attribute('query_max_letter_sequence', max_seq_letter(query))
    aqmds = Attribute('query_max_digit_sequence', max_seq_digit(query))
    aqmsc = Attribute('query_max_symbol_sequence', max_seq_symbol(query))
     
    aqtc = Attribute('query_token_count', count_token(query))
    aqmtl = Attribute('query_max_token_length', max_token_length(query))
    aqmte = Attribute('query_max_token_entropy', max_token_entropy(query))

    ## Fragment
    afrl = Attribute('fragment_length', len(fragment))
    afre = Attribute('fragment_entropy', entropy(fragment))
    afrdc = Attribute('fragment_dot_count', count_dot(fragment))
    afrsc = Attribute('fragment_symbol_count', count_symbol(fragment))
    afrgc = Attribute('fragment_digit_count', count_digit(fragment))
    afrvc = Attribute('fragment_vowel_count', count_vowel(fragment))
    afrmls = Attribute('fragment_max_letter_sequence', max_seq_letter(fragment))
    afrmds = Attribute('fragment_max_digit_sequence', max_seq_digit(fragment))
    afrmsc = Attribute('fragment_max_symbol_sequence', max_seq_symbol(fragment))

    afrtc = Attribute('fragment_token_count', count_token(fragment))
    afrmtl = Attribute('fragment_max_token_length', max_token_length(fragment))
    afrmte = Attribute('fragment_max_token_entropy', max_token_entropy(fragment))



    ## Ratio
    if len(url) != 0:
        adur = Attribute('domain_url_ratio', len(domain)/len(url))
        apur = Attribute('path_url_ratio', len(path)/len(url))
        afur = Attribute('file_url_ratio', len(file)/len(url))
        aqur = Attribute('query_url_ratio', len(query)/len(url))
        afrur = Attribute('fragment_url_ratio', len(fragment)/len(url))
    else:
        adur = Attribute('domain_url_ratio', None)
        apur = Attribute('path_url_ratio', None)
        afur = Attribute('file_url_ratio', None)
        aqur = Attribute('query_url_ratio', None)
        afrur = Attribute('fragment_url_ratio', None)

    if len(domain) != 0:
        apdr = Attribute('path_domain_ratio', len(path)/len(domain))
        afdr = Attribute('file_domain_ratio', len(file)/len(domain))
        aqdr = Attribute('query_domain_ratio', len(query)/len(domain))
        afrdr = Attribute('fragment_domain_ratio', len(fragment)/len(domain))
    else:
        apdr = Attribute('path_domain_ratio', None)
        afdr = Attribute('file_domain_ratio', None)
        aqdr = Attribute('query_domain_ratio', None)
        afrdr = Attribute('fragment_domain_ratio', None)

    if len(path) != 0:
        afpr = Attribute('file_path_ratio', len(file)/len(path))
        aqpr = Attribute('query_path_ratio', len(query)/len(path))
        afrdr = Attribute('fragment_path_ratio', len(fragment)/len(path))
    else:
        afpr = Attribute('file_path_ratio', None)
        aqpr = Attribute('query_path_ratio', None)
        afrdr = Attribute('fragment_path_ratio', None)

    if len(file) != 0:
        aqfr = Attribute('query_file_ratio', len(query)/len(file))
        afrfr = Attribute('fragment_file_ratio', len(fragment)/len(file))
    else:
        aqfr = Attribute('query_file_ratio', None)
        afrfr = Attribute('fragment_file_ratio', None)

    if len(query) != 0:
        afrqr = Attribute('fragment_query_ratio', len(fragment)/len(query))
    else:
        afrqr = Attribute('fragment_query_ratio', None)

    # Keywords
    key_count = 0
    for b in _BRAND:
        if b in url: key_count += 1
    aukc = Attribute('url_keyword_count', key_count)

    tokens = token_list(url)
    token_key_count = 0
    for b in _BRAND:
        if b in tokens: token_key_count += 1
    atkc = Attribute('token_keyword_count', token_key_count)
    

    lex_att = [
        aul, aue, audc, ausc, augc, auvc, aumls, aumds, aumsc, autc, aumtl, aumte,
        adl, ade, addc, adsc, adgc, advc, admls, admds, admsc, adtc, admtl, admte,
        apl, ape, apdc, apsc, apgc, apvc, apmls, apmds, apmsc, aptc, apmtl, apmte,
        afl, afe, afdc, afsc, afgc, afvc, afmls, afmds, afmsc, aftc, afmtl, afmte,
        aql, aqe, aqdc, aqsc, aqgc, aqvc, aqmls, aqmds, aqmsc, aqtc, aqmtl, aqmte,
        adur, apur, afur, aqur, afrur, apdr, afdr, aqdr, afrdr, afpr, aqpr, afrdr,
        aqfr, afrfr, afrqr, aukc, atkc, aisdomip
    ]       

    return lex_att









def example1():

    e = r"http://globesecurityservicesgoogle.com/BzJoVeo0/netflix/index.html"
    u = furl(e)
    
    au = Attribute('url', e)     
    olf = Object('lexical_features', lexical(u))
    print(len(olf.data))

    # URL Object
    ou = Object('url', [au, olf])
    pprint(ou.data)


if __name__ == "__main__":
    from pprint import pprint
    import os
    
    config = {
            "mongo_url" : "mongodb://localhost:27017/",
            "db" : "phish_db",
            "coll" : "phish"
            }

    os.environ["_MONGO_URL"] = config.pop("mongo_url")
    os.environ["_TAHOE_DB"] = config.pop("db", "phish_db")
    os.environ["_TAHOE_COLL"] = config.pop("coll", "phish")

    from tahoe import Attribute, Object
    example1()
