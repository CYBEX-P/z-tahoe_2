## ----------------- From PyPI -----------------
import logging, dns.resolver, pdb

## ----------------- Not from PyPI -----------------
from tahoe import Attribute


def get_dns_att(host):
    try: da = dns.resolver.query(host, 'A')
    except:
        ttl = None
        ip = None
    else:
        ttl = da.ttl
        ip = da[0].address
        
    try:
        dptr = dns.resolver.query(ip+'.in-addr.arpa', 'PTR')
    except:
        isptr = 0
    else:
        isptr = 1
        
    if isptr:
        host_eq_rev 
    
    attl = Attribute('dns_ttl', ttl)
    aisptr = Attribute('dns_ptr_exists', isptr)
    
    attributes = [attl, aisptr]
    
    return attributes
        
 