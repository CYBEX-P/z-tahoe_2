## ----------------- From PyPI -----------------
from ipwhois import IPWhois
from dateutil.parser import parse
#from pytz import utc


## ----------------- Not from PyPI -----------------
from tahoe import Attribute, misc

## ----------------- Local -----------------

## ----------------- Debug -----------------
import pdb
from pprint import pprint


def get_ipwhois_att(ip):
    sub_types = ['asn']
    try:
        obj = IPWhois(ip)
        w = obj.lookup_rdap(depth=0, inc_nir=False)
    except:
        logging.error("--  ip: {} -- ".format(ip), exc_info=True)
        
        attributes = [Attribute(st, None) for st in sub_types]
    else:
        asn = w.get('asn')
        asn_country_code = w.get('asn_country_code')
        
        now_dt = datetime.datetime.utcnow()
        asn_dt = w.get('asn_date')
        
        if isinstance(asn_dt, str):
            asn_dt = parse(asn_dt).replace(tzinfo=utc)
            days_creation = (now_dt - asn_dt).days
            months_creation = asn_dt // 30
            years_creation = asn_dt // 365
        else:
            days_creation, months_creation, years_creation = None, None, None
            
        
        
    pdb.set_trace()
    


