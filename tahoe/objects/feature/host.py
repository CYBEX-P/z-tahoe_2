## ----------------- From PyPI -----------------
import logging, socket, furl, tldextract

## ----------------- Not from PyPI -----------------
from tahoe import Attribute

## ----------------- Local -----------------

## ----------------- Debug -----------------
  

def get_host_att(u):
    sub_types = ['host', 'domain', 'reverse_domain', 'domain_eq_reverse',
                 'ip', 'ip1', 'ip2', 'ip3', 'ip4',]
    try:
        u = furl.furl(u)
        host = u.host

        domain = tldextract.extract(host)
        domain = domain.domain + '.' + domain.suffix
        domain = domain.lower()

        try:
            ip = socket.gethostbyname(host)
            try: rvd = socket.gethostbyaddr(ip)[0]
            except socket.herror: rvd = None
            else:
                rvd = tldextract.extract(rvd)
                rvd = rvd.domain + '.' + rvd.suffix
                rvd = rvd.lower()
        except:
            ip, ip1, ip2, ip3, ip4, rvd = None, None, None, None, None, None
        else:
            ip1, ip2, ip3, ip4 = ip.split('.')
    except TypeError:
        print(u.url)
        attributes = [Attribute(st, None) for st in sub_types]
    except:
        logging.error("--  host: {} -- ".format(host), exc_info=True)

        attributes = [Attribute(st, None) for st in sub_types]
    else:      
       
        aip = Attribute('ip', ip)
        
        aip1 = Attribute('ip1', ip1)
        aip2 = Attribute('ip2', ip2)
        aip3 = Attribute('ip3', ip3)
        aip4 = Attribute('ip4', ip4)

        ah = Attribute('host', host)
        ad = Attribute('domain', domain)
        arvd = Attribute('reverse_domain', rvd)
        ader = Attribute('domain_eq_reverse', int(rvd==domain and rvd != None))

        attributes = [aip, aip1, aip2, aip3, aip4, ah, ad, arvd, ader]

    return attributes

