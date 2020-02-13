## ----------------- From PyPI -----------------
import datetime, whois, logging, tldextract, os, random, socks, socket

## ----------------- Not from PyPI -----------------
from tahoe import Attribute, misc

## ----------------- Local -----------------

## ----------------- Debug -----------------
import pdb
from pprint import pprint

## ----------------- Proxy -----------------
##base = os.path.abspath(os.path.dirname(__file__))
##path = os.path.join(base, "socks.txt")
##
##with open(path) as f: 
##    proxies = f.read().splitlines()


## ----------------- Main -----------------

def get_whois_att(host):
##    proxy = random.choice(proxies)
##    os.environ["SOCKS"] = proxy
    
    sub_types = [
        'days_creation', 'months_creation', 'years_creation', 'days_expiration',
        'months_expiration', 'years_expiration', 'days_updated', 'months_updated',
        'years_updated',  'dnssec', 'domain', 'name_server_domain', 'whois_name', 
        'whois_org', 'whois_registrar', 'whois_server', 'whois_address_1', 'whois_address_2', 
        'whois_city', 'whois_country', 'whois_state', 'whois_zipcode', 'epp_code_addperiod', 
        'epp_code_autorenewperiod', 'epp_code_inactive', 'epp_code_ok', 
        'epp_code_pendingcreate', 'epp_code_pendingdelete', 'epp_code_pendingrenew', 
        'epp_code_pendingrestore', 'epp_code_pendingtransfer', 'epp_code_pendingupdate', 
        'epp_code_redemptionperiod', 'epp_code_renewperiod', 'epp_code_serverdeleteprohibited', 
        'epp_code_serverhold', 'epp_code_serverrenewprohibited', 'epp_code_servertransferprohibited', 
        'epp_code_serverupdateprohibited', 'epp_code_transferperiod', 'epp_code_clientdeleteprohibited', 
        'epp_code_clienthold', 'epp_code_clientrenewprohibited', 'epp_code_clienttransferprohibited', 
        'epp_code_clientupdateprohibited']
        
    try: w = whois.whois(host)
    except (socks.SOCKS5Error, socks.GeneralProxyError, socks.ProxyConnectionError, socket.timeout): 
##        try: proxies.remove(proxy)
##        except ValueError: pass
        attributes = [Attribute(st, None) for st in sub_types] 
    except whois.parser.PywhoisError:
        attributes = [Attribute(st, None) for st in sub_types]           
    except:
        logging.error("--  host: {} -- ".format(host), exc_info=True)
        
        attributes = [Attribute(st, None) for st in sub_types]
    else:
        #  creation, expiration, updated dates
        
        now_dt = datetime.datetime.utcnow()

        creation_dt = w.creation_date
        expiration_dt = w.expiration_date
        updated_dt = w.updated_date

        if isinstance(creation_dt, list): creation_dt = creation_dt[0]
        if isinstance(expiration_dt, list): expiration_dt = expiration_dt[0]
        if isinstance(updated_dt, list): updated_dt = updated_dt[0]

        if isinstance(creation_dt, datetime.datetime):
            days_creation = (now_dt - creation_dt).days
            months_creation = days_creation // 30
            years_creation = days_creation // 365
        else:
            days_creation, months_creation, years_creation = None, None, None

        if isinstance(expiration_dt, datetime.datetime):
            days_expiration = (expiration_dt - now_dt).days
            months_expiration = days_expiration // 30
            years_expiration = days_expiration // 365
        else:
            days_expiration, months_expiration, years_expiration = None, None, None

        if isinstance(updated_dt, datetime.datetime):
            days_updated = (now_dt - updated_dt).days
            months_updated = days_updated // 30
            years_updated = days_updated // 365
        else:
            days_updated, months_updated, years_updated = None, None, None

        adc = Attribute('days_creation', days_creation)
        amc = Attribute('months_creation', months_creation)
        ayc = Attribute('years_creation', years_creation)
        ade = Attribute('days_expiration', days_expiration)
        ame = Attribute('months_expiration', months_expiration)
        aye = Attribute('years_expiration', years_expiration)
        adu = Attribute('days_updated', days_updated)
        amu = Attribute('months_updated', months_updated)
        ayu = Attribute('years_updated', years_updated)

        attributes = [adc, amc, ayc, ade, ame, aye, adu, amu, ayu]
        

        # EPP Status Codes
        
        epp_codes_dict = {
            'epp_code': {
                'addperiod':0, 'autorenewperiod':0, 'inactive':0, 'ok':0,
                'pendingcreate':0, 'pendingdelete':0, 'pendingrenew':0,
                'pendingrestore':0, 'pendingtransfer':0, 'pendingupdate':0,
                'redemptionperiod':0, 'renewperiod':0, 'serverdeleteprohibited':0,
                'serverhold':0, 'serverrenewprohibited':0, 'servertransferprohibited':0,
                'serverupdateprohibited':0, 'transferperiod':0, 
                'clientdeleteprohibited':0, 'clienthold':0, 'clientrenewprohibited':0,
                'clienttransferprohibited':0, 'clientupdateprohibited':0
            }
        }
        
        if isinstance(w.get('status'), list):
            for s in w['status']:
                s = s.split()[0].lower().replace('_','').replace('-','')
                if s in epp_codes_dict: epp_codes_dict['epp_codes'][s] = 1

        epp_feat = misc.features(epp_codes_dict, sep = '_', root_only=True)
        astatus_s = [Attribute(k,v[0]) for k,v in epp_feat.items()]

        attributes += astatus_s
        
        # DNS Security
        adnssec = Attribute('dnssec', w.get('dnssec'))

        # Domain Name
        dn = w.get('domain_name')
        if not dn: dn = w.get('domain')
        if isinstance(dn, list): dn = dn[0]
        if dn: dn = dn.lower()
        adomainname = Attribute('domain', dn)

        # Name Server Domain
        nsd = w.get('name_servers')
        if not nsd: nsd = w.get('nserver')
        if isinstance(nsd, list): nsd = nsd[0]
        if isinstance(nsd, str):
            nsd = nsd.lower()
            nsd = tldextract.extract(nsd)
            nsd = nsd.domain + '.' + nsd.suffix
            nsd = nsd.lower()
        anamesrvdom = Attribute('name_server_domain', nsd)

        # Name, Org
        name, org = None, None
        
        name = w.get('name')
        if not name: name = w.get('registrant_name')
        if isinstance(name, str): name = name.lower()
        
        org = w.get('org')
        if not org: org = w.get('registrant_org')
        if isinstance(org, str): org = org.lower()
        
        aname = Attribute('whois_name', name)
        aorg = Attribute('whois_org', org)

        # Registrar
        registrar = w.get('registrar')
        if isinstance(registrar, str): registrar = registrar.lower()
        aregistrar = Attribute('whois_registrar', registrar)

        # Whois Server
        whoissrv = w.get('whois_server')
        if isinstance(whoissrv, str): whoissrv = whoissrv.lower()
        awhoissrv = Attribute('whois_server', whoissrv)

        attributes += [adnssec, adomainname, anamesrvdom, aname, aorg, aregistrar, awhoissrv]

        # Address
        add = w.get('address')
        if not add: add = w.get('registrant_street')
        add1 = add
        add2 = None
        if isinstance(add, list):
            add1 = add[0]
            if len(add) > 1: add2 = add[1]

        if isinstance(add1, str): add1 = add1.lower()
        if isinstance(add2, str): add2 = add2.lower()
        
        aadd1 = Attribute('whois_address_1', add1)
        aadd2 = Attribute('whois_address_2', add2)

        # GeoLocation
        city = w.get('city')
        if not city: city = w.get('registrant_city')
        acity = Attribute('whois_city', city)
        
        country = w.get('country')
        if not country: country = w.get('registrant_country')
        acountry = Attribute('whois_country', w.get('country'))
        
        astate = Attribute('whois_state', w.get('state'))
        azipcode = Attribute('whois_zipcode', w.get('zipcode'))

        attributes += [aadd1, aadd2, acity, acountry, astate, azipcode]
    
    return attributes
            


