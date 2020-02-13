## ----------------- From PyPI -----------------
import socket, datetime, whois, logging, geoip2.database, tldextract, dns.resolver
from urllib.parse import urlparse, unquote
from ipwhois import IPWhois
from pprint import pprint


## ----------------- Not from PyPI -----------------
from tahoe import Attribute, Object, misc

## ----------------- Local -----------------

## ----------------- Debug -----------------
import pdb
from pprint import pprint

asn_reader = geoip2.database.Reader('D:\\mal_url\\feature\\geolite2\\GeoLite2-ASN.mmdb')
city_reader = geoip2.database.Reader('D:\\mal_url\\feature\\geolite2\\GeoLite2-City.mmdb')
country_reader = geoip2.database.Reader('D:\\mal_url\\feature\\geolite2\\GeoLite2-Country.mmdb')

##def get_dns(host):
##    try: da = dns.resolver.query(host, 'A')
##    except:
##        attl = None
##        ip = None
##    else:
##        attl = da.ttl
##        ip = da[0].address
##        
##    try:
##        dptr = dns.resolver.query(ip+'.in-addr.arpa', 'PTR')
##    except:
##        isptr = 0
##    else:
##        isptr = 1
##        
    
  

def get_ip(host, domain):
    sub_types = ['ip', 'ip1', 'ip2', 'ip3', 'ip4', 'reverse_domain']
    try:
        ip = socket.gethostbyname(host)
        try: rvd = socket.gethostbyaddr(ip)[0]
        except socket.herror: rvd = None
        else:
            rvd = rvd.lower()
            rvd = tldextract.extract(rvd)
            rvd = rvd.domain + '.' + rvd.suffix
            rvd = rvd.lower()
    except:
        logging.error("--  host: {} -- ".format(host), exc_info=True)

        ip = None
        attributes = [Attribute(st, None) for st in sub_types]
        attributes += [Attribute('domain_eq_reverse', 0)]
    else:      
        ip1, ip2, ip3, ip4 = ip.split('.')
        
        aip = Attribute('ip', ip)
        
        aip1 = Attribute('ip1', ip1)
        aip2 = Attribute('ip2', ip2)
        aip3 = Attribute('ip3', ip3)
        aip4 = Attribute('ip4', ip4)

        arvd = Attribute('reverse_domain', rvd)
        ader = Attribute('domain_eq_reverse', int(rvd==domain and rvd != None))

        attributes = [aip, aip1, aip2, aip3, aip4, arvd, ader]

    return attributes, ip


def get_whois2(host):
    obj = IPWhois(host)
    results = obj.lookup_rdap(depth=0, inc_nir=True)
    pprint(results)
    pdb.set_trace()


def get_whois(host):
    sub_types = [
        'days_creation', 'months_creation', 'years_creation', 'days_expiration',
        'months_expiration', 'years_expiration', 'days_updated', 'months_updated',
        'years_updated', 'epp_server_code_addPeriod', 'epp_server_code_autoRenewPeriod',
        'epp_server_code_inactive', 'epp_server_code_ok', 'epp_server_code_pendingCreate',
        'epp_server_code_pendingDelete', 'epp_server_code_pendingRenew',
        'epp_server_code_pendingRestore', 'epp_server_code_pendingTransfer',
        'epp_server_code_pendingUpdate', 'epp_server_code_redemptionPeriod',
        'epp_server_code_renewPeriod', 'epp_server_code_serverDeleteProhibited',
        'epp_server_code_serverHold', 'epp_server_code_serverRenewProhibited',
        'epp_server_code_serverTransferProhibited', 'epp_server_code_serverUpdateProhibited',
        'epp_server_code_transferPeriod', 'epp_server_code_clientDeleteProhibited',
        'epp_server_code_clientTransferProhibited', 'epp_server_code_clientUpdateProhibited',
        'epp_client_code_clientDeleteProhibited', 'epp_client_code_clientHold',
        'epp_client_code_clientRenewProhibited', 'epp_client_code_clientTransferProhibited',
        'epp_client_code_clientUpdateProhibited', 'dnssec', 'domain', 'name_server_domain',
        'whois_name', 'whois_org', 'whois_registrar', 'whois_server', 'whois_address_1',
        'whois_address_2', 'whois_city', 'whois_country', 'whois_state', 'whois_zipcode']
    try: w = whois.whois(host)
    except:
        logging.error("--  host: {} -- ".format(host), exc_info=True)
        
        attributes = [Attribute(st, None) for st in sub_types]
        dn = None
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
        
        epp_status_codes_obj = {
            'epp_server_code' : {
                'addPeriod':0, 'autoRenewPeriod':0, 'inactive':0, 'ok':0,
                'pendingCreate':0, 'pendingDelete':0, 'pendingRenew':0,
                'pendingRestore':0, 'pendingTransfer':0, 'pendingUpdate':0,
                'redemptionPeriod':0, 'renewPeriod':0, 'serverDeleteProhibited':0,
                'serverHold':0, 'serverRenewProhibited':0, 'serverTransferProhibited':0,
                'serverUpdateProhibited':0, 'transferPeriod':0
            },
            'epp_client_code' : {
                'clientDeleteProhibited':0, 'clientHold':0, 'clientRenewProhibited':0,
                'clientTransferProhibited':0, 'clientUpdateProhibited':0
            }
        }
        
        if isinstance(w.get('status'), list):
            for s in w['status']:
                s = s.split()[0]
                try: epp_status_codes_obj['epp_server_code'][s] = 1
                except: epp_status_codes_obj['epp_client_code'][s] = 1

        epp_feat = misc.features(epp_status_codes_obj, sep = '_', root_only=True)
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
    
    return attributes, dn
            



def get_geoip(ip):
    sub_types = ['continent_code', 'country_code', 'subdivision_code', 'city_name',
                 'postcode', 'latitude', 'longitude', 'timezone',
                 'registered_country_code', 'asn', 'asn_org']

    if not ip: return [Attribute(st, None) for st in sub_types]
    
    try:
        response = city_reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        attributes = [Attribute(st, None) for st in sub_types]
    else:
        continent = response.continent.code
        country = response.country.iso_code
        subdiv = response.subdivisions.most_specific.iso_code
        city = response.city.name
        postcode= response.postal.code
        lat = response.location.latitude
        long = response.location.longitude
        timezone = response.location.time_zone
        registered_country = response.registered_country.iso_code

        acontinent = Attribute('continent_code', continent)
        acountry = Attribute('country_code', country)
        asubdiv = Attribute('subdivision_code', subdiv)
        acity = Attribute('city_name', city)
        apostcode = Attribute('postcode', postcode)
        alat = Attribute('latitude', lat)
        along = Attribute('longitude', long)
        atz = Attribute('timezone', timezone)
        aregcount = Attribute('registered_country_code', registered_country)

        attributes = [acontinent, acountry, asubdiv, acity, apostcode,
                      alat, along, atz, aregcount]  

        try:
            response = asn_reader.asn(ip)
            asn = response.autonomous_system_number
            aso = response.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            asn, aso = None, None

        aasn = Attribute('asn', asn)
        aaso = Attribute('asn_org', aso)

        attributes +=[aasn, aaso]    

    return attributes




def host(u):
    url = u.url
    host = u.host

    whoisatts, domain = get_whois(host)
    ipatts, ip = get_ip(host, domain)
    geoipatts = get_geoip(ip)

    oh = Object('host_features', ipatts+whoisatts+geoipatts)
            
    return oh



def example1():
    from furl import furl
    e = "http://digitalcommons.usu.edu"
    e = "https://google.com"
    e = 'https://facebook.com'
    u = furl(e)


##    pprint(host(u).data)
    h = '133.1.2.5'
    get_whois2(h)
    
##    au = Attribute('url', e)     
##    olf = Object('host_features', host(u))
##
##    # URL Object
##    ou = Object('url', [au, olf])
##    pprint(ou.data)


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
