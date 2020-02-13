## ----------------- From PyPI -----------------
import logging, geoip2.database


## ----------------- Not from PyPI -----------------
from tahoe import Attribute


asn_reader = geoip2.database.Reader('D:\\mal_url\\feature\\geolite2\\GeoLite2-ASN.mmdb')
city_reader = geoip2.database.Reader('D:\\mal_url\\feature\\geolite2\\GeoLite2-City.mmdb')
country_reader = geoip2.database.Reader('D:\\mal_url\\feature\\geolite2\\GeoLite2-Country.mmdb')


def get_geoip_att(ip):
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

 
