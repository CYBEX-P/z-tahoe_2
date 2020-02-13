from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import selenium.common.exceptions as err

from pprint import pprint

u = r"http://donnisiagian.com/db/2019/index.php"
u = r"http://jppost-apu.top/zp.html"
u = r"http://hovermop.com/bpm47/"
u = r"https://p4pal-signinupdateaccountapps.nsupdate.info/?apps"
u = r"http://mehrcardvip.com/wp-includes/ID3/www.alibaba.com/alibaba/"

opts = Options()
opts.log.level = "trace"

d = Firefox(options=opts, service_log_path='log.txt')
d.get(u)

d.implicitly_wait(10)
for j in range(3):
    inputs = d.find_elements_by_tag_name('input')
    for inp in inputs:
        try:
            inp_type = inp.get_attribute('type')
            inp_id = inp.get_attribute('id')
            inp_name = inp.get_attribute('name')
            inp_value = inp.get_attribute('value').lower()

            ishidden = inp_type in ['hidden']

            isemail = 'email' in [inp_type, inp_id, inp_name]

            ispass = 'password' in [inp_type, inp_id, inp_name]
            ispass = ispass or 'pass' in [inp_id, inp_name]

            isbutton = inp_type in ['image', 'submit']
            isbutton = isbutton or inp_value in ['sign in', 'login', 'log in', 'next']

            if isemail and not ishidden and not inp_value:
                inp.send_keys("abcde@fghi.com")                
            if ispass and not ishidden and not inp_value:
                inp.send_keys("Acvd1#254")
            if isbutton and not ishidden:
                inp.click()
        except err.StaleElementReferenceException:
            break
        
    try:
        b = d.find_element_by_tag_name('button')
        b.click()
    except:
        pass
    d.implicitly_wait(3)



##//input[@type='text' or @type='password']


##elem = driver.find_element_by_name("q")
##elem.clear()
##elem.send_keys("pycon")
##elem.send_keys(Keys.RETURN)
##assert "No results found." not in driver.page_source

d.close()
