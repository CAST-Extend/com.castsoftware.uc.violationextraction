import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning 
from base64 import b64encode
import re
import os
import sys
import time
import subprocess
import json
#import psycopg2
import traceback

'''
Created on 13 avr. 2020

@author: MMR
'''

####################################################################################

class Filter:
    def __init__(self):
        None
        
class ViolationFilter(Filter):
    def __init__(self, criticalrulesonlyfilter, businesscriterionfilter, technicalcriterionfilter, technofilter, violationstatusfilter, qridfilter, qrnamefilter, modulefilter, nbrowsfilter):
        self.criticalrulesonly = criticalrulesonlyfilter
        self.technicalcriterion = technicalcriterionfilter
        self.businesscriterion = businesscriterionfilter
        self.modulefilter = modulefilter
        self.techno = technofilter
        self.violationstatus = violationstatusfilter
        self.nbrows = nbrowsfilter
        self.qrid = qridfilter
        self.qrname = qrnamefilter

class StringUtils:
    @staticmethod 
    def NonetoEmptyString(obj):
        if obj == None or obj == 'None':
            return ''
        return obj

    ########################################################################
    # workaround to remove the unicode characters before sending them to the CSV/Excel file
    # and avoid the below error
    #UnicodeEncodeError: 'charmap' codec can't encode character '\x82' in position 105: character maps to <undefined>    
    @staticmethod    
    def remove_unicode_characters(astr):
        return astr.encode('ascii', 'ignore').decode("utf-8")

    ########################################################################
    @staticmethod    
    def remove_semicolumn(astr):
        return astr.replace(';', '')

    ########################################################################
    @staticmethod
    def remove_trailing_suffix (mystr, suffix='rest'):
        # remove trailing /
        while mystr.endswith('/'):
            mystr = mystr[:-1]
        if mystr.endswith(suffix):
            return (mystr[:len(mystr)-len(suffix)-1])        
        else:
            return mystr

######################################################################################################################

class DateUtils:
    @staticmethod 
    # Format a timestamp date into a string
    def get_formatted_dateandtime(mydate):
        formatteddate = str(mydate.year) + "_"
        if mydate.month < 10:
            formatteddate += "0"
        formatteddate += str(mydate.month) + "_"
        if mydate.day < 10:
            formatteddate += "0"
        formatteddate += str(mydate.day)
        
        formatteddate += "_" 
        if mydate.hour < 10:
            formatteddate += "0"    
        formatteddate += str(mydate.hour)
        if mydate.minute < 10:
            formatteddate += "0"    
        formatteddate += str(mydate.minute)    
        if mydate.second < 10:
            formatteddate += "0"    
        formatteddate += str(mydate.second)    
        
        return formatteddate       

####################################################################################


class FileUtils:
    
    """Checks if a file is locked by opening it in append mode.
    If no exception thrown, then the file is not locked.
    """
    @staticmethod
    def is_file_locked_with_retries(filepath):
        logutils = LogUtils()
        filelocked = False
        icount = 0
        while icount < 10 and FileUtils.is_file_locked(filepath):
            icount += 1
            filelocked = True
            logutils.logwarning('File %s is locked. Please unlock it ! Waiting 5 seconds before retrying (try %s/10) ' % (filepath, str(icount)),True)
            time.sleep(5)
        if not FileUtils.is_file_locked(filepath):
            filelocked = False
        return filelocked        
    
    """Checks if a file is locked by opening it in append mode.
    If no exception thrown, then the file is not locked.
    """
    @staticmethod
    def is_file_locked(filepath):
    
        locked = False
        file_object = None
        if os.path.exists(filepath):
            try:
                #print ("Trying to open %s." % filepath)
                buffer_size = 8
                # Opening file in append mode and read the first 8 characters.
                file_object = open(filepath, 'a', buffer_size)
                if file_object:
                    #print ("%s is not locked." % filepath)
                    locked = False
            
            except IOError:
                e = sys.exc_info()[0]
                #print ("File is locked (unable to open in append mode). %s." % e)
                locked = True
            finally:
                if file_object:
                    file_object.close()
                    #print ("%s closed." % filepath)
        #else:
        #    print "%s not found." % filepath
        return locked


####################################################################################


        
        

class RestUtils:
    CLIENT_CURL = 'curl'
    CLIENT_REQUESTS = 'requests'
    
    USERAGENT = 'XY'
   
    def __init__(self, url, restclient, user=None, password = None, apikey = None, uselocalcache=False, cachefolder=None, extensionid='Community Extension'): 
        self.session_cookie = None
        self.session = None
        self.restclient = restclient
        self.url = url
        self.extensionid = extensionid
        self.user = user
        self.password = password
        self.apikey = apikey
        self.uselocalcache = uselocalcache
        self.cachefolder = cachefolder
        self.cachesubfolder = None 
    
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


    ####################################################################################################
    
    def get_json(self, request, apikey=None, cachefilename=None):
        logutils = LogUtils()
        json_filepath = self.get_cachefilepath(cachefilename)
        # create parent folder if required 
        if json_filepath != None and not os.path.exists(os.path.dirname(json_filepath)):
            os.path.dirname(json_filepath)
        # run rest command only if file do not exist or we don't use the local cache and force the data to be loaded again
        if self.uselocalcache and json_filepath != None and os.path.isfile(json_filepath):
            try:
                with open(json_filepath, 'r', encoding='utf-8') as json_file:
                #with open(json_filepath, 'r') as json_file:
                    return json.load(json_file)
            except UnicodeDecodeError:
                logutils.logwarning('Unicode decode error in json file %s: Skipping' % json_filepath, True)                
            except json.decoder.JSONDecodeError:
                logutils.logwarning('Invalid json file %s: Skipping' % json_filepath, True)  
        else:
            if self.restclient == 'curl':
                return self.execute_curl(request, apikey, json_filepath)
            elif self.restclient == 'requests':
                return self.execute_requests(request)    
    
    ####################################################################################################
    
    def modify_with_json(self, requesttype, request, apikey, inputjson, cachefilename=None, contenttype='text/plain'):
        if type(inputjson) == 'str':
            inputjsonstr = inputjson
        else:
            inputjsonstr = json.dumps(inputjson)  
        json_filepath = self.get_cachefilepath(cachefilename)
        # create parent folder if required 
        if not os.path.exists(os.path.dirname(json_filepath)):
            os.path.dirname(json_filepath)
        if self.restclient == 'curl':
            return self.execute_curl(request, apikey, json_filepath, requesttype, 'application/json', inputjsonstr)
        elif self.restclient == 'requests':
            return self.execute_requests(request, requesttype, 'application/json', inputjsonstr, contenttype)      
    
    ####################################################################################################
    """
    def put_json(self, request, apikey, inputjson, cachefilename=None):
        if type(inputjson) == 'str':
            inputjsonstr = inputjson
        else:
            inputjsonstr = json.dumps(inputjson)  
        json_filepath = self.get_cachefilepath(cachefilename)
        # create parent folder if required 
        if not os.path.exists(os.path.dirname(json_filepath)):
            os.path.dirname(json_filepath)
        if self.restclient == 'curl':
            return self.execute_curl(request, apikey, json_filepath, 'PUT', 'application/json', inputjsonstr)
        elif self.restclient == 'requests':
            return self.execute_requests(request, 'PUT', 'application/json', inputjsonstr, 'text/plain')        
    """
    ####################################################################################################
    def get_response_cookies(self, response):
        return response.headers._store 

    ####################################################################################################
    def get_cachefolderpath(self):
        folder = None
        if self.cachefolder != None:
            folder = self.cachefolder
            if self.cachesubfolder != None:
                folder += "\\" + self.cachesubfolder 
        return folder
    ####################################################################################################
    def get_cachefilepath(self, cachefilename):
        if cachefilename == None:
            return None
        folder = os.path.dirname(self.get_cachefolderpath() + '\\' + cachefilename)
        if folder != None and cachefilename != None:
            return "%s\%s" % (folder, cachefilename)
        else:
            return None

    ####################################################################################################
    def execute_curl(self, request, apikey, cachefilepath, requesttype='GET', accept='application/json', inputjsonstr=None):
        logutils = LogUtils()
        json_output = None
        request_text = self.url + request
        
        strcmd = 'curl %s' % request_text
        strcmd += ' -X %s' % requesttype
        strcmd += ' -H "Accept: ' + accept + '"'
        strcmd += ' -H "User-Agent: '+ RestUtils.USERAGENT + '"'
        strcmd += ' -H "X-Client: ' + self.extensionid + '"'
        if self.apikey != None and self.apikey != 'N/A':
            strcmd += ' -H "X-API-KEY: ' + self.apikey+ '"'
            # add user if we use the API KEY
            if self.user != None and self.user != 'N/A':
                strcmd += ' -H "X-API-USER: ' + self.user+ '"'
        if self.user != None and self.password != None and self.user != 'N/A' and self.password != 'N/A':
            strcmd += ' -u ' + self.user + ':' + self.password            
        strcmd += ' -H "Connection: keep-alive"'
        if requesttype != 'GET':
            strcmd += ' -H  "Content-Type: application/json"' 
            strcmd += ' -d "' + inputjsonstr.replace('"','\\"') + '"'
        strcmd += ' -o "%s"' % cachefilepath

        if not os.path.exists(os.path.dirname(cachefilepath)):
            os.makedirs(os.path.dirname(cachefilepath))

        logutils.logdebug("curl running: " + strcmd, True)
        status, curl_output = subprocess.getstatusoutput(strcmd)
        if status != 0:
            # error
            logutils.logerror("Error running %s - curl status %s" % (request_text, str(status)), True)
            logutils.logerror("curl output %s" % curl_output)
            raise SystemError                

        # if no error send back a json string containing data from the cache file just loaded
        try:
            with open(cachefilepath, 'r') as json_file:
                json_output = json.load(json_file)
        except UnicodeDecodeError:
            logutils.logwarning('Unicode decode error in json file %s: Skipping' % cachefilepath, True)
        except json.decoder.JSONDecodeError:
            logutils.logwarning('Invalid json file %s: Skipping' % cachefilepath, True)   

        return json_output
    
    ####################################################################################################
    
    # get the response session cookie containing JSESSION
    def get_session_cookie(self, response):
        session_cookie = None
        response_cookies = self.get_response_cookies(response)
        if response_cookies != None:
            sc = response_cookies.get('set-cookie')
            if sc != None and sc[1]  != None:
                session_cookie = sc[1]        
        return session_cookie
    
    ####################################################################################################
    # retrieve the connection
    def open_session(self, resturi=''):
        logutils = LogUtils()
        if self.restclient == 'curl':
            # Nothing to do for curl
            None
        elif self.restclient == 'requests':
            uri = self.url + '/' +  resturi
            logutils.loginfo('Opening session to ' + uri)
            response = None
            request_headers = {}
            #request_headers.update(self.get_default_http_headers())        
            request_headers.update({'accept':'application/json'})        
            try:
                self.session = requests.session()
                if self.user != None and self.password != None and self.user != 'N/A' and self.password != 'N/A':
                    logutils.loginfo ('Using user and password')
                    #we need to base 64 encode it 
                    #and then decode it to acsii as python 3 stores it as a byte string
                    #userAndPass = b64encode(user_password).decode("ascii")
                    auth = str.encode("%s:%s" % (self.user, self.password))
                    #user_and_pass = b64encode(auth).decode("ascii")
                    user_and_pass = b64encode(auth).decode("iso-8859-1")
                    request_headers.update({'Authorization':'Basic %s' %  user_and_pass})
                # else if the api key is provided
                elif self.apikey != None and self.apikey != 'N/A':
                    logutils.loginfo ('Using api key')
                    # API key configured in the Health / Engineering / REST-API WAR
                    request_headers.update({'X-API-KEY':self.apikey})
                    if self.user != None and self.user != 'N/A':
                        request_headers.update({'X-API-USER':self.user})
                    # we are provide a user name hardcoded' 
                    #request_headers.update({'X-API-USER':'admin_apikey'})            
                    # API key configured in ExtenNG
                    #request_headers.update({'x-nuget-apikey':self.apikey})
                
                logutils.loginfo ('request headers = ' + str(request_headers))
                
                response = self.session.get(uri, headers=request_headers, verify=False)
                
            except:
                logutils.logerror ('Error connecting to ' + uri)
                logutils.logerror ('URL is not reachable. Please check your connection (web application down, VPN not active, ...)')
                raise SystemExit
            #finally:
            #    logutils.loginfo ('Headers = ' + str(response.headers))
                
            if response.status_code != 200:
                # This means something went wrong.
                logutils.logerror ('Error connecting to ' + uri)
                logutils.loginfo ('Status code = ' + str(response.status_code))
                logutils.loginfo ('response headers = ' + str(response.headers))
                logutils.loginfo ('Please check the URL, user and password or api key')
                raise SystemExit
            else: 
                logutils.loginfo ('Successfully connected to  : ' + self.url)    
    
    ####################################################################################################

    def get_default_http_headers(self):
        logutils = LogUtils()
        # User agent & Name of the client added in the header (for the audit trail)
        default_headers = {"User-Agent": "XY", "X-Client": self.extensionid} 
        return default_headers

    ####################################################################################################
    def execute_requests(self, request, requesttype='GET', accept='application/json', inputjsonstr=None, contenttype='application/json'):
        logutils = LogUtils()
        if self.session == None:
            self.session = self.open_session()
            
        if request == None:
            request_text = self.url
        else:
            request_text = self.url
            if not request_text.endswith('/'): request_text += '/'
            request_text += request
        
        request_headers = {}
        request_headers.update(self.get_default_http_headers())
        request_headers.update({'accept' : accept})
        try:
            request_headers.update({'X-XSRF-TOKEN': self.session.cookies['XSRF-TOKEN']})
        except KeyError:
            None
        request_headers.update({'Content-Type': contenttype})
    
        logutils.logdebug('Sending ' + requesttype + ' ' + request_text + ' with contenttype=' + contenttype + ' json=' + str(inputjsonstr), False)
        #logutils.logdebug('  Request headers=' + json.dumps(request_headers) , False)
    
        # send the request
        if 'GET' == requesttype:
            response = self.session.get(request_text,headers=request_headers, verify=False)
        elif 'POST' == requesttype:
            response = self.session.post(request_text,inputjsonstr,headers=request_headers)
        elif 'PUT' == requesttype:
            response = self.session.put(request_text,inputjsonstr,headers=request_headers)        
        elif 'DELETE' == requesttype:
            response = self.session.delete(request_text,inputjsonstr,headers=request_headers)    
        else:
            logutils.logerror('Invalid HTTP request type' + requesttype)
        
        output = None
        if response != None:
            #logutils.logdebug('  HTTP code=%s headers=%s'% (str(response.status_code), json.dumps(response.headers._store)), False)
            
            # Error
            if response.status_code not in (200, 201, 204):
                logutils.logerror('HTTP(S) request failed ' + str(response.status_code) + ' :' + request_text,True)
                if response.text != None:
                    logutils.logerror('%s' % str(response.text), True)
                return None
            else:
                # get the session cookie containing JSESSION
                # look for the Set-Cookie in response headers, to inject it for future requests
                session_cookie = self.get_session_cookie(response)
                if session_cookie != None:
                    # copy the session cookie
                    self.session_cookie = session_cookie
                    #print('3='+session_cookie)
                
                if contenttype == 'application/json':
                    output = response.json()
                else:
                    output = response.text
    
        return output 
    
    ####################################################################################################
    
    def execute_requests_get(self, request, accept='application/json', content_type='application/json'):
        return self.execute_requests(request, 'GET', accept, None, content_type)
    
    ####################################################################################################
    
    def execute_requests_post(self, request, accept='application/json', inputjson=None, contenttype='application/json'):
        return self.execute_requests(request, 'POST', accept, inputjson, contenttype)
    
    ####################################################################################################
    
    def execute_requests_put(self, request, accept='application/json', inputcontent=None, contenttype='application/json'):
        return self.execute_requests(request, 'PUT', accept, inputcontent, contenttype)
    
    ####################################################################################################
    
    def execute_requests_delete(self, request, accept='application/json', inputjson=None, contenttype='application/json'):
        return self.execute_requests(request, 'DELETE', accept, inputjson, contenttype)


########################################################################


########################################################################
# snapshot class
class Domain:
    def __init__(self, href=None, name=None, version=None, schema=None):
        self.href = href
        self.name = name
        self.version = version
        self.schema = schema
    
    @staticmethod
    def load(json):
        if json != None:
            d = Domain()
            d.href = json['href']
            d.name = json['name']
            d.version = json['version']
            d.schema = json['schema']
            return d
        else: return None
    
    def isAAD(self):
        return self.name != None and self.name == 'AAD'
    
    @staticmethod
    def loadlist(json):
        domainlist = []
        if json != None:
            for item in json:
                domainlist.append(Domain.load(item)) 
        return domainlist

########################################################################

# Application
class Application:
    def __init__(self):
        self.href = None
        self.name = None
        self.id = None
        self.schema_central = None
        self.schema_local = None
        self.schema_mgnt = None
    
    @staticmethod   
    def load(json):
        if json != None:   
            x = Application()
            x.href = json['href']
            x.name = json['name']
            x.id = AIPRestAPI.get_href_id(x.href)
            return x  
        else: return None
        
    @staticmethod
    def loadlist(json):
        applicationlist = []
        if json != None:
            for item in json:
                applicationlist.append(Application.load(item)) 
        return applicationlist        
        
########################################################################

# server status
class Server:
    def __init__(self):
        self.version = None
        self.status = None
        self.freememory = None
    
    @staticmethod   
    def load(json):
        if json != None:   
            x = Server()
            #servversion2digits = servversion[-4:] 
            #if float(servversion2digits) <= 1.13 : 
            #    None
            x.version = json['version']
            x.status = json['status']
            x.freememory = json['memory']['freeMemory']
            return x                
        else: return None
        
########################################################################
# module class
class ModuleUnit:
    def __init__(self, href=None, name=None):
        self.id = None
        self.href = href
        self.name = name
        self.including_snapshots = []
        self.init_id()


    @staticmethod
    def get_moduleid_from_href(href):
        moduleid = None
        if href:
            for item in href.split(sep='/'):
                moduleid = item        
        return moduleid

    def init_id(self):
        self.id = ModuleUnit.get_moduleid_from_href(self.href)       

    @staticmethod
    def load(json_module):
        x = ModuleUnit()
        if json_module != None:
            x.name = json_module['name']
            x.href = json_module['href']
            x.init_id()            
            
        return x
    @staticmethod
    def loadlist(json_modules):
        objlist = []
        if json_modules != None:
            for json_module in json_modules:
                objlist.append(ModuleUnit.load(json_module)) 
        return objlist  
##################################################################################

# snapshot filter class
class SnapshotFilter:
    def __init__(self, snapshot_index, snapshot_ids):
        self.snapshot_index = snapshot_index
        self.snapshot_ids = snapshot_ids

########################################################################

# snapshot class
class Snapshot:
    def __init__(self, href=None, domainname=None, applicationid=None, applicationname=None, snapshotid=None, isodate=None, version=None):
        self.href = href
        self.domainname = domainname
        self.applicationid = applicationid
        self.snapshotid = snapshotid
        self.isodate = isodate
        self.version = version
        self.versionname = None
        self.applicationname = applicationname
        self.time = None
        self.number = None
        self.technologies = None
        self.modules = None
        self.rank = None
        self.last = None
        self.beforelast = None
        self.first = None

    def get_technologies_as_string(self):
        strtechnologies = ''
        if self.technologies != None:
            for t in self.technologies:
                strtechnologies += t + ','
            if ',' in strtechnologies:
                strtechnologies = strtechnologies[:-1]
        return strtechnologies

    @staticmethod
    def load(json_snapshot, last, beforelast, first, rank):
        x = Snapshot()
        if json_snapshot != None:
            x.version = json_snapshot['annotation']['version']
            x.versionname = json_snapshot['annotation']['name']
            x.href = json_snapshot['href']
            x.applicationname = json_snapshot['name']
            x.isodate = json_snapshot['annotation']['date']['isoDate']
            x.time = json_snapshot['annotation']['date']['time']
            x.number = json_snapshot['number']
            x.last = last
            x.beforelast = beforelast
            x.first = first
            x.rank = rank
            try:
                x.technologies = json_snapshot['technologies']
            except KeyError:
                None

            x.applicationid = -1
            x.snapshotid = -1
            """rexappsnapid = "([-A-Z0-9_]+)/applications/([0-9]+)/snapshots/([0-9]+)"
            m0 = re.search(rexappsnapid, x.href)
            if m0: 
                x.domainname = m0.group(1)
                x.applicationid = m0.group(2)
                x.snapshotid = m0.group(3)
            """
            rex = "/snapshots/([0-9]+)"
            m0 = re.search(rex, x.href)
            if m0: 
                x.snapshotid = m0.group(1)
            rex = "/applications/([0-9]+)/"
            m0 = re.search(rex, x.href)
            if m0: 
                x.applicationid = m0.group(1)      
            rex = "(.*)/applications"
            m0 = re.search(rex, x.href)
            if m0: 
                x.domainname = m0.group(1)      
        return x
    @staticmethod
    def loadlist(json_snapshots):
        snapshotlist = []
        if json_snapshots != None:
            icount = 0
            rank = ""
            for json_snapshot in json_snapshots:
                icount += 1
                if icount==1:
                    rank="N"
                elif icount==2:
                    rank="N-1"
                else:
                    rank = "N-" + str(int(rank.split('-')[1])+1)
                snapshotlist.append(Snapshot.load(json_snapshot, icount==1, icount==2, icount==len(json_snapshots),rank)) 
        return snapshotlist  

########################################################################
   
# Module class
class Module:
    def __init__(self):
        self.href = None
        self.domainname = None
        self.snapshotid = None
        self.moduleid = None
        self.modulename = None
        self.technologies = None

    def get_technologies_as_string(self):
        strtechnologies = ''
        if self.technologies != None:
            for t in self.technologies:
                strtechnologies += t + ','
            if ',' in strtechnologies:
                strtechnologies = strtechnologies[:-1]
        return strtechnologies

    @staticmethod
    def load(json_module):
        x = Module()
        if json_module != None:
            x.href = json_module['href']
            x.modulename = json_module['name']
            try:
                x.technologies = json_module['technologies']
            except KeyError:
                None
            x.moduleid = -1
            x.snapshotid = -1
            rexappsnapid = "([A-Z0-9_]+)/modules/([0-9]+)/snapshots/([0-9]+)"
            m0 = re.search(rexappsnapid, x.href)
            if m0: 
                x.domainname = m0.group(1)
                x.moduleid = m0.group(2)
                x.snapshotid = m0.group(3)   
        return x
    @staticmethod
    def loadlist(json_modules):
        listmodules = []
        if json_modules != None:
            for json in json_modules:
                listmodules.append(Module.load(json)) 
        return listmodules 
  
########################################################################
  

########################################################################

# CAST AIP Dahshboard REST API 
class AIPRestAPI:
    FILTER_ALL = "$all"
    FILTER_SNAPSHOTS_ALL = FILTER_ALL
    FILTER_SNAPSHOTS_LAST = "-1"
    FILTER_SNAPSHOTS_LAST_TWO = "-2"
    
    ########################################################################
    
    def __init__(self, restutils): 
        self.restutils = restutils
      
    ########################################################################
    # extract the last element that is the id
    @staticmethod
    def get_href_id(href, separator='/'):
        if href == None or separator == None:
            return None
        href_id = ""
        hrefsplit = href.split('/')
        for elem in hrefsplit:
            # the last element is the id
            href_id = elem    
        return href_id      
        
    ########################################################################
    # get mngt or schema name from the central schema name
    # assumption for the naming convention all the triplet schemas have same prefix + have default suffixes (_mngt, _central, _local)  
    @staticmethod
    def get_schema_name(centralschemaname, suffix='mngt'):
        if centralschemaname == None or suffix == None:
            return None
        schema = ''
        schema_split = centralschemaname.split("_")
        icount=0
        for sc in schema_split:
            icount+=1
            if (icount < len(schema_split)):
                schema += sc
            if (icount < len(schema_split) - 1):
                schema += "_"
        schema += "_" + suffix
        return schema        

    ########################################################################
    # Extract the packages list (platform and extension) installed & referenced in the mngt schema
    '''def get_mngt_schema_packages(self, domainname, appname, mngt_schema, host="localhost", port="2282", database="postgres", user="operator", password="CastAIP"):
        listpackages = []
        json_packages = []
        conn = None
        cur = None
        try:
            if not os.path.exists(self.restutils.get_cachefolderpath()): 
                os.makedirs(self.restutils.get_cachefolderpath())
            cachefilepath = self.restutils.get_cachefolderpath() + '\\packages_' + domainname + "_" + appname + ".json"
            if self.restutils.uselocalcache and cachefilepath != None and os.path.isfile(cachefilepath):
                with open(cachefilepath, 'r') as json_file:
                    json_packages = json.load(json_file)
            else:
                # load data from DB and save json data to disk
                conn = psycopg2.connect(host=host, port = port, database=database, user=user, password=password)
                cur = conn.cursor()
                sql = "SELECT package_name,version FROM " + mngt_schema + ".sys_package_version where package_name like '%CORE_PMC%' or package_name like '%com%' order by 1 desc"
                logutils.logdebug("sql="+sql)
                #minjus_genesis_82_mngt.sys_package_version where package_name like '%CORE_PMC%' or package_name like '%com%' order by 1 desc"""
                cur.execute(sql) 
                for package_name, version in cur.fetchall():
                    if package_name == 'CORE_PMC':
                        package_type = "platform"
                    else:
                        package_type = "extension"
                        if package_name[0:1] == '/':
                            package_name = package_name[1:]
                    json_packages.append(
                            {
                                "package_type": package_type, 
                                "package_mngt_id": package_name, 
                                "package_mngt_version": version}
                            )
                # create cache file
                with open(cachefilepath, 'w') as json_file:
                    json.dump(json_packages, json_file)

            if json_packages != None:
                listpackages = PackageMngt.loadlist_from_mngt(json_packages)

        except:
            tb = traceback.format_exc()
            logutils.logerror("Error extracting the versions from postgresql %s" % tb, True)
        finally:
            if cur is not None:
                cur.close()
            if conn is not None:
                conn.close()
    '''   

        
    ########################################################################

    def get_server_json(self):
        request = "server"
        return self.restutils.get_json(request)
    
    def get_server(self):
        return Server.load(self.get_server_json())

    ########################################################################
    def get_domains_json(self):
        request = ""
        return self.restutils.execute_requests_get(request)

    def get_domains(self):
        return Domain.loadlist(self.get_domains_json())
        
    ########################################################################
    def get_modules_json(self,domainname,applicationid):
        request = domainname + "/applications/" + applicationid + "/modules"
        return self.restutils.execute_requests_get(request)

    def get_modules_snapshots_json(self,domainname,applicationid, modulehref):
        request = modulehref + "/snapshots" 
        return self.restutils.execute_requests_get(request)

    def get_modules(self,domainname,applicationid):
        list_modules = ModuleUnit.loadlist(self.get_modules_json(domainname,applicationid))
        for module in list_modules:
            json_module_snapshots = self.get_modules_snapshots_json(domainname, applicationid, module.href)
            for json_snapshot in json_module_snapshots:
                snapshot_href = None
                try:
                    snapshot_href = json_snapshot["applicationSnapshot"]["href"]
                    snapshot_id = ModuleUnit.get_moduleid_from_href(snapshot_href)
                except KeyError:
                    None
                if snapshot_id:
                    module.including_snapshots.append(snapshot_id)
        
        return list_modules
    ########################################################################
    def get_applications_json(self, domain):
        request = domain + "/applications"
        return self.restutils.execute_requests_get(request)
    
    def get_applications(self, domain):
        applicationlist = Application.loadlist(self.get_applications_json(domain.name))
        for app in applicationlist:
            if domain.schema != None and "_central" in domain.schema:
                app.schema_central = domain
                app.schema_mngt = AIPRestAPI.get_schema_name(domain.schema, "mngt")
                app.schema_local = AIPRestAPI.get_schema_name(domain.schema, "local")
        return applicationlist
    
    ########################################################################
    def get_transactions_per_business_criterion(self, domainname, applicationid, snapshotid, bcid, nbrows):
        logutils = LogUtils()
        logutils.loginfo("Extracting the transactions for business criterion " + bcid)
        request = domainname + "/applications/" + applicationid + "/snapshots/" + snapshotid + "/transactions/" + bcid
        request += '?startRow=1'
        request += '&nbRows=' + str(nbrows)    
        return self.restutils.execute_requests_get(request)
    
    ########################################################################
    def get_application_snapshots_json(self, domainname, applicationid):
        request = domainname + "/applications/" + applicationid + "/snapshots" 
        return self.restutils.execute_requests_get(request)
    
    def get_application_snapshot_modules_json(self, domainname, applicationid, snapshotid):
        request = domainname + "/applications/" + str(applicationid) + "/snapshots/" + str(snapshotid) + "/modules" 
        return self.restutils.execute_requests_get(request)    
    
    def get_application_snapshots(self, domainname, applicationid):
        snapshotlist = Snapshot.loadlist(self.get_application_snapshots_json(domainname, applicationid))
        for it in snapshotlist:
            modulelist = Module.loadlist(self.get_application_snapshot_modules_json(domainname, applicationid, it.snapshotid))
            it.modules = modulelist 
        return snapshotlist 
    
    def get_application_modules(self, domainname, applicationid, snapshotid):
        modulelist = Module.loadlist(self.get_application_snapshot_modules_json(domainname, applicationid, snapshotid))
        return modulelist
    
    ########################################################################
    def get_total_number_violations_json(self, domain, applicationid, snapshotid):
        logutils = LogUtils()
        logutils.loginfo("Extracting the number of violations")
        request = domain + "/results?sizing-measures=67011,67211&application=" + applicationid + "&snapshot=" + snapshotid
        return self.restutils.execute_requests_get(request)
    
    ########################################################################
    def get_qualitydistribution_details_json(self, domain, applicationid, snapshotid, metricid, category, nbrows):
        request = domain + "/applications/" + str(applicationid) + "/snapshots/" + str(snapshotid) + '/components/' + str(metricid) + '/'
        request += str(category)+'?business-criterion=60017&startRow=1&nbRows=' + str(nbrows)
        return self.restutils.execute_requests_get(request)
    
    ########################################################################
    def get_dict_cyclomaticcomplexity_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        #Very High Complexity Artifacts
        categories = [1,2,3,4]
        labels = {1:'Very High Complexity Artifacts',2:'High Complexity Artifacts',3:'Moderate Complexity Artifacts',4:'Low Complexity Artifacts'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_CYCLOMATIC_COMPLEXITY, cat, nbrows)
            icount = 0
            if json != None:
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                    
                logutils.loginfo('Cyclomatic complexity distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict

    ########################################################################
    def get_dict_costcomplexity_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        categories = [1,2,3,4]
        labels = {1:'Very High Complexity',2:'High Complexity',3:'Moderate Complexity',4:'Low Complexity'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_COST_COMPLEXITY, cat, nbrows)
            icount = 0
            if json != None:
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                logutils.loginfo('Cost complexity distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict

    ########################################################################
    def get_dict_fanout_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        categories = [1,2,3,4]
        labels = {1:'Very High Fan-Out classes',2:'High Fan-Out classes',3:'Moderate Fan-Out classes',4:'Low Fan-Out classes'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_FAN_OUT, cat, nbrows)
            icount = 0
            if json != None:            
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                logutils.loginfo('Fan-Out classes distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict

    ########################################################################
    def get_dict_fanin_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        #Very High Fan-In classes
        categories = [1,2,3,4]
        labels = {1:'Very High Fan-In classes',2:'High Fan-In classes',3:'Moderate Fan-In classes',4:'Low Fan-In classes'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_FAN_IN, cat, nbrows)
            icount = 0
            if json != None:            
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                logutils.loginfo('Fan-In classes distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict

    ########################################################################
    def get_dict_coupling_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        #Very High Coupling Artifacts
        categories = [1,2,3,4]
        labels = {1:'Very High Coupling Artifacts',2:'High Coupling Artifacts',3:'Average Coupling Artifacts',4:'Low Coupling Artifacts'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_COUPLING, cat, nbrows)
            icount = 0
            if json != None:                 
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                logutils.loginfo('Coupling distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict

    ########################################################################
    def get_dict_size_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        categories = [1,2,3,4]
        # Very Large Size Artifacts
        labels = {1:'Very Large Size Artifacts',2:'Large Size Artifacts',3:'Average Size Artifacts',4:'Small Size Artifacts'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_SIZE, cat, nbrows)
            icount = 0
            if json != None:
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                logutils.loginfo('Size distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict
    ########################################################################
    def get_dict_SQLcomplexity_distribution(self, domain, applicationid, snapshotid, nbrows):
        logutils = LogUtils()
        dict = {}
        categories = [1,2,3,4]
        # Very Large Size Artifacts
        labels = {1:'Very High SQL Complexity Artifacts',2:'High SQL Complexity Artifacts',3:'Moderate SQL Complexity Artifacts',4:'Low Complexity Artifacts'}
        for cat in categories:
            json = self.get_qualitydistribution_details_json(domain, applicationid, snapshotid, Metric.DIST_SQL_COMPLEXITY, cat, nbrows)
            icount = 0
            if json != None:            
                for it in json:
                    icount += 1
                    dict.update({it['href']:labels.get(cat)})
                logutils.loginfo('SQL complexity distribution cat ' + str(cat) + ' : ' + str(icount), False)
        return dict
    ########################################################################
    def get_distributions_details(self, domain, applicationid, snapshotid, nbrows):
        dict = {}
        # cyclomatic complexity dist.
        dict.update({Metric.DIST_CYCLOMATIC_COMPLEXITY:self.get_dict_cyclomaticcomplexity_distribution(domain, applicationid, snapshotid, nbrows)})
        # cost complexity dist.
        dict.update({Metric.DIST_COST_COMPLEXITY:self.get_dict_costcomplexity_distribution(domain, applicationid, snapshotid, nbrows)})        
        # fan in dist.
        dict.update({Metric.DIST_FAN_IN:self.get_dict_fanin_distribution(domain, applicationid, snapshotid, nbrows)})
        # fan out dist.
        dict.update({Metric.DIST_FAN_OUT:self.get_dict_fanout_distribution(domain, applicationid, snapshotid, nbrows)})
        # size dist.
        dict.update({Metric.DIST_SIZE:self.get_dict_size_distribution(domain, applicationid, snapshotid, nbrows)})
        # coupling dist.
        dict.update({Metric.DIST_COUPLING:self.get_dict_coupling_distribution(domain, applicationid, snapshotid, nbrows)})
        # SQL dist.
        dict.update({Metric.DIST_SQL_COMPLEXITY:self.get_dict_SQLcomplexity_distribution(domain, applicationid, snapshotid, nbrows)})        
        
        return dict

    ########################################################################
    def get_snapshot_modules_violations(self, domainname, moduleid, snapshotid, violationfilter):
        logutils = LogUtils()
        logutils.loginfo("Extracting the module snapshot violations")
        request = domainname + "/modules/" + moduleid + "/snapshots/" + snapshotid + '/violations'
        request += '?startRow=1'
        request += '&nbRows=' + str(violationfilter.nbrows)
        
        # we can't have 2 rule-pattern params filled, else the most wide will be used, nor the most narrow (it will use "or" not "and")
        rule_patterns_filled = False

        # filter on violation status
        if violationfilter.violationstatus != None:
            request += '&status=' + violationfilter.violationstatus

        # filter on technology
        if violationfilter.techno != None:
            request += '&technologies=' + violationfilter.techno

        # filter on list of quality rules ids
        if violationfilter.qrid != None:
            strqrid = str(violationfilter.qrid)
            if not rule_patterns_filled:
                request += '&rule-pattern=('
                for item in strqrid.split(sep=','):
                    request += item + ','
                request = request[:-1]
                request += ')'
                rule_patterns_filled = True                
                
        # filter on business criterion, or several business criterias
        elif violationfilter.businesscriterion != None:
            strbusinesscriterionfilter = str(violationfilter.businesscriterion)        
            # we can't have multiple value separated with a comma
            if ',' not in strbusinesscriterionfilter:
                request += '&business-criterion=' + strbusinesscriterionfilter
            elif not rule_patterns_filled:
                # case of multiple value separated with a comma, cannot be combined with list of quality rules ids 
                request += '&rule-pattern=('
                for item in strbusinesscriterionfilter.split(sep=','):
                    request += 'cc:' + item + ','
                    if violationfilter.criticalrulesonly == None or not violationfilter.criticalrulesonly:   
                        request += 'nc:' + item + ','
                request = request[:-1]
                request += ')'
                rule_patterns_filled = True
        
        elif violationfilter.technicalcriterion != None:
            strtechnicalcriterionfilter = str(violationfilter.technicalcriterion)
            request += '&rule-pattern=('
            for item in strtechnicalcriterionfilter.split(sep=','):
                request += 'c:' + item + ','
            request = request[:-1]
            request += ')' 
        elif not rule_patterns_filled and violationfilter.criticalrulesonly != None and violationfilter.criticalrulesonly:
            # cannot be combined with list of quality rules ids, or several business criterias         
            request += '&rule-pattern=critical-rules'
            rule_patterns_filled = True
        

             
        return self.restutils.execute_requests_get(request)               
               
                
    ########################################################################
    def get_snapshot_violations_json(self, domainname, applicationid, snapshotid, violationfilter):
        logutils = LogUtils()
        logutils.loginfo("Extracting the snapshot violations")

        request = domainname + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/violations'
        request += '?startRow=1'
        request += '&nbRows=' + str(violationfilter.nbrows)
        
        # we can't have 2 rule-pattern params filled, else the most wide will be used, nor the most narrow (it will use "or" not "and")
        rule_patterns_filled = False

        # filter on violation status
        if violationfilter.violationstatus != None:
            request += '&status=' + violationfilter.violationstatus

        # filter on technology
        if violationfilter.techno != None:
            request += '&technologies=' + violationfilter.techno

        # filter on list of quality rules ids
        if violationfilter.qrid != None:
            strqrid = str(violationfilter.qrid)
            if not rule_patterns_filled:
                request += '&rule-pattern=('
                for item in strqrid.split(sep=','):
                    request += item + ','
                request = request[:-1]
                request += ')'
                rule_patterns_filled = True                
                
        # filter on business criterion, or several business criterias
        elif violationfilter.businesscriterion != None:
            strbusinesscriterionfilter = str(violationfilter.businesscriterion)        
            # we can't have multiple value separated with a comma
            if ',' not in strbusinesscriterionfilter:
                request += '&business-criterion=' + strbusinesscriterionfilter
            elif not rule_patterns_filled:
                # case of multiple value separated with a comma, cannot be combined with list of quality rules ids 
                request += '&rule-pattern=('
                for item in strbusinesscriterionfilter.split(sep=','):
                    request += 'cc:' + item + ','
                    if violationfilter.criticalrulesonly == None or not violationfilter.criticalrulesonly:   
                        request += 'nc:' + item + ','
                request = request[:-1]
                request += ')'
                rule_patterns_filled = True
        
        elif violationfilter.technicalcriterion != None:
            strtechnicalcriterionfilter = str(violationfilter.technicalcriterion)
            request += '&rule-pattern=('
            for item in strtechnicalcriterionfilter.split(sep=','):
                request += 'c:' + item + ','
            request = request[:-1]
            request += ')' 
        elif not rule_patterns_filled and violationfilter.criticalrulesonly != None and violationfilter.criticalrulesonly:
            # cannot be combined with list of quality rules ids, or several business criterias         
            request += '&rule-pattern=critical-rules'
            rule_patterns_filled = True
        
        if violationfilter.modulefilter:
            if violationfilter.modulefilter == "$all":
                request += '&modules=$all'
            else:
                request += '&modules=(' + violationfilter.modulefilter + "')"
            
        return self.restutils.execute_requests_get(request)
        
        
    def get_snapshot_violations(self, domainname, applicationid, snapshotid, edurl=None, snapshothref=None, tqiqm=None, listtccontributions=None, violationfilter=None):
        logutils = LogUtils()
        logutils.loginfo("Extracting violations (modulesfilter=%s)" % str(violationfilter.modulefilter),True)
        json_violations = []
        listviolations = []
        #modules_violations = {}
        violations_modules = {}
        
        # modules violations
        if violationfilter.modulefilter and violationfilter.modulefilter == "$all":
            for module in self.get_modules(domainname, applicationid):
                logutils.loginfo("  processing module %s" % str(module.name),True)
                if snapshotid in module.including_snapshots:
                    module_json_violations = self.get_snapshot_modules_violations(domainname,module.id,snapshotid, violationfilter)
                    json_violations += module_json_violations
                    """module_violations = modules_violations.get(module.name) 
                    if not module_violations:
                        modules_violations[module.name] = []
                        module_violations = modules_violations.get(module.name)
                    """
                    for violation in module_json_violations:
                        #modules_violations[module.name].append(violation)
                        
                        try:                                    
                            qrrulepatternhref = violation['rulePattern']['href']
                        except KeyError:
                            qrrulepatternhref = None
                        try:
                            componentHref = violation['component']['href']
                        except KeyError:
                            componentHref = None
                        if qrrulepatternhref and componentHref:
                            violationid = qrrulepatternhref+'#'+componentHref
                            violation_modules = violations_modules.get(violationid) 
                            if not violation_modules:
                                violations_modules[violationid] = []
                            violations_modules[violationid].append(module.name)
        
            
            #with open('violations_modules.json', 'w') as f:
            #    json.dump(violations_modules, f)
        
        # application violations
        else:
            json_violations = self.get_snapshot_violations_json(domainname, applicationid, snapshotid, violationfilter)                                            
        if json_violations != None:
            iCouterRestAPIViolations = 0
            for violation in json_violations:
                objviol = Violation()
                iCouterRestAPIViolations += 1
                currentviolurl = ''
                violations_size = len(json_violations)
                imetricprogress = int(100 * (iCouterRestAPIViolations / violations_size))
                if iCouterRestAPIViolations==1 or iCouterRestAPIViolations==violations_size or iCouterRestAPIViolations%500 == 0:
                    logutils.loginfo("processing violation " + str(iCouterRestAPIViolations) + "/" + str(violations_size)  + ' (' + str(imetricprogress) + '%)',True)
                try:
                    objviol.qrname = violation['rulePattern']['name']
                except KeyError:
                    qrname = None    
                       
                try:                                    
                    objviol.qrrulepatternhref = violation['rulePattern']['href']
                except KeyError:
                    objviol.qrrulepatternhref = None
                                                                
                qrrulepatternsplit = objviol.qrrulepatternhref.split('/')
                for elem in qrrulepatternsplit:
                    # the last element is the id
                    objviol.qrid = elem                                            
                
                # critical contribution
                objviol.qrcritical = '<Not extracted>'
                try:
                    if tqiqm:
                        qrdetails = tqiqm[objviol.qrid]
                        if tqiqm != None and qrdetails != None and qrdetails.get("critical") != None:
                            objviol.critical = str(qrdetails.get("critical"))
                except KeyError:
                    logutils.logwarning('Could not find the critical contribution for %s'% str(objviol.qrid), True)
                    
                # filter on quality rule id or name, if the filter match
                if violationfilter.qrid != None and not re.match(violationfilter.qrid, str(objviol.qrid)):
                    continue
                if violationfilter.qrname != None and not re.match(violationfilter.qrname, qrname):
                    continue
                actionPlan = violation['remedialAction']
                try:               
                    objviol.hasActionPlan = actionPlan != None
                except KeyError:
                    logutils.logwarning('Not able to extract the action plan')
                if objviol.hasActionPlan:
                    try:               
                        objviol.actionplanstatus = actionPlan['status']
                        objviol.actionplantag = actionPlan['tag']
                        objviol.actionplancomment = actionPlan['comment']
                    except KeyError:
                        logutils.logwarning('Not able to extract the action plan details')
                try:                                    
                    objviol.hasExclusionRequest = violation['exclusionRequest'] != None
                    if objviol.hasExclusionRequest:
                        objviol.exclusioncomment = violation['exclusionRequest']['comment']
                except KeyError:
                    logutils.logwarning('Not able to extract the exclusion request')
                # filter the violations already in the exclusion list 
                try:                                    
                    objviol.violationstatus = violation['diagnosis']['status']
                except KeyError:
                    logutils.logwarning('Not able to extract the violation status')
                try:
                    objviol.componenthref = violation['component']['href']
                except KeyError:
                    componentHref = None

                objviol.componentid = ''
                objviol.id = ''
                rexcompid = "/components/([0-9]+)/snapshots/"
                m0 = re.search(rexcompid, componentHref)
                if m0: 
                    objviol.componentid = m0.group(1)
                if objviol.qrrulepatternhref != None and objviol.componenthref != None:
                    objviol.id = objviol.qrrulepatternhref+'#'+objviol.componenthref
                try:
                    objviol.componentShortName = violation['component']['shortName']
                except KeyError:
                    logutils.logwarning('Not able to extract the componentShortName')                                     
                try:
                    objviol.componentNameLocation = violation['component']['name']
                except KeyError:
                    logutils.logwarning('Not able to extract the componentNameLocation')
                # filter on component name location
                try:
                    objviol.componentstatus = violation['component']['status']
                except KeyError:
                    objviol.componentstatus = None                                            
                try:
                    objviol.findingshref = violation['diagnosis']['findings']['href']
                except KeyError:
                    objviol.findingsHref = None                                            
                try:
                    objviol.componenttreenodehref = violation['component']['treeNodes']['href']
                except KeyError:
                    objviol.componenttreenodehref  = None                                        
                try:
                    objviol.sourcecodeshref = violation['component']['sourceCodes']['href']
                except KeyError:
                    objviol.sourcecodeshref = None
                
                try:
                    objviol.propagationriskindex = violation['component']['propagationRiskIndex']
                except KeyError:
                    objviol.propagationriskindex = None                                            
        
                firsttechnicalcriterionid = '#N/A#'
                if listtccontributions:
                    for tcc in listtccontributions:
                        if tcc.metricid ==  objviol.qrid:
                            firsttechnicalcriterionid = tcc.parentmetricid
                            break 
                
                if edurl and snapshothref:
                    currentviolfullurl = edurl + '/engineering/index.html#' + snapshothref
                    currentviolfullurl += '/business/60017/qualityInvestigation/0/60017/' 
                    currentviolfullurl += firsttechnicalcriterionid + '/' + objviol.qrid + '/' + objviol.componentid
                    objviol.url = currentviolfullurl
        
                objviol.functionalviolationid = objviol.qrid +'#'+ objviol.componentNameLocation
                
                violation_modules = violations_modules.get(objviol.id) 
                if violation_modules:
                    modules = violations_modules[objviol.id]
                    objviol.modules = modules
        
                listviolations.append(objviol)        
        return listviolations
    ########################################################################
    def get_tqi_transactions_violations_json(self, domain, snapshotid, transactionid, criticalonly, violationStatus, technoFilter,nbrows):    
        logutils = LogUtils()
        request = domain + "/transactions/" + transactionid + "/snapshots/" + snapshotid + '/violations'
        request += '?startRow=1'
        request += '&nbRows=' + str(nbrows)
        if criticalonly != None and criticalonly:         
            request += '&rule-pattern=critical-rules'
        if violationStatus != None:
            request += '&status=' + violationStatus
        
        businesscriterionfilter = "60017"
        if businesscriterionfilter != None:
            strbusinesscriterionfilter = str(businesscriterionfilter)        
            # we can have multiple value separated with a comma
            if ',' not in strbusinesscriterionfilter:
                request += '&business-criterion=' + strbusinesscriterionfilter
            request += '&rule-pattern=('
            for item in strbusinesscriterionfilter.split(sep=','):
                request += 'cc:' + item + ','
                if criticalonly == None or not criticalonly:   
                    request += 'nc:' + item + ','
            request = request[:-1]
            request += ')'
            
        if technoFilter != None:
            request += '&technologies=' + technoFilter
            
        return self.restutils.execute_requests_get(request)

    ########################################################################
    def update_backgroundfactmetric(self, domain, applicationid, snapshotid, metricid, coveragevalue, modulelist, central_schema="com_vogella_junit_first_central", app_name="com.vogella.junit.first"):
        logutils = LogUtils()
        #AAD/applications/3/snapshots/10/results?background-facts=(66004)
        request = domain + "/applications/" + str(applicationid) + "/snapshots/" + str(snapshotid) + "/results"
        #?background-facts=(' + str(metricid) + ')'
        #?background-facts=(' + metricid + ')'
        
        value = "ADG Database;Application Name;Module Name;Metric Id;Result\n"
        formatedcoverage_for_hd = float(coveragevalue) / 100
        value += central_schema + ";" + central_schema + ";;"+(metricid)+";" + str(formatedcoverage_for_hd) + "\n"
        for it in modulelist:
            # we don't compute a coverage value for the modules, so we inject 0 value
            value += central_schema + ";" + app_name + ";" + it.modulename + ";"+(metricid)+";0\n"
        
        return self.restutils.execute_requests_put(request, accept='application/json', inputcontent=value, contenttype='text/csv')
    
    ########################################################################
    def create_scheduledexclusions_json(self, domain, applicationid, snapshotid, json_exclusions_to_create):
        request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/exclusions/requests'
        return self.restutils.execute_request_post(request, 'application/json',json_exclusions_to_create)

    def get_scheduled_exclusions_json(self, domain, applicationid, snapshotid):
        request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/exclusions/scheduled?&startRow=1&nbRows=100000'
        return self.restutils.execute_requests_get(request, 'application/json')

    def get_excluded_violations_json(self, domain, applicationid, snapshotid):
        request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/excluded-violations?&startRow=1&nbRows=100000'
        return self.restutils.execute_requests_get(request, 'application/json')

    ########################################################################
    def create_actionplans_json(self, domain, applicationid, snapshotid, json_actionplans_to_create):
        request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/action-plan/issues'
        return self.restutils.execute_request_post(request, 'application/json',json_actionplans_to_create)

    def get_actionplans_json(self, domain, applicationid, snapshotid):
        request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/action-plan/issues?=&startRow=1&nbRows=500000'
        return self.restutils.execute_requests_get(request, 'application/json')

    ########################################################################
    def get_rule_pattern(self, rulepatternHref):
        logutils = LogUtils()
        logutils.logdebug("Extracting the rule pattern details")   
        request = rulepatternHref
        json_rulepattern =  self.restutils.execute_requests_get(request)
        obj = None
        if json_rulepattern != None:
            obj = RulePatternDetails()    
            try:
                obj.associatedValueName = json_rulepattern['associatedValueName']
            except KeyError:
                None
            try:
                qslist = json_rulepattern['qualityStandards']
                for qs in qslist:
                    obj.listQualityStandard.append(qs['standard']+"/"+qs['id'])
            except KeyError:
                None
        return obj 

    ########################################################################

    # extract the last element that is the id
    def get_hrefid(self, href, separator='/'):
        if href == None or separator == None:
            return None
        _id = ""
        hrefsplit = href.split('/')
        for elem in hrefsplit:
            # the last element is the id
            _id = elem    
        return _id


    ########################################################################
    # Action plan summary
    def get_actionplan_summary_json(self, domainname, applicationid, snapshotid):
        request = domainname + "/applications/" + applicationid + "/snapshots/" + snapshotid + "/action-plan/summary"
        return self.restutils.execute_requests_get(request)

    # do not include the solved
    def get_actionplan_summary(self,domainname,applicationid, snapshotid):
        logutils = LogUtils()
        dictapsummary = {}
        json_apsummary = self.get_actionplan_summary_json(domainname, applicationid, snapshotid)
        if json_apsummary != None:
            for qrap in json_apsummary:
                qrhref = qrap['rulePattern']['href']
                qrid = self.get_hrefid(qrhref)
                addedissues = 0
                pendingissues = 0
                addedissues  = qrap['addedIssues']
                pendingissues  = qrap['pendingIssues']
                numberofactions = addedissues + pendingissues
                dictapsummary.update({qrid:numberofactions})
        return dictapsummary


    # parse the exclusions excluded and scheduled
    def parse_json_exclusions(self, json_exclusions):
        dictsummary = {}
        if json_exclusions:
            for excl_item in json_exclusions:
                qrhref = excl_item['rulePattern']['href']
                qrid = self.get_hrefid(qrhref)
                status = excl_item['exclusionRequest']['status']
                if not dictsummary.get(qrid):
                    dictsummary[qrid] = {}
                    dictsummary[qrid]["total"] = 0
                    dictsummary[qrid]["processed"] = 0
                    dictsummary[qrid]["added"] = 0
                total = dictsummary[qrid]["total"] + 1
                added = dictsummary[qrid]["added"]
                processed = dictsummary[qrid]["processed"]
                if status == 'added':
                    added += 1
                elif status == 'processed':
                    processed += 1                    
                dictsummary[qrid].update({"total":total, "added":added, "processed": processed})           
        return dictsummary 

    # include the exclusions summary : excluded and scheduled
    def get_exclusions_summary(self,domainname,applicationid, snapshotid):
        dictsummary = {}

        dictsummary["exclusions"] = {}
        json_exclusions_summary = self.get_excluded_violations_json(domainname, applicationid, snapshotid)
        dictsummary["exclusions"] = self.parse_json_exclusions(json_exclusions_summary)

        dictsummary["scheduled_exclusions"] = {}
        json_scheduled_exclusions_summary = self.get_scheduled_exclusions_json(domainname, applicationid, snapshotid)
        dictsummary["scheduled_exclusions"] = self.parse_json_exclusions(json_scheduled_exclusions_summary)
        
        return dictsummary


    # include the total (including solved) and the number of solved, added, fixed
    def get_actionplan_summary_including_solved(self,domainname,applicationid, snapshotid):
        dictapsummary = {}
        json_apsummary = self.get_actionplans_json(domainname, applicationid, snapshotid)
        if json_apsummary != None:
            for qrap in json_apsummary:
                qrhref = qrap['rulePattern']['href']
                qrid = self.get_hrefid(qrhref)
                status = qrap['remedialAction']['status']
                if not dictapsummary.get(qrid):
                    dictapsummary[qrid] = {}
                    dictapsummary[qrid]["total"] = 0
                    dictapsummary[qrid]["added"] = 0
                    dictapsummary[qrid]["pending"] = 0
                    dictapsummary[qrid]["solved"] = 0
                
                total = dictapsummary[qrid]["total"] + 1
                added = dictapsummary[qrid]["added"]
                pending = dictapsummary[qrid]["pending"]
                solved = dictapsummary[qrid]["solved"]
                if status == 'added':
                    added += 1
                elif status == 'pending':
                    pending += 1
                elif status == 'solved':
                    solved += 1
                dictapsummary[qrid].update({"total":total, "added":added, "pending": pending, "solved" : solved})
        return dictapsummary

    ########################################################################
    # Educate feature
    def get_actionplan_triggers_json(self, domainname, applicationid, snapshotid):
        request = domainname + "/applications/" + applicationid + "/snapshots/" + snapshotid + "/action-plan/triggers"
        return self.restutils.execute_requests_get(request)

    def get_actionplan_triggers(self, domainname, applicationid, snapshotid):
        dict_aptriggers = {}
        json_aptriggers = self.get_actionplan_triggers_json(domainname, applicationid, snapshotid)
        if json_aptriggers != None:
            for qrap in json_aptriggers:
                qrhref = qrap['rulePattern']['href']
                qrid = self.get_hrefid(qrhref)
                active = qrap['active']
                dict_aptriggers.update({qrid:active})
        return dict_aptriggers
    ########################################################################
    def get_qualitymetrics_results_json(self, domainname, applicationid, snapshotfilter, snapshotids, criticalonly,  modules=None, qridfilter=None, nbrows=10000000):
        logutils = LogUtils()
        logutils.loginfo('Extracting the quality metrics results',True)
        request = domainname + "/applications/" + applicationid + "/results?quality-indicators"
        request += '=(business-criteria,technical-criteria'
        if not qridfilter:
            request += ',cc:60017'
        else:
            request += ','+str(qridfilter)
        if not qridfilter and (criticalonly == None or not criticalonly):   
            request += ',nc:60017'
        request += ')&select=(evolutionSummary,violationRatio,aggregators)'
        strsnapshotfilter = ''
        if snapshotfilter != None:
            strsnapshotfilter = "&snapshots=" + snapshotfilter
        elif snapshotids != None:
            strsnapshotfilter = "&snapshot-ids=" + snapshotids
        else:
            strsnapshotfilter = '&snapshots=-1'
        request += strsnapshotfilter
        if modules != None:
            request += '&modules=' + modules
        request += '&startRow=1'
        request += '&nbRows=' + str(nbrows)
        return self.restutils.execute_requests_get(request)

    def get_qualitymetrics_results_by_snapshotids_json(self, domainname, applicationid, snapshotids, criticalonly, modules, qridfilter, nbrows):
        return self.get_qualitymetrics_results_json(domainname, applicationid, None, snapshotids, criticalonly, modules, qridfilter, nbrows)

    def get_qualitymetrics_results_allsnapshots_json(self, domainname, applicationid, snapshotfilter, criticalonly, modules, qridfilter, nbrows):
        return self.get_qualitymetrics_results_json(domainname, applicationid, snapshotfilter, None, criticalonly, modules, qridfilter, nbrows)

    def get_metric_from_json(self, json_metric, parent_metric=None):
        logutils = LogUtils()
        if json_metric == None:
            return None
    
        metric = Metric()
        if parent_metric == None:
            
            try:
                metric.type = json_metric['type']
                #if metric.type != "quality-rules":
                #    print("not a qr")
            except KeyError:
                None
            try:
                metric.id = json_metric['reference']['key']
            except KeyError:
                None
            try:
                metric.name = json_metric['reference']['name']
            except KeyError:
                None                                                    
            try:
                metric.critical = json_metric['reference']['critical']
            except KeyError:
                None
        else:
            metric.type = parent_metric.type
            metric.id = parent_metric.id
            metric.name = parent_metric.name
            metric.critical = parent_metric.critical 
        """
        logutils.logdebug("D01 " +  metric.name + " " + str(json_metric))
        logutils.logdebug("D02 " +  str(json_metric['result']))
        logutils.logdebug("D03 " +  str(json_metric['result']['grade']))
        if json_metric == None or json_metric['result']== None or json_metric['result']['grade'] == None:
            None
        """
        hasresult = False
        try:
            hasresult = json_metric['result'] != None
        except:
            None

        if hasresult:        
            try:
                metric.grade = json_metric['result']['grade']
            except:
                logutils.logwarning("Metric %s has an empty grade " % str(metric.name))
                # if there is no grade for the modules, we skip
                # we don't skip for the application metric, even if it's not normal but we might have a grade for the module and we want to process in this case
                if parent_metric != None:
                    return None
                    
            try:
                metric.failedchecks = json_metric['result']['violationRatio']['failedChecks']
            except KeyError:
                None                                                          
            try:
                metric.successfulchecks = json_metric['result']['violationRatio']['successfulChecks']
            except KeyError:
                None                                                             
            try:
                metric.totalchecks = json_metric['result']['violationRatio']['totalChecks']
            except KeyError:
                None                                                         
            try:
                metric.ratio = json_metric['result']['violationRatio']['ratio']
            except KeyError:
                None
                
            if  metric.ratio == None:
                logutils.logwarning("Metric %s has an empty compliance ratio " % str(metric.name))                                                           
            try:
                metric.addedviolations = json_metric['result']['evolutionSummary']['addedViolations']                                              
            except KeyError:
                None   
            try:
                metric.removedviolations = json_metric['result']['evolutionSummary']['removedViolations']
                metric.deltaviolations = metric.addedviolations - metric.removedviolations 
            except KeyError:
                None      
              
        return metric


    def get_list_business_criteria(self, mapbctc, bcids, qrdetails):
        strlistbc = ''
        strlistbc_raw = ''
        #mapbctc
        if mapbctc != None:
            for bcid in bcids:
                listtc = mapbctc.get(bcid)
                for tc in listtc:
                    qrlisttc = qrdetails.get('tc').keys()
                    for tcid in qrlisttc:
                        if tc == tcid:
                            # found 
                            if bcid == "60016": 
                                strlistbc = strlistbc + 'Security,'
                                strlistbc_raw = strlistbc_raw + '60016#Security,'
                            if bcid == "60014": 
                                strlistbc = strlistbc + 'Efficiency,'
                                strlistbc_raw = strlistbc_raw + '60014#Efficiency,'
                            if bcid == "60013": 
                                strlistbc = strlistbc + 'Robustness,'
                                strlistbc_raw = strlistbc_raw + '60013#Robustness,'
                            if bcid == "60011": 
                                strlistbc = strlistbc + 'Transferability,'
                                strlistbc_raw = strlistbc_raw + '60011#Transferability,'
                            if bcid == "60012": 
                                strlistbc = strlistbc + 'Changeability,'
                                strlistbc_raw = strlistbc_raw + '60012#Changeability,'
        if strlistbc != '': strlistbc = strlistbc[:-1]    
        return strlistbc, strlistbc_raw


    def get_qualitymetrics_results(self, domainname, applicationid, snapshotid, tqiqm, criticalonly, modules=None, qridfilter=None, nbrows=10000000, mapbctc=None):
        logutils = LogUtils()
        dictmetrics = {}
        dicttechnicalcriteria = {}
        listbc = []

        dictmodules = None
        if modules != None:
            dictmodules = {}
        
        json_qr_results = self.get_qualitymetrics_results_by_snapshotids_json(domainname, applicationid, snapshotid, criticalonly, modules, qridfilter, nbrows)
        if json_qr_results: 
            for res in json_qr_results:
                iCount = 0
                lastProgressReported = None
                for res_app in res['applicationResults']:
                    iCount += 1
                    b_has_grade = False
                    metricssize = len(res['applicationResults'])
                    imetricprogress = int(100 * (iCount / metricssize))
                    if imetricprogress in (9,19,29,39,49,59,69,79,89,99) : 
                        if lastProgressReported == None or lastProgressReported != imetricprogress:
                            logutils.loginfo(' ' + str(imetricprogress+1) + '% of the metrics processed',True)
                            lastProgressReported = imetricprogress
                    # parse the json
                    metric = self.get_metric_from_json(res_app)
                    # skip the metrics that have no grade
                    if not metric:
                        continue
                    metric.applicationName = res['application']['name'] 
                    
                    if metric.type in ("quality-measures","quality-distributions","quality-rules"):
                        if not metric.grade:
                            b_has_grade = False
                            logutils.logwarning("Metric has no grade, removing it from the list : " + metric.name, True)
                        else:
                            b_has_grade = True
                            if metric.type == "quality-rules":
                                try:
                                    metric.threshold1 = tqiqm[''+metric.id].get("threshold1")
                                    metric.threshold2 = tqiqm[''+metric.id].get("threshold2")
                                    metric.threshold3 = tqiqm[''+metric.id].get("threshold3")
                                    metric.threshold4 = tqiqm[''+metric.id].get("threshold4")
                                except KeyError:
                                    None
                                
                                json_thresholds = None
                                # loading from another place when tresholds are empty
                                if not metric.threshold1 or not metric.threshold2 or not metric.threshold3 or not metric.threshold4:
                                    #logutils.loginfo('Extracting the quality rules thresholds',True)
                                    json_thresholds = self.get_qualityrules_thresholds_json(domainname, snapshotid, metric.id)   
                                if json_thresholds != None and json_thresholds['thresholds'] != None:
                                    icount = 0
                                    for thres in json_thresholds['thresholds']:
                                        icount += 1
                                        if icount == 1: metric.threshold1=thres
                                        if icount == 2: metric.threshold2=thres
                                        if icount == 3: metric.threshold3=thres
                                        if icount == 4: metric.threshold4=thres
                            dictmetrics[metric.id] = metric
                    elif metric.type == "technical-criteria":
                        #print('tc grade=' + str(metric.grade) + str(type(metric.grade)))
                        if (metric.grade == None): 
                            logutils.logwarning("Technical criterion has no grade, removing it from the list : " + metric.name)
                        else:
                            dicttechnicalcriteria[metric.id] = metric
                    elif metric.type == 'business-criteria':
                        if (metric.grade == None): 
                            logutils.logwarning("Business criterions has no grade, removing it from the list : " + metric.name)
                        else:
                            listbc.append(metric)
                    
                    if modules:
                        try:
                            for res_mod in res_app['moduleResults']:
                                mod_name = res_mod['moduleSnapshot']['name'] 
                                if not dictmodules.get(mod_name):
                                    dictmodules[mod_name] = {}
                                metric_module = self.get_metric_from_json(res_mod, metric)
                                # skip the metrics that have no grade
                                if metric_module == None:
                                    continue
                                if metric_module.grade != None:
                                    b_one_module_has_grade = True
                                metric_module.applicationName = res['application']['name']
                                metric_module.threshold1 = metric.threshold1
                                metric_module.threshold2 = metric.threshold2
                                metric_module.threshold3 = metric.threshold3
                                metric_module.threshold4 = metric.threshold4
                                dictmodules[mod_name][metric_module] = metric_module
                        except KeyError:
                            None
                    # we add the metric only if it has a grade at application level or has grade at least at module level
                    if metric.type in ("quality-measures","quality-distributions","quality-rules"):
                        if b_has_grade or b_one_module_has_grade:
                            dictmetrics[metric.id] = metric  
                        if not b_has_grade or (modules != None and not b_one_module_has_grade):
                            logutils.logwarning("Metric %s" % metric.name, True)
                        if not b_has_grade:
                            logutils.logwarning("    has no grade at application level", True)
                        if modules != None and not b_one_module_has_grade:
                            logutils.logwarning("    has no grade at module level", True)
                        if not b_has_grade and not b_one_module_has_grade:
                            logutils.logwarning("    skipping metric", True)
                           
        return dictmetrics, dicttechnicalcriteria, listbc, dictmodules

    ########################################################################
    def get_all_snapshots_json(self, domain):
        request = domain + "/results?snapshots=" + AIPRestAPI.FILTER_SNAPSHOTS_ALL
        return self.restutils.execute_requests_get(request)

    ########################################################################
    def get_loc_json(self, domain, snapshotsfilter=None):
        return self.get_sizing_measures_by_id(domain, Metric.TS_LOC, snapshotsfilter)
  
    ########################################################################
    def get_afp_json(self, domain, snapshotsfilter=None):
        return self.get_sizing_measures_by_id(domain, Metric.FS_AFP, snapshotsfilter)
  
    ########################################################################
    def get_tqi_json(self, domain, snapshotsfilter=None):
        return self.get_quality_indicators_by_id(domain, Metric.BC_TQI, snapshotsfilter)  
    def get_sizing_measures_by_id_json(self, domain, metricids, snapshotsfilter=None, modules=None):
        snapshot_index = None 
        snapshot_ids = None
        if snapshotsfilter != None:
            if snapshotsfilter.snapshot_index != None:
                snapshot_index = snapshotsfilter.snapshot_index
            if snapshotsfilter.snapshot_ids != None:
                snapshot_ids = snapshotsfilter.snapshot_ids
        if snapshot_index == None and snapshot_ids == None:
            snapshot_index == AIPRestAPI.FILTER_SNAPSHOTS_LAST
        request = domain + "/results?sizing-measures=(" + str(metricids) + ")"
        if snapshot_index != None:
            request += "&snapshots=" + snapshot_index
        if snapshot_ids != None:
            request += "&snapshot-ids=" + snapshot_ids            
        if modules != None:
            request += "&modules=" + modules
        return self.restutils.execute_requests_get(request)

    ########################################################################
    def get_quality_distribution_by_id_as_json(self, domain, metricids, snapshotsfilter=None):
        json_cost_complexity = self.get_quality_indicators_by_id(domain, metricids, snapshotsfilter)
        json_snapshots = {}
        if json_cost_complexity != None:
            for metric in json_cost_complexity:
                snapshothref = metric['applicationSnapshot']['href']
                if json_snapshots.get(snapshothref) == None:
                    json_snapshots[snapshothref] = {}
                for appresults in metric['applicationResults']:
                    json_distr = {}
                    key = appresults['reference']['key']
                    categories = None
                    try:
                        categories = appresults['result']['categories']
                    except KeyError:
                        None
                    if categories != None:
                        icount = 0
                        NbVeryHigh = 0.0
                        NbHigh = 0.0
                        NbAverage = 0.0
                        NbLow = 0.0
                        for c in categories:
                            icount += 1
                            if icount == 1: very_high = c
                            elif icount == 2: high = c
                            elif icount == 3: average = c
                            elif icount == 4: low = c
                        try: NbVeryHigh=very_high.get('value') 
                        except: None                                 
                        try: NbHigh=high.get('value')
                        except: None
                        try: NbAverage=average.get('value')
                        except: None
                        try: NbLow=low.get('value')
                        except: None
                        total = NbVeryHigh+NbHigh+NbAverage+NbLow
                        PercentVeryHigh=0.0
                        PercentHigh=0.0
                        PercentAverage=0.0
                        PercentLow=0.0                          
                        if total > 0:
                            PercentVeryHigh = NbVeryHigh / total
                            PercentHigh = NbHigh / total
                            PercentAverage = NbAverage / total
                            PercentLow = NbLow / total
                        json_distr = {key+"_NbVeryHigh":NbVeryHigh,key+"_NbHigh":NbHigh,key+"_NbAverage":NbAverage,
                                                            key+"_NbLow":NbLow,key+"_PercentVeryHigh":PercentVeryHigh,key+"_PercentHigh":PercentHigh,
                                                            key+"_PercentAverage":PercentAverage,key+"_PercentLow":PercentLow}       
                        json_snapshots.get(snapshothref).update(json_distr) 
        return json_snapshots

    ########################################################################
    def get_sizing_measures_json(self, domain, snapshotsfilter=None, modulesfilter=None):
        if snapshotsfilter == None:
            snapshotsfilter = AIPRestAPI.FILTER_SNAPSHOTS_LAST
        
        snapshot_index = None 
        snapshot_ids = None
        if snapshotsfilter != None:
            if snapshotsfilter.snapshot_index != None:
                snapshot_index = snapshotsfilter.snapshot_index
            if snapshotsfilter.snapshot_ids != None:
                snapshot_ids = snapshotsfilter.snapshot_ids        
        if snapshot_index == None and snapshot_ids == None:
            snapshot_index == AIPRestAPI.FILTER_SNAPSHOTS_LAST
        request = domain + "/results?sizing-measures=(technical-size-measures,technical-debt-statistics,run-time-statistics,functional-weight-measures)"
        if snapshot_index:
            request += "&snapshots=%s" % snapshot_index
        if snapshot_ids:
            request += "&snapshot-ids=%s" % snapshot_ids
        if modulesfilter:
            request += "&modules=%s" % modulesfilter
        
        return self.restutils.execute_requests_get(request)

    def get_sizing_measures(self, domain, snapshotsfilter=None, modulesfilter=None):
        list_results = [] # per snapshot
        sizing_measures_json = self.get_sizing_measures_json(domain, snapshotsfilter, modulesfilter)
        for item_snapshot in sizing_measures_json:
            application_name =  item_snapshot["applicationSnapshot"]['name']
            snapshot_href = item_snapshot["applicationSnapshot"]["href"]
            snapshot_id =  AIPRestAPI.get_href_id(snapshot_href)
            dic_snapshot_results = {}
            dic_snapshot_results["application_name"] = application_name
            dic_snapshot_results["snapshot_href"] = snapshot_href
            dic_snapshot_results["snapshot_id"] = snapshot_id
            dic_snapshot_results["metrics"] = {}
            
            for item_metric in item_snapshot['applicationResults']:
                metric_id = item_metric['reference']['key']
                metric_type = item_metric['type'] 
                dic_snapshot_results["metrics"][metric_id] = {}
                metric_name = item_metric['reference']['name']
                metric_value = item_metric['result']['value']
                dic_snapshot_results["metrics"][metric_id]["metric_id"] = metric_id 
                dic_snapshot_results["metrics"][metric_id]["metric_type"] = metric_type
                dic_snapshot_results["metrics"][metric_id]["metric_name"] = metric_name
                dic_snapshot_results["metrics"][metric_id]["metric_value"] = metric_value
                dic_snapshot_results["metrics"][metric_id]["modules"] = {}
                for module_result in item_metric["moduleResults"]:
                    module_name = module_result['moduleSnapshot']['name']
                    module_value = module_result['result']['value']
                    dic_snapshot_results["metrics"][metric_id]["modules"][module_name] = {}
                    dic_snapshot_results["metrics"][metric_id]["modules"][module_name]["module_name"] = module_name
                    dic_snapshot_results["metrics"][metric_id]["modules"][module_name]["module_value"] = module_value
            list_results.append(dic_snapshot_results)            
        return list_results
        

    ########################################################################
    def get_quality_indicators_json(self, domain, snapshotsfilter=None):
        if snapshotsfilter == None:
            snapshotsfilter = AIPRestAPI.FILTER_SNAPSHOTS_LAST
        request = domain + "/results?quality-indicators=(quality-rules,business-criteria,technical-criteria,quality-distributions,quality-measures)&select=(evolutionSummary,violationRatio,aggregators,categories)&snapshots="+snapshotsfilter
        return self.restutils.execute_requests_get(request)



    ########################################################################
    def get_quality_indicators_by_id_json(self, domain, metricids, snapshotsfilter=None):
        if snapshotsfilter == None:
            snapshotsfilter = AIPRestAPI.FILTER_SNAPSHOTS_LAST
        request = domain + "/results?quality-indicators=(" + str(metricids) + ")&select=(evolutionSummary,violationRatio,aggregators,categories)&snapshots="+snapshotsfilter
        return self.restutils.execute_requests_get(request)

    ########################################################################
    def get_metric_contributions_json(self, domain, metricid, snapshotid):
        request = domain + "/quality-indicators/" + str(metricid) + "/snapshots/" + snapshotid 
        return self.restutils.execute_requests_get(request)

    def get_metric_contributions(self, domain, metricid, snapshotid):
        return Contribution.loadlist(self.get_metric_contributions_json(domain, metricid, snapshotid))

    #################################Violation#######################################
    def get_qualityrules_thresholds_json(self, domain, snapshotid, qrid):
        request = domain + "/quality-indicators/" + str(qrid) + "/snapshots/"+ snapshotid
        return self.restutils.execute_requests_get(request)
    
    ########################################################################
    def get_businesscriteria_grades_json(self, domain, snapshotsfilter=None):
        if snapshotsfilter == None:
            snapshotsfilter = AIPRestAPI.FILTER_SNAPSHOTS_LAST        
        request = domain + "/results?quality-indicators=(60017,60016,60014,60013,60011,60012,66031,66032,66033,60013,20140522)&applications=($all)&snapshots=" + snapshotsfilter 
        return self.restutils.execute_requests_get(request)

    ########################################################################
    def get_snapshot_tqi_quality_model_json (self, domainname, snapshotid):
        logutils = LogUtils()
        logutils.loginfo("Extracting the snapshot quality model")   
        request = domainname + "/quality-indicators/60017/snapshots/" + snapshotid + "/base-quality-indicators" 
        return self.restutils.execute_requests_get(request)

    def get_snapshot_quality_model_qualitymetrics_json (self, domainname, snapshotid):
        logutils = LogUtils()
        logutils.loginfo("Extracting the snapshot quality model - quality-rules")   
        request = domainname + "/configuration/snapshots/" + snapshotid + "/quality-rules" 
        return self.restutils.execute_requests_get(request)    
    
    def get_snapshot_quality_model_qualitydistributions_json (self, domainname, snapshotid):
        logutils = LogUtils()
        logutils.loginfo("Extracting the snapshot quality model - quality-distributions")   
        request = domainname + "/configuration/snapshots/" + snapshotid + "/quality-distributions" 
        return self.restutils.execute_requests_get(request)    

    def get_snapshot_quality_model_qualitymeasures_json (self, domainname, snapshotid):
        logutils = LogUtils()
        logutils.loginfo("Extracting the snapshot quality model - quality-measures")   
        request = domainname + "/configuration/snapshots/" + snapshotid + "/quality-measures" 
        return self.restutils.execute_requests_get(request)    

    ########################################################################
    def get_snapshot_tqi_quality_model (self, domainname, snapshotid):
        tqiqm = {}
        ''' 
        5 metrics are missing here (quality-measures and quality-distributions), because they don't contribute to the Total quality index :
        67001 : Cost Complexity distribution
        67030 : Distribution of defects to critical diagnostic-based metrics per cost complexity
        67020 : Distribution of violations to critical diagnostic-based metrics per cost complexity
        62003 : SEI Maintainability Index 3
        62004 : SEI Maintainability Index 4
        '''
        json_snapshot_quality_model = self.get_snapshot_tqi_quality_model_json(domainname, snapshotid)
        json_snapshot_qualitymetrics = self.get_snapshot_quality_model_qualitymetrics_json(domainname, snapshotid)
        json_snapshot_qualitydistributions = self.get_snapshot_quality_model_qualitydistributions_json(domainname, snapshotid)
        json_snapshot_qualitymeasures = self.get_snapshot_quality_model_qualitymeasures_json(domainname, snapshotid)
        listqualitymetrics = []
        listqualitydistributions = []
        listqualitymeasures = []
        for qmitem in json_snapshot_qualitymetrics: listqualitymetrics.append(qmitem['key'])
        for qmitem in json_snapshot_qualitydistributions: listqualitydistributions.append(qmitem['key'])
        for qmitem in json_snapshot_qualitymeasures: listqualitymeasures.append(qmitem['key'])        
        
        if json_snapshot_quality_model != None:
            for qmitem in json_snapshot_quality_model:
                maxWeight = -1
                qrid = qmitem['key']
                qrcompoundWeight = qmitem['compoundedWeight'] 
                qrcompoundWeightFormula = qmitem['compoundedWeightFormula']
                regexp = "\([0-9]+x([0-9]+)\)"                                            
                for m in re.finditer(regexp, qrcompoundWeightFormula):
                    if m.group(1) != None and int(m.group(1)) > int(maxWeight): 
                        maxWeight = int(m.group(1))                                            
                qrname = qmitem['name']
                qrcritical = qmitem['critical']
                qrtype=None
                threshold1 = None
                threshold2 = None 
                threshold3 = None
                threshold4 = None
                if qrid in listqualitymetrics: 
                    qrtype = 'quality-rules'
                    try:
                        if qmitem['thresholds'] != None:
                            icount = 0
                            for thres in qmitem['thresholds']:
                                icount += 1
                                if icount == 1: threshold1=thres
                                if icount == 2: threshold2=thres
                                if icount == 3: threshold3=thres
                                if icount == 4: threshold4=thres                                                
                    except KeyError:
                        None
                elif qrid in listqualitydistributions: qrtype = 'quality-distributions'
                elif qrid in listqualitymeasures: qrtype = 'quality-measures'
                    
                tqiqm[qrid] = {"critical":qrcritical,"type": qrtype, "hasresults":False, "name":qrname, "tc":{},"maxWeight":maxWeight,"compoundedWeight":qrcompoundWeight,"compoundedWeightFormula":qrcompoundWeightFormula}
                if qrid in listqualitymetrics: 
                    # adding the thresholds
                    tqiqm.get(qrid).update({"threshold1":threshold1, "threshold2:":threshold2,"threshold3":threshold3, "threshold4" : threshold4}) 
                    #tqiqm[qrid] = {"critical":qrcrt,"tc":{},"maxWeight":maxWeight,"compoundedWeight":qrcompoundWeight,"compoundedWeightFormula":qrcompoundWeightFormula, 
                    #""               "threshold1":threshold1, "threshold2:":threshold2,"threshold3":threshold3, "threshold4" : threshold4}  
                #contains the technical criteria (might be several) for each rule, we keep the fist one
                for tccont in qmitem['compoundedWeightTerms']:
                    _term = tccont['term'] 
                    #tqiqm[qrid] = {tccont['technicalCriterion']['key']: tccont['technicalCriterion']['name']} 
                    #TODO: add qrcompoundWeight and/or qrcompoundWeightFormula
                    tqiqm.get(qrid).get("tc").update({tccont['technicalCriterion']['key']: tccont['technicalCriterion']['name']})
        return tqiqm
    ########################################################################
    def get_snapshot_bc_tc_mapping_json(self, domain, snapshotid, bcid):
        logutils = LogUtils()
        logutils.loginfo("Extracting the snapshot business criterion " + bcid +  " => technical criteria mapping")  
        request = domain + "/quality-indicators/" + str(bcid) + "/snapshots/" + snapshotid
        return self.restutils.execute_requests_get(request)
    
    ########################################################################
    def get_components_pri_json (self, domain, applicationid, snapshotid, bcid,nbrows):
        logutils = LogUtils()
        logutils.loginfo("Extracting the components PRI for business criterion " + bcid)  
        request = domain + "/applications/" + str(applicationid) + "/snapshots/" + str(snapshotid) + '/components/' + str(bcid)
        request += '?startRow=1'
        request += '&nbRows=' + str(nbrows)
        return self.restutils.execute_requests_get(request)
         
    ########################################################################
    def get_sourcecode_json(self, sourceCodesHref):
        return self.restutils.execute_requests_get(sourceCodesHref)     
    
    ########################################################################
    def get_sourcecode_file_json(self, filehref, srcstartline, srcendline):
        strstartendlineparams = ''
        if srcstartline != None and srcstartline >= 0 and srcendline != None and srcendline >= 0:
            strstartendlineparams = '?start-line='+str(srcstartline)+'&end-line='+str(srcendline)
        return self.restutils.execute_requests_get(filehref+strstartendlineparams, 'text/plain', 'text/plain')    
    
    ########################################################################
    def get_objectviolation_metrics(self, objHref):
        logutils = LogUtils()
        logutils.logdebug("Extracting the component metrics")    
        request = objHref
        json_component = self.restutils.execute_requests_get(request)
        obj = None
        if json_component != None:
            obj = ObjectViolationMetric()
            try:
                obj.componentType = json_component['type']['label']
            except KeyError:
                None                              
            try:
                obj.codeLines = json_component['codeLines']
                if obj.codeLines == None :  obj.codeLines = 0
            except KeyError:
                obj.codeLines = 0
            try:
                obj.commentedCodeLines = json_component['commentedCodeLines']
                if obj.commentedCodeLines == None :  obj.commentedCodeLines = 0
            except KeyError:
                obj.commentedCodeLines = 0                                          
            try:
                obj.commentLines = json_component['commentLines']
                if obj.commentLines == None :  obj.commentLines = 0
            except KeyError:
                obj.commentLines = 0
                  
            try:
                obj.fanIn = json_component['fanIn']
            except KeyError:
                obj.fanIn = 0
            try:
                obj.fanOut = json_component['fanOut']
            except KeyError:
                obj.fanOut = 0 
            try:
                obj.cyclomaticComplexity = json_component['cyclomaticComplexity']
            except KeyError:
                obj.cyclomaticComplexity ='Not available'   
            #Incorrect ratio, recomputing manually
            #try:
            #    obj.ratioCommentLinesCodeLines = json_component['ratioCommentLinesCodeLines']
            #except KeyError:
            #    obj.ratioCommentLinesCodeLines = None
    
            obj.ratioCommentLinesCodeLines = None
            if obj.codeLines != None and obj.commentLines != None and obj.codeLines != 'Not available' and obj.commentLines != 'Not available' and (obj.codeLines + obj.commentLines != 0) :
                obj.ratioCommentLinesCodeLines = obj.commentLines / (obj.codeLines + obj.commentLines) 
            else:
                obj.ratioCommentLinesCodeLines = 0
            try:
                obj.halsteadProgramLength = json_component['halsteadProgramLength']
            except KeyError:
                obj.halsteadProgramLength = 0
            try:
                obj.halsteadProgramVocabulary = json_component['halsteadProgramVocabulary']
            except KeyError:
                obj.halsteadProgramVocabulary = 0
            try:
                obj.halsteadVolume = json_component['halsteadVolume']
            except KeyError:
                obj.halsteadVolume = 0 
            try:
                obj.distinctOperators = json_component['distinctOperators']
            except KeyError:
                obj.distinctOperators = 0 
            try:
                obj.distinctOperands = json_component['distinctOperands']
            except KeyError:
                obj.distinctOperands = 0                                             
            try:
                obj.integrationComplexity = json_component['integrationComplexity']
            except KeyError:
                obj.integrationComplexity = 0
            try:
                obj.criticalViolations = json_component['criticalViolations']
            except KeyError:
                obj.criticalViolations = 'Not available'
    
        return obj
        
    
    ########################################################################
    def get_objectviolation_findings_json(self, objHref, qrid):
        logutils = LogUtils()
        logutils.logdebug("Extracting the component findings")    
        request = objHref + '/findings/' + qrid 
        return self.restutils.execute_requests_get(request)
         
    ########################################################################
    # extract the transactions TRI & violations component list per business criteria
    def init_transactions (self, domain, applicationid, snapshotid, criticalonly, violationStatus, technoFilter,nbrows):
        logutils = LogUtils()
        #TQI,Security,Efficiency,Robustness
        bcids = ["60017","60016","60014","60013"]
        transaclist = {}
        for bcid in bcids: 
            json_transactions = self.get_transactions_per_business_criterion(domain, applicationid, snapshotid, bcid, nbrows)
            if json_transactions != None:
                transaclist[bcid] = []
                icount = 0
                for trans in json_transactions:
                    icount += 1
                    tri = None
                    shortname = 'Undefined'
                    name = 'Undefined'
                    transactionHref = 'Undefined'
                    transactionid = -1 
                    
                    try:
                        name =  trans['name']
                    except KeyError:
                        None  
                    try:
                        tri =  trans['transactionRiskIndex']
                    except KeyError:
                        None
                    try:
                        transactionHref =  trans['href']
                    except KeyError:
                        None
                    rexuri = "/transactions/([0-9]+)/"
                    m0 = re.search(rexuri, transactionHref)
                    if m0: transactionid = m0.group(1)
                    try:
                        shortName =  trans['shortName']
                    except KeyError:
                        None 
                        
                    mytransac = {
                        "name":name,
                        "shortName":shortName,
                        "href":transactionHref,
                        "business criteria id":bcid,
                        "transactionRiskIndex":tri,
                        "componentsWithViolations":[]
                    }
                    
                    # for TQI only we retrieve the list of components in violations on that transaction
                    # for the other we need only the transaction TRI
                    json_tran_violations = None
                    # look for the transaction violation only for the TQI, for the other HF take the violation already extracted for the TQI  
                    if bcid == "60017":
                        logutils.loginfo("Extracting the violations for transaction " + transactionid + ' (' + str(icount) + '/' + str(len(json_transactions)) + ')')
                        json_tran_violations = self.get_tqi_transactions_violations_json(domain, snapshotid, transactionid, criticalonly, violationStatus, technoFilter,nbrows)                  
                        if json_tran_violations != None:
                            for tran_viol in json_tran_violations:
                                mytransac.get("componentsWithViolations").append(tran_viol['component']['href'])
                                #print(shortName + "=>" + tran_viol['component']['href'])
                    else:
                        if transaclist["60017"] != None:
                            for t in transaclist["60017"]:
                                if mytransac['href'] == t['href']:
                                    mytransac.update({"componentsWithViolations":t.get("componentsWithViolations")})
                                    break
                    transaclist[bcid].append(mytransac)
        return transaclist
    
    ########################################################################
    def initialize_components_pri (self, domain, applicationid, snapshotid,bcids,nbrows):
        logutils = LogUtils()
        comppridict = {}
        str_pri = ''
        for bcid in bcids:
            comppridict.update({bcid:{}})
            json_snapshot_components_pri = self.get_components_pri_json(domain, applicationid, snapshotid, bcid,nbrows)
            if json_snapshot_components_pri != None:
                for val in json_snapshot_components_pri:
                    compid = None
                    try:
                        treenodehref = val['treeNodes']['href']
                    except KeyError:
                        logutils.logerror('KeyError treenodehref ' + str(val))
                    if treenodehref != None:
                        rexuri = "/components/([0-9]+)/"
                        m0 = re.search(rexuri, treenodehref)
                        if m0: compid = m0.group(1)
                        name = val['name']
                        pri = val['propagationRiskIndex']
                        str_pri += str(bcid) + ";" + name + ";" + str(pri) + "\n"                                                 
                        if treenodehref != None and pri != None: 
                            comppridict.get(bcid).update({compid:pri})
                            #if (bcid == 60016 or bcid == "60016"):
                                #print(str(compid))
            json_snapshot_components_pri = None
        # creating a file with all components PRI values per HF
        """
        text_file = open("components_pri.csv", "w")
        n = text_file.write(str_pri)
        text_file.close()
        """
        return comppridict
    
    
    ########################################################################
    def initialize_bc_tch_mapping(self, domain, applicationid, snapshotid, bcids):
        outputtcids = {}
        for bcid in bcids:
            outputtcid = []
            json = self.get_snapshot_bc_tc_mapping_json(domain, snapshotid, bcid)
            if json != None:
                if json != None:
                    for val in json['gradeContributors']:
                        outputtcid.append(val['key'])
            outputtcids.update({bcid:outputtcid}) 
            json = None
        return outputtcids    
########################################################################

class QualityStandard:
    id = None
    category = None
    
########################################################################

class ObjectViolationMetric:
    componentType = '<Not extracted>'
    criticalViolations = '<Not extracted>'
    cyclomaticComplexity = '<Not extracted>'
    codeLines = '<Not extracted>'
    commentLines = '<Not extracted>'
    ratioCommentLinesCodeLines = '<Not extracted>'
    commentedCodeLines = None
    fanIn = None
    fanOut = None
    halsteadProgramLength = None
    halsteadProgramVocabulary = None
    halsteadVolume = None
    distinctOperators = None
    distinctOperands = None
    integrationComplexity = None
    criticalViolations = None

########################################################################

class RulePatternDetails:
    def __init__(self):
        self.associatedValueName = ''
        self.listQualityStandard = []

    def get_quality_standards(self):
        strqualitystandards = ''
        #print(len(self.listQualityStandard))
        for qs in self.listQualityStandard:
            strqualitystandards += qs + ","
        if strqualitystandards != '': strqualitystandards = strqualitystandards[:-1]
        return strqualitystandards

########################################################################

# metric class
class Metric:
    # Business criteria metrics
    BC_TQI = 60017
    BC_Security = 60016
    BC_Efficiency = 60014
    BC_Robustness = 60013
    BC_Transferability = 60011
    BC_Changeability = 60012
    BC_GreenIT = 20140522
    BC_ProgrammingPractices = 66031
    BC_Documentation = 66032
    BC_ArchitecturalDesign = 66033
    BC_ISO5055_Index = 1061000
    BC_ISO5055_Maintainability = 1061001
    BC_ISO5055_Performance_Efficiency = 1061002
    BC_ISO5055_Reliability = 1061003
    BC_ISO5055_Security = 1061004
    
    bc_names = {
            BC_TQI : "Total Quality Index", BC_Security : "Security", BC_Efficiency : "Efficiency",     BC_Robustness : "Robustness",
            BC_Transferability : "Transferability", BC_Changeability : "Changeability", BC_GreenIT : "Green IT",
            BC_ProgrammingPractices : "Programming Practices",    BC_Documentation : "Documentation", BC_ArchitecturalDesign : "ArchitecturalDesign",
            BC_ISO5055_Index : "ISO-5055 Index", BC_ISO5055_Maintainability : "ISO-5055 Maintainability",  BC_ISO5055_Performance_Efficiency : "ISO-5055 Performance Efficiency",  BC_ISO5055_Reliability : "ISO-5055 Reliability", BC_ISO5055_Security : "ISO-5055 Security"
        } 
    
    # Total Quality Index,Security,Efficiency,Robustness,Changeability,Transferability,Coding Best Practices/Programming Practices,Documentation,Architectural Design,Green IT
    #      ISO-5055-Index, ISO-5055-Maintainability, ISO-5055-Performance-Efficiency, ISO-5055-Reliability, ISO-5055-Security    
    
    bcids = [str(BC_TQI),str(BC_Security),str(BC_Efficiency),str(BC_Robustness),str(BC_Changeability),str(BC_Transferability),
             str(BC_GreenIT),
             str(BC_ProgrammingPractices),str(BC_Documentation),str(BC_ArchitecturalDesign),
             str(BC_ISO5055_Index),str(BC_ISO5055_Maintainability), str(BC_ISO5055_Performance_Efficiency), str(BC_ISO5055_Reliability), str(BC_ISO5055_Security)
         ]
    bcids_for_reporting = [
            str(BC_TQI),str(BC_Security),str(BC_Efficiency),str(BC_Robustness),str(BC_Changeability),str(BC_Transferability),
         ]
    
    # Technical sizes metrics
    TS_LOC="10151"
    TS_DECISION_POINTS="10506"
    TS_NB_ARTIFACTS="10152"
    TS_NB_CLASSES="10155"
    TS_NB_PROGRAMS="10156"
    TS_NB_TABLES="10163"
    TS_NB_VIEWS="10164"
    TS_NB_FUNCTIONS_AND_PROC="19175"
    
    # Functional size metrics
    FS_AFP="10202"
    
    
    # Distributions metrics
    DIST_CYCLOMATIC_COMPLEXITY = "65501"
    DIST_COST_COMPLEXITY = "67001"
    DIST_FAN_OUT = "66020"
    DIST_FAN_IN = "66021"
    DIST_COUPLING = "65350"
    DIST_SIZE = "65105"
    DIST_SQL_COMPLEXITY = "65801"
    DIST_METRICS = [DIST_CYCLOMATIC_COMPLEXITY,DIST_COST_COMPLEXITY,DIST_FAN_OUT,DIST_FAN_IN,DIST_COUPLING,DIST_SIZE,DIST_SIZE]
    
    id = None
    name = None
    type = None
    critical = None
    grade = None
    failedchecks = None
    successfulchecks = None
    totalchecks = None
    ratio = None
    threshold1 = None
    threshold2 = None
    threshold3 = None
    threshold4 = None
    addedviolations = None
    removedviolations = None
    deltaviolations = None
    applicationName = None
    
    technical_criteria_raw = None
    technical_criteria = None
    business_criteria_raw = None
    business_criteria = None

    @staticmethod
    def get_distributionsmetrics():
        metrics = ''
        for m in Metric.DIST_METRICS:
            metrics += m + ','
        return metrics[:-1]

########################################################################

    
# contribution class (technical criteria contributions to business criteria, or quality metrics to technical criteria) 
class Contribution:
    parentmetricid = None
    parentmetricname = None
    metricid = None
    metricname = None
    weight = None
    critical = None
  
    @staticmethod
    def loadlist(json_contributions):
        listcontributions = []
        if json_contributions != None:
            for json in json_contributions['gradeContributors']:
                listcontributions.append(Contribution.load(json, json_contributions['name'], json_contributions['key'] )) 
        return listcontributions   

    @staticmethod
    def load(json_contribution, parentmetricname, parentmetricid):
        x = Contribution()
        if json_contribution != None:
            x.parentmetricname = parentmetricname
            x.parentmetricid = parentmetricid
            x.metricname = json_contribution['name']
            x.metricid = json_contribution['key']
            x.critical = json_contribution['critical']
            x.weight = json_contribution['weight']      
        return x
  
########################################################################
    
# violation class
class Violation:
    id = None
    qrid = None
    qrname = None
    critical = None
    componentid = None
    componentShortName = None
    componentNameLocation = None
    hasActionPlan = False
    actionPlan = None
    actionplanstatus = ''
    actionplantag = ''
    actionplancomment = ''
    hasExclusionRequest = False
    exclusioncomment = ''
    url = None
    violationstatus = None
    componentstatus = None
    modules = []
    violationid = None
    functionalviolationid = None
    
    findingshref = None
    componenttreenodehref = None                                    
    sourcecodeshref  = None                                   
    propagationriskindex = None                                
    
    
    

########################################################################

class ViolationOutput:
    appName = None
    violation = None
    violation_metrics = None
    snapshotdate = None
    snapshotversion = None
    maxWeight = None
    compoundedWeight = None
    compoundedWeightFormula = None
    failedchecks = None
    ratio = None
    addedViolations = None
    removedViolations = None
    
    violationsStatus = None
    componentStatus = None
    associatedvaluelabel = None
    associatedvalue = None
    technicalcriteriaidandnames = None
    strlistbc = None
    strqualitystandards = None
    pri_selected_bc = None
    pri_security = None
    pri_robustness = None
    pri_efficiency = None
    pri_transferability = None
    pri_changeability = None
    transactions_number = None
    transactions_list = None
    transactions_robustness_number = None
    transactions_robustness_tri = None
    transactions_robustness_maxtri = None
    transactions_efficiency_number = None
    transactions_efficiency_tri = None
    transactions_efficiency_maxtri = None
    transactions_security_number = None
    transactions_security_tri = None
    transactions_security_maxtri = None
    distribution_cyclomaticcomplexity = None
    distribution_costcomplexity = None
    distribution_fanout = None
    distribution_fanin = None
    distribution_size = None
    distribution_coupling = None
    distribution_sqlcomplexity = None
    
    iCounterFilteredViolations = None
    totalcritviol = None
    totalviol = None
    
    qrrulepatternhref = None
    componenthref = None
    inputcomment = None
    actionplaninputtag = None
    
    modules = None
   
# Logging utils
class LogUtils:
    """
    @staticmethod
    def logdebug(logger, msg, tosysout = False):
        logger.debug(msg)
        if tosysout:
            print(msg)

    @staticmethod
    def loginfo(logger, msg, tosysout = False):
        logger.info(msg)
        if tosysout:
            print(msg)

    @staticmethod
    def logwarning(logger, msg, tosysout = False):
        logger.warning(msg)
        if tosysout:
            print("#### " + msg)

    @staticmethod
    def logerror(logger, msg, tosysout = False):
        logger.error(msg)
        if tosysout:
            print("#### " + msg)
    """
    
    def __new__(cls, ):
        """ creates a singleton object, if it is not created, 
        or else returns the previous singleton object"""
        if not hasattr(cls, 'instance'):
            cls.instance = super(LogUtils, cls).__new__(cls)
        return cls.instance

    def loginfo(self, msg, tosysout = False):
        if self.logger:
            self.logger.info(msg)
        if tosysout:
            print(msg)

    def logdebug(self, msg, tosysout = False):
        if self.logger:
            self.logger.debug(msg)
        if tosysout:
            print(msg)

    def logwarning(self, msg, tosysout = False):
        if self.logger:
            self.logger.warning(msg)
        if tosysout:
            print("#### " + msg)

    def logerror(self, msg, tosysout = False):
        if self.logger:
            self.logger.error(msg)
        if tosysout:
            print("#### " + msg)

#########################################################################
class MSAUtils:
    @staticmethod
    def getbloctype(generated_bks,line_begin,line_end):
        #K60M3G.cbl;2419;1986;82%;1:448|492:640|1011:2402
        if generated_bks is None or generated_bks == "":
            return "Manual" 
        split_bks = generated_bks.split('|')
        for sp in split_bks:
            if sp is None or len(sp.split(":")) != 2:
                return "Manual" 
            bk_start = int(sp.split(":")[0])
            bk_end = int(sp.split(":")[1])     
            if line_begin >= bk_start and line_begin <= bk_end and line_end >= bk_start and line_end <= bk_end:
                return "Generated"
            elif line_begin >= bk_start and line_begin <= bk_end and line_end > bk_end:
                return "Mixed"
            elif line_begin < bk_start and line_end >= bk_start and line_end <= bk_end:
                return "Generated"

        return "Manual"
#########################################################################