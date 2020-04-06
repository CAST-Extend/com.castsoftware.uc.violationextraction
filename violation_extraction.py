import json
from http.client import HTTPSConnection
from http.client import HTTPConnection
from base64 import b64encode
import argparse
import logging
import logging.handlers
import re
import sys
import csv
import traceback
import os
import time

'''
 Author : MMR
 Feb 2020
'''
#Security,Efficiency,Robustness,Transferability,Changeability
bcids = ["60016","60014","60013","60012","60011"]
setcookie = None
########################################################################
# retrieve the connection depending on 
def open_connection(logger,host,protocol):
    connection = None
    global setcookie
    setcookie = None
    logger.info('Opening connection to ' + protocol  + '://' + host)
    if re.search('[hH][tT][tT][pP][sS]',protocol):
        connection = HTTPSConnection(host)
    elif re.search('[hH][tT][tT][pP]',protocol):
        connection = HTTPConnection(host)
    return connection

########################################################################
# retrieve the connection depending on 
def close_connection(logger,connection):
    logger.info('Closing connection')
    if connection == None:
        return
    else:
        connection.close()
    global setcookie
    setcookie = None

########################################################################

def execute_request(logger, connection, requesttype, request, warname, user, password, apikey, inputjson, contenttype='application/json'):
    global setcookie
    
    request_headers = {}
    json_data = None

    request_text = "/"
    if warname != None:
        request_text +=  warname +"/"
    request_text += "rest/" + request
    logger.debug('Sending ' + requesttype + ' ' + request_text + ' with contenttype=' + contenttype)   

    # if the user and password are provided, we take them first
    if user != None and password != None and user != 'N/A' and user != 'N/A':
        #we need to base 64 encode it 
        #and then decode it to acsii as python 3 stores it as a byte string
        #userAndPass = b64encode(user_password).decode("ascii")
        auth = str.encode("%s:%s" % (user, password))
        #user_and_pass = b64encode(auth).decode("ascii")
        user_and_pass = b64encode(auth).decode("iso-8859-1")
        request_headers.update({'Authorization':'Basic %s' %  user_and_pass})
    # else if the api key is provided
    elif apikey != None and apikey != 'N/A':
        print (apikey)
        # API key configured in the WAR
        request_headers.update({'X-API-KEY:':apikey})
        # we are provide a user name hardcoded' 
        request_headers.update({'X-API-USER:':'admin_apikey'})
        
    # Name of the client added in the header (for the audit trail)
    request_headers.update({'X-Client':'com.castsoftware.uc.violationextraction'})
    
    # GET request
    if requesttype == 'GET':
        request_headers.update({'accept' : contenttype})
    # POST/PUT/DELETE request, we are provining a json file
    else:
        request_headers.update({'Content-type' : contenttype})
        json_data = json.dumps(inputjson)
    
    # if the session JSESSIONID is already defined we inject the cookie to reuse previous session
    if setcookie != None:
        request_headers.update({'Set-Cookie':setcookie})

    # sent the request
    connection.request(requesttype, request_text, json_data, headers=request_headers)        
     
    #get the response back
    response = connection.getresponse()
    #logger.debug('     response status ' + str(response.status) + ' ' + str(response.reason))    
    
    # Error 
    if  response.status != 200:
        msg = 'HTTPS request failed ' + str(response.status) + ' ' + str(response.reason) + ':' + request_text
        print (msg)
        logger.error(msg)
        return None
    
    # look for the Set-Cookie in response headers, to inject it for future requests
    if setcookie == None: 
        for h1 in response.headers._headers:
            if h1 != None and h1[0] == 'Set-Cookie':
                setcookie = h1[1]
                break
    
    #send back the date
    encoding = response.info().get_content_charset('iso-8859-1')
    responseread_decoded = response.read().decode(encoding)
    
    if contenttype=='application/json':
        output = json.loads(responseread_decoded)
    else:
        output = responseread_decoded
    
    return output

########################################################################
def get_server(logger, connection, warname, user, password, apikey):
    request = "server"
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################
def get_domains(logger, connection, warname, user, password, apikey):
    request = ""
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_applications(logger, connection, warname, user, password, apikey, domain):
    request = domain + "/applications"
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_transactions_per_business_criterion(logger, connection, warname, user, password, apikey, domain, applicationid, snapshotid, bcid, nbrows):
    logger.info("Extracting the transactions for business criterion " + bcid)
    request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + "/transactions/" + bcid
    request += '?startRow=1'
    request += '&nbRows=' + str(nbrows)    
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_application_snapshots(logger, connection, warname, user, password, apikey, domain, applicationid):
    request = domain + "/applications/" + applicationid + "/snapshots" 
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_total_number_violations(logger, connection, warname, user, password, apikey, domain, applicationid,snapshotid):
    logger.info("Extracting the number of violations")
    request = domain + "/results?sizing-measures=67011,67211&application=" + applicationid + "&snapshot=" + snapshotid
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_qualityrules_results(logger, connection, warname, user, password, apikey, domain, applicationid, criticalonly, nbrows):
    logger.info("Extracting the quality rules details")
    request = domain + "/applications/" + applicationid + "/results?quality-indicators"
    request += '=(cc:60017'
    if criticalonly == None or not criticalonly:   
        request += ',nc:60017'
    request += ')&select=(evolutionSummary,violationRatio)'
    # last snapshot only
    request += '&snapshots=-1'
    request += '&startRow=1'
    request += '&nbRows=' + str(nbrows)
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_snapshot_violations(logger, connection, warname, user, password, apikey, domain, applicationid, snapshotid, criticalonly, violationStatus, businesscriterionfilter, technoFilter, nbrows):
    logger.info("Extracting the snapshot violations")
    request = domain + "/applications/" + applicationid + "/snapshots/" + snapshotid + '/violations'
    request += '?startRow=1'
    request += '&nbRows=' + str(nbrows)
    if criticalonly != None and criticalonly:         
        request += '&rule-pattern=critical-rules'
    if violationStatus != None:
        request += '&status=' + violationStatus
    if businesscriterionfilter == None:
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
        
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_tqi_transactions_violations(logger, connection, warname, user, password, apikey, domain, snapshotid, transactionid, criticalonly, violationStatus, technoFilter,nbrows):    
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
        
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)


########################################################################
def create_scheduledexclusions(logger, connection, warname, user, password, apikey, uriapplication, json):
    request = uriapplication + '/exclusions/requests'
    return execute_request(logger, connection, 'POST', request, warname, user, password, apikey, json)

########################################################################
def create_actionplans(logger, connection, warname, user, password, apikey, uriapplication, json):
    request = uriapplication + '/action-plan/issues'
    return execute_request(logger, connection, 'POST', request, warname, user, password, apikey, json)

########################################################################

def get_objectviolation_metrics(logger, connection, warname, user, password, apikey, objHref):
    logger.debug("Extracting the component metrics")    
    request = objHref
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_objectviolation_findings(logger, connection, warname, user, password, apikey, objHref, qrid):
    logger.debug("Extracting the component findings")    
    request = objHref + '/findings/' + qrid 
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_rule_pattern(logger, connection, warname, user, password, apikey, rulepatternHref):
    logger.debug("Extracting the rule pattern details")   
    request = rulepatternHref
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_snapshot_tqi_quality_model (logger, connection, warname, user, password, apikey, domain, snapshotid):
    logger.info("Extracting the snapshot quality model")   
    request = domain + "/quality-indicators/60017/snapshots/" + snapshotid + "/base-quality-indicators" 
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################

def get_snapshot_bc_tc_mapping(logger, connection, warname, user, password, apikey, domain, snapshotid, bcid):
    logger.info("Extracting the snapshot business criterion " + bcid +  " => technical criteria mapping")  
    request = domain + "/quality-indicators/" + str(bcid) + "/snapshots/" + snapshotid
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)

########################################################################
 
def get_components_pri (logger, connection, warname, user, password, apikey, domain, applicationid, snapshotid, bcid,nbrows):
    logger.info("Extracting the components PRI for business criterion " + bcid)  
    request = domain + "/applications/" + str(applicationid) + "/snapshots/" + str(snapshotid) + '/components/' + str(bcid)
    request += '?startRow=1'
    request += '&nbRows=' + str(nbrows)
    #print ('aarequest =' + request) 
    return execute_request(logger, connection, 'GET', request, warname, user, password, apikey, None)
     
########################################################################
     
def get_sourcecode(logger, connection, sourceCodesHref, warname, user, password, apikey):
    return execute_request(logger, connection, 'GET', sourceCodesHref, warname, user, password, apikey, None)     

########################################################################

def get_sourcecode_file(logger, connection, warname, filehref, srcstartline, srcendline, user, password, apikey):
    strstartendlineparams = ''
    if srcstartline >= 0 and srcendline >= 0:
        strstartendlineparams = '?start-line='+str(srcstartline)+'&end-line='+str(srcendline)
    return execute_request(logger, connection, 'GET', filehref+strstartendlineparams, warname, user, password, apikey, None,'text/plain')    
     
########################################################################
# extract the transactions TRI & violations component list per business criteria
def init_transactions (logger, connection, warname, usr, pwd, apikey,domain, applicationid, snapshotid, criticalonly, violationStatus, technoFilter,nbrows):
    #Security,Efficiency,Robustness,TQI
    bcids = ["60017","60016","60014","60013"]
    transaclist = {}
    for bcid in bcids: 
        json_transactions = get_transactions_per_business_criterion(logger, connection, warname, usr, pwd, apikey,domain, applicationid, snapshotid, bcid, nbrows)
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
                    #print(str(name))
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
                    logger.info("Extracting the violations for transaction " + transactionid + ' (' + str(icount) + '/' + str(len(json_transactions)) + ')')
                    json_tran_violations = get_tqi_transactions_violations(logger, connection, warname, usr, pwd, apikey,domain, snapshotid, transactionid, criticalonly, violationStatus, technoFilter,nbrows)                  
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

 
def initialize_components_pri (logger, connection, warname, user, password, apikey, domain, applicationid, snapshotid,bcids,nbrows):
    comppridict = {}
    for bcid in bcids:
        comppridict.update({bcid:{}})
        json_snapshot_components_pri = get_components_pri(logger, connection, warname, user, password, apikey, domain, applicationid, snapshotid, bcid,nbrows)
        if json_snapshot_components_pri != None:
            for val in json_snapshot_components_pri:
                compid = None
                try:
                    treenodehref = val['treeNodes']['href']
                except KeyError:
                    logger.error('KeyError treenodehref ' + str(val))
                if treenodehref != None:
                    rexuri = "/components/([0-9]+)/"
                    m0 = re.search(rexuri, treenodehref)
                    if m0: compid = m0.group(1)
                    pri = val['propagationRiskIndex']                                                 
                    if treenodehref != None and pri != None: comppridict.get(bcid).update({compid:pri}) 
        json_snapshot_components_pri = None
    return comppridict


########################################################################
 
def initialize_bc_tch_mapping(logger, connection, warname, user, password, apikey, domain, applicationid, snapshotid, bcids):
    outputtcids = {}
    for bcid in bcids:
        outputtcid = []
        json = get_snapshot_bc_tc_mapping(logger, connection, warname, user, password, apikey, domain, snapshotid, bcid)
        if json != None:
            if json != None:
                for val in json['gradeContributors']:
                    outputtcid.append(val['key'])
        outputtcids.update({bcid:outputtcid}) 
        json = None
    return outputtcids

########################################################################
# workaround to remove the unicode characters before sending them to the CSV file
# and avoid the below error
#UnicodeEncodeError: 'charmap' codec can't encode character '\x82' in position 105: character maps to <undefined>    

def remove_unicode_characters(astr):
    return astr.encode('ascii', 'ignore').decode("utf-8")

    '''
    # harcoded solution that will be removed later
    mystr = mystr.replace('\ufb01', '')
    mystr = mystr.replace('\ufb02', '')
    mystr = mystr.replace('\u200b','')
    
    mystr = mystr.replace('\x80','')
    mystr = mystr.replace('\x82','')
    mystr = mystr.replace('\x83','')
    mystr = mystr.replace('\x84', '')
    mystr = mystr.replace('\x85', '')
    mystr = mystr.replace('\x86', '')
    mystr = mystr.replace('\x87', '')
    mystr = mystr.replace('\x88', '')
    mystr = mystr.replace('\x89', '')
    mystr = mystr.replace('\x90', '')
    mystr = mystr.replace('\x91', '')
    mystr = mystr.replace('\x92', '')
    mystr = mystr.replace('\x93','')
    mystr = mystr.replace('\x94','')
    mystr = mystr.replace('\x95', '')
    mystr = mystr.replace('\x96','')
    mystr = mystr.replace('\x97','')
    mystr = mystr.replace('\x98','')
    mystr = mystr.replace('\x99','')
    mystr = mystr.replace('\x9c','')
    mystr = mystr.replace('\x9f','')

    return mystr
    '''
########################################################################

def init_parse_argument():
    # get arguments
    parser = argparse.ArgumentParser(add_help=False)
    requiredNamed = parser.add_argument_group('Required named arguments')
    requiredNamed.add_argument('-restapiurl', required=True, dest='restapiurl', help='Rest API URL using format https://demo-eu.castsoftware.com/CAST-RESTAPI or http://demo-eu.castsoftware.com/Engineering')
    requiredNamed.add_argument('-edurl', required=False, dest='edurl', help='Engineering dashboard URL using format http://demo-eu.castsoftware.com/Engineering, if empty will be same as restapiurl')    
    requiredNamed.add_argument('-user', required=False, dest='user', help='Username')    
    requiredNamed.add_argument('-password', required=False, dest='password', help='Password')
    requiredNamed.add_argument('-apikey', required=False, dest='apikey', help='Api key')
    requiredNamed.add_argument('-log', required=False, dest='log', help='log file')
    requiredNamed.add_argument('-of', required=False, dest='outputfolder', help='output folder')    
    
    requiredNamed.add_argument('-applicationfilter', required=False, dest='applicationfilter', help='Application name regexp filter')
    requiredNamed.add_argument('-qridfilter', required=False, dest='qridfilter', help='Violation quality rule id regexp filter')
    requiredNamed.add_argument('-qrnamefilter', required=False, dest='qrnamefilter', help='Violation quality rule name regexp filter')
    requiredNamed.add_argument('-componentnamelocationfilter', required=False, dest='componentnamelocationfilter', help='Violation component name location regexp filter')    
    requiredNamed.add_argument('-actionplanfilter', required=False, dest='actionplanfilter', help='Violation action plan filter (WithActionPlan|WithoutActionPlan)')
    requiredNamed.add_argument('-exclusionrequestfilter', required=False, dest='exclusionrequestfilter', help='Violation exclusion filter (Excluded|NotExcluded) default = Excluded')
    requiredNamed.add_argument('-criticalrulesonlyfilter', required=False, dest='criticalrulesonlyfilter', help='Violation quality rules filter (True|False)')
    requiredNamed.add_argument('-violationstatusfilter', required=False, dest='violationstatusfilter', help='Violation status filter (added|unchanged)')
    requiredNamed.add_argument('-componentstatusfilter', required=False, dest='componentstatusfilter', help='Component status filter (added|unchanged|updated)')
    requiredNamed.add_argument('-priminvaluefilter', required=False, dest='priminvaluefilter', help='Violation PRI integer minimum value filter, requires businesscriterionfilter to bet set only with one BC value')
    requiredNamed.add_argument('-businesscriterionfilter', required=False, dest='businesscriterionfilter', help='Business criterion filter : 60016,60012, ...)')
    requiredNamed.add_argument('-technofilter', required=False, dest='technofilter', help='Violation quality rule technology filter (JEE, SQL, HTML5, Cobol...)')
    requiredNamed.add_argument('-componentsfilter', required=False, dest='componentsfilter', help='List of components href filter . DOMAIN08/components/121756,DOMAIN08/components/12875)')
    requiredNamed.add_argument('-violationsfilter', required=False, dest='violationsfilter', help='List of violations to filter (rule pattern 1#components href 1,rule pattern 2#components href 2,...)')
    requiredNamed.add_argument('-displaysource', required=False, dest='displaysource', help='Display the violations source code (true|false), default = false')

    requiredNamed.add_argument('-createexclusions', required=False, dest='createexclusions', help='Create exclusions with the violations selected/filtered (True|False) default = False')
    requiredNamed.add_argument('-createactionplans', required=False, dest='createactionplans', help='Create actions plans with the violations selected/filtered (True|False) default = False')
    requiredNamed.add_argument('-actionplaninputtag', required=False, dest='actionplaninputtag', help='Actions plans tags')
    requiredNamed.add_argument('-comment', required=False, dest='comment', help='Exclusion/Action plan comment')
    
    requiredNamed.add_argument('-detaillevel', required=False, dest='detaillevel', help='Report detail level (Simple|Intermediate|Full) default = Intermediate')
    requiredNamed.add_argument('-csvfile', required=False, dest='csvfile', help='Generate CSV file (true|false) default = false')
    requiredNamed.add_argument('-loglevel', required=False, dest='loglevel', help='Log level (INFO|DEBUG) default = INFO')
    requiredNamed.add_argument('-nbrows', required=False, dest='nbrows', help='max number of rows extracted from the rest API, default = 1000000000')
    
    return parser
########################################################################

def generate_csvfile(logger, data, filepath):
    if data != None:
        '''with open(filepath, mode='w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file, delimiter=';')
            # write in csv file
            csv_writer.writerows(data)
        '''
        file = open(filepath, 'w')
        for line in data:
            #linesplited = line.split(';')
            #msg = 'writing line ' + line#linesplited[0] 
            #logger.debug(msg)
            file.write(line + '\n') 
        msg = 'File ' + filepath + ' generated with ' + str(len(data)) + ' lines'
        print (msg)
        logger.info(msg) 

########################################################################

def get_csvfilepath(outputfolder, appName):
    fpath = ''
    if outputfolder != None:
        fpath = outputfolder + '/'
    fpath += appName + "_violations.csv"
    return fpath 

########################################################################

def is_locked(filepath):
    """Checks if a file is locked by opening it in append mode.
    If no exception thrown, then the file is not locked.
    """
    locked = None
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

########################################################################
if __name__ == '__main__':

    global logger

    parser = init_parse_argument()
    args = parser.parse_args()
    restapiurl = args.restapiurl
    edurl = restapiurl 
    if args.edurl != None:
        edurl = args.edurl
    
    user = 'N/A'
    if args.user != None: 
        user = args.user 
    password = 'N/A'
    if args.password != None: 
        password = args.password    
    apikey = 'N/A'
    if args.apikey != None: 
        apikey = args.apikey    
    log = 'violation_extraction.log'
    if args.log != None:
        log = args.log
    outputfolder = args.outputfolder 

    # Version
    script_version = "1.0.6"

    # new params
    applicationfilter = args.applicationfilter
    qridfilter = args.qridfilter
    qrnamefilter = args.qrnamefilter
    componentnamelocationfilter  = args.componentnamelocationfilter
    actionplanfilter = args.actionplanfilter
    exclusionrequestfilter = args.exclusionrequestfilter
    criticalrulesonlyfilter = False
    if args.criticalrulesonlyfilter != None and (args.criticalrulesonlyfilter == 'True' or args.criticalrulesonlyfilter == 'true'):
        criticalrulesonlyfilter = True
    violationstatusfilter = args.violationstatusfilter
    componentstatusfilter = args.componentstatusfilter
    priminvaluefilter = args.priminvaluefilter
    businesscriterionfilter = args.businesscriterionfilter
    technofilter = args.technofilter
    componentsfilter = args.componentsfilter
    violationsfilter = args.violationsfilter
    displaysource = False
    if args.displaysource != None and (args.displaysource == 'True' or args.displaysource == 'true'):
        displaysource = True
    loglevel = "INFO"
    if args.loglevel != None and (args.loglevel == 'INFO' or args.loglevel == 'DEBUG'):
        loglevel = args.loglevel
    createexclusions = False
    if args.createexclusions  != None and (args.createexclusions == 'True' or args.createexclusions == 'true'):
        createexclusions = True
    createactionplans = False
    if args.createactionplans  != None and (args.createactionplans == 'True' or args.createactionplans == 'true'):
        createactionplans = True        
    actionplaninputtag = 'moderate'
    if args.actionplaninputtag  != None:
        actionplaninputtag = args.actionplaninputtag            
    comment = 'Default comment'
    if args.comment == None:
        if createexclusions: comment = 'Automated exclusion'
        elif createactionplans: comment = 'Automated action plan'
    elif args.comment  != None:
        comment = args.comment
    detaillevel = 'Intermediate'
    if args.detaillevel != None and (args.detaillevel == 'Simple' or args.detaillevel == 'Intermediate' or args.detaillevel == 'Full'):
        detaillevel = args.detaillevel
    csvfile = False
    if args.csvfile != None and (args.csvfile == 'True' or args.csvfile == 'true'):
        csvfile = True
    nbrows = 1000000000
    if args.nbrows != None and type(nbrows) == int: 
        nbrows=args.nbrows
    
    # Do not change this parameter value, just used to speed up the debugging in some specific cases
    bload_all_data = True
    bload_objectviolation_metrics = bload_all_data
    bload_rule_pattern = bload_all_data
    bload_objectviolation_findings = bload_all_data
    bload_qr_results = bload_all_data
    bload_bc_tch_mapping = bload_all_data 
    bload_components_pri = bload_all_data
    bload_serverdetail = bload_all_data
    bload_quality_model = True

    ###########################################################################
    # Forcing the filter values (harcoded), for testing
    # business criteria
    #businesscriterionfilter = "60011,60014"
    # filter only the critical quality rules : True|False 
    #criticalrulesonlyfilter = True

    #qridfilter = None
    #qrnamefilter = 'Avoid calling programs statically' 
    #componentnamelocationfilter = '.*COBRPT07|.*COBASV03'
          
    # NotExcluded : will keep only violation not excluded
    # Excluded: will keep only violation excluded
    #exclusionRequestfilter = 'Excluded'
    #exclusionRequestfilter = 'NotExcluded'
    
    # WithActionPlan : having action plan
    # WithoutActionPlan : not having action plan
    #actionplanfilter = 'WithActionPlan'
    #actionplanfilter = 'WithoutActionPlan'
    #actionplanfilter = None

    
    #Violations added/unchanged
    #violationstatusfilter = 'added'
    #Components added/unchanged/updated 
    #componentstatusfilter = 'updated'
    
    # Either None or a integer value representing the minimal value for PRI
    #priminvaluefilter = 500
    #priminvaluefilter = None
    
    # This is only to add the PRI, the violations are not filtered
    #60017, TQI no PRI, 60016 # Security, 60013 # Robustness, 60014 # Efficiency, 60011 # Transferability, 60012 # Changeability, 66031 # Programming practices
    #businessCriterionForPRI = 60016 # Security
    
    # filter the technology
    #technofilter = 'JEE'                                
    
    ###########################################################################

    # setup logging
    logger = logging.getLogger(__name__)
    handler = logging.FileHandler(log, mode="w")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    if loglevel == 'INFO':
        logger.setLevel(logging.INFO)
    elif loglevel == 'DEBUG':
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    try:
        rootapiurl = 'Undefined'
        rootedurl = 'Undefined'
        protocol = 'Undefined'
        host = 'Undefined'
        warname = 'Undefined'
        
        currentviolurl = ''
        qrrulepatternhref = ''
        componentHref = ''
        currentviolpartialurl = ''
        currentviolfullurl = ''
        
        # Processing for the REST API URL 
        rexURL = "(([hH][tT][tT][pP][sS]*)[:][/][/]([A-Za-z0-9_:\.-]+)([/]([A-Za-z0-9_\.-]+))*[/]*)"
        m0 = re.search(rexURL, restapiurl)
        if m0:
            rootapiurl = m0.group(1)
            protocol = m0.group(2)
            host = m0.group(3)
            warname = m0.group(5)
        else:
            logger.error('Malformed restapiurl value, abording : ' + restapiurl)
            sys.exit(-1)
  
        # Processing for the Engineering dashboard URL 
        rexURL = "(([hH][tT][tT][pP][sS]*)[:][/][/]([A-Za-z0-9_:\.-]+)([/]([A-Za-z0-9_\.-]+))*[/]*)"
        m0 = re.search(rexURL, edurl)
        if m0:
            rootedurl = m0.group(1)
        else:
            logger.error('Malformed rootedurl value, abording : ' + rootedurl)
            sys.exit(-1)  
    
        # log params
        logger.info('********************************************')
        logger.info('script_version='+script_version)
        logger.info('****************** params ******************')
        logger.info('restapiurl='+restapiurl)
        logger.info('edurl='+edurl)
        logger.info('rootedurl='+rootedurl)
        logger.info('host='+host)
        logger.info('protocol='+protocol)
        logger.info('warname='+str(warname))
        logger.info('usr='+str(user))
        logger.info('pwd=*******')
        logger.info('apikey='+str(apikey))
        logger.info('log file='+log)
        logger.info('log level='+loglevel)
        logger.info('applicationfilter='+str(applicationfilter))
        logger.info('qridfilter='+str(qridfilter))
        logger.info('qrnamefilter='+str(qrnamefilter))
        logger.info('componentnamelocationfilter='+str(componentnamelocationfilter))
        logger.info('actionplanfilter='+str(actionplanfilter))
        logger.info('exclusionrequestfilter='+str(exclusionrequestfilter))
        logger.info('criticalrulesonlyfilter='+str(criticalrulesonlyfilter))
        logger.info('violationstatusfilter='+str(violationstatusfilter))
        logger.info('priminvaluefilter='+str(priminvaluefilter))
        logger.info('businesscriterionfilter='+str(businesscriterionfilter))
        logger.info('componentsfilter='+str(componentsfilter))
        logger.info('violationsfilter='+str(violationsfilter))
        logger.info('createexclusions='+str(createexclusions))
        logger.info('createactionplans='+str(createactionplans))
        logger.info('actionplaninputtag='+str(actionplaninputtag))
        logger.info('comment='+str(comment))
        logger.info('technofilter='+str(technofilter))
        logger.info('detaillevel='+str(detaillevel))
        logger.info('nbrows='+str(nbrows))
        logger.info('csvfile='+str(csvfile))
        logger.info('displaysource='+str(displaysource))
        logger.info('output folder='+str(outputfolder))
        logger.info('bload_all_data='+str(bload_all_data))
        logger.info('bload_objectviolation_metrics='+str(bload_objectviolation_metrics))
        logger.info('bload_rule_pattern='+str(bload_rule_pattern))
        logger.info('bload_objectviolation_findings='+str(bload_objectviolation_findings))
        logger.info('bload_qr_results='+str(bload_qr_results))
        logger.info('bload_bc_tch_mapping='+str( bload_bc_tch_mapping))
        logger.info('bload_components_pri='+str(bload_components_pri))
        logger.info('bload_serverdetail='+str(bload_serverdetail))
        logger.info('bload_quality_model='+str(bload_quality_model))
        
        logger.info('********************************************')    
        connection = open_connection(logger, host, protocol)   
        progressmsg = 'Initialization'
        print(progressmsg)
        logger.info(progressmsg)        
        # few checks on the server
        json_server = None
        if not bload_serverdetail:
            logger.debug("NOT loading the server detail")
        else: 
            json_server = get_server(logger, connection, warname, user, password, apikey)
        
        if json_server != None:
            logger.info('server status=' + json_server['status'])    
            servversion = json_server['version']
            logger.info('server version=' + servversion)
            #servversion2digits = servversion[-4:] 
            #if float(servversion2digits) <= 1.13 : 
            #    None
            logger.info('server memory (free)=' + str(json_server['memory']['freeMemory']))
            logger.info('********************************************')    
        
        # retrieve the domains & the applications in those domains 
        json_domains = get_domains(logger, connection, warname, user, password, apikey)
        if json_domains != None:
            idomain = 0
            for item in json_domains:
                idomain += 1
                domain = ''
                try:
                    domain = item['href']
                except KeyError:
                    pass
                
                msg = "Domain " + domain + " | progress:" + str(idomain) + "/" + str(len(json_domains))
                logger.info(msg)
                print(msg)                 # only engineering domains
                if domain != 'AAD':  #and domain == 'AED_AYYILDIZ':
                    json_apps = get_applications(logger, connection, warname, user, password, apikey,domain)
                    applicationid = -1
                    appHref = ''
                    appName = ''
                    for app in json_apps:
                        try:
                            appName = app['name']
                        except KeyError:
                            pass                        
                        try:
                            appHref = app['href']
                        except KeyError:
                            pass     
                        hrefsplit = appHref.split('/')
                        for elem in hrefsplit:
                            # the last element is the id
                            applicationid = elem
                            
                        #appName = 'eCommer.*'
                        if applicationfilter != None and not re.match(applicationfilter, appName):
                            logger.info('Skipping application : ' + appName)
                            continue                
                        elif applicationfilter == None or re.match(applicationfilter, appName):
                            msg = "Processing application " + appName
                            logger.info(msg)
                            print(msg)
                            csvdatas = [] 
                            if csvfile != None and csvfile:
                                # testing if csv file can be written
                                fpath = get_csvfilepath(outputfolder, appName)
                                filelocked = False
                                icount = 0
                                while icount < 10 and is_locked(fpath):
                                    icount += 1
                                    filelocked = True
                                    msg = 'File %s is locked. Please unlock it ! Waiting 5 seconds before retrying (try %s/10) ' % (fpath, str(icount))
                                    logger.warn(msg)
                                    print(msg)
                                    time.sleep(5)
                                if is_locked(fpath):
                                    msg = 'File %s is locked, aborting for application %s' % (fpath,appName)
                                    logger.error(msg)
                                    print(msg)
                                    continue
                                               
                            # snapshot list
                            json_snapshots = get_application_snapshots(logger, connection,warname, user, password, apikey,domain, applicationid)
                            if json_snapshots != None:
                                for snap in json_snapshots:
                                    csvdata = []
                                    snapHref = ''
                                    snapshotid = -1
                                    try:
                                        snapHref = snap['href']
                                    except KeyError:
                                        pass                             
                                    hrefsplit = snapHref.split('/')
                                    for elem in hrefsplit:
                                        # the last element is the id
                                        snapshotid = elem
    
                                    snapshotversion = snap['annotation']['version']
                                    snapshotdate =  snap['annotation']['date']['isoDate']    
                                    logger.info("    Snapshot " + snapHref + '#' + snapshotid)


                                    # Number of violations / snapshots
                                    progressmsg = 'Initialization (step 1/5)'
                                    print(progressmsg)
                                    logger.info(progressmsg)
                                    json_tot_violations = get_total_number_violations(logger, connection, warname, user, password, apikey,domain, applicationid, snapshotid)
                                    intotalviol = -1
                                    intotalcritviol = -1
                                    if (json_tot_violations != None):
                                        for elm0 in json_tot_violations:
                                            #67011 : total number of critical violations
                                            #67211 : total number all violations
                                            for elm in elm0['applicationResults']:
                                                if elm['reference']['key'] == "67011":
                                                    intotalcritviol = elm['result']['value']
                                                elif elm['reference']['key'] == "67211":
                                                    intotalviol = elm['result']['value']
                                    #print ('total / critical violations ' + str(intotalviol) + ' ' + str(intotalcritviol))
                                                                        
                                    # retrieve the mapping quality url id => technical criterion id
                                    tqiqm = {}
                                    json_snapshot_quality_model = None
                                    progressmsg = 'Initialization (step 2/5)'
                                    print(progressmsg)
                                    logger.info(progressmsg)                                    
                                    if not bload_quality_model:
                                        logger.info("NOT Extracting the snapshot quality model")                                           
                                    else:
                                        json_snapshot_quality_model = get_snapshot_tqi_quality_model(logger, connection, warname, user, password, apikey,domain, snapshotid)
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
                                            qrcrt = qmitem['critical']
                                            tqiqm[qrid] = {"critical":qrcrt,"tc":{},"maxWeight":maxWeight,"compoundedWeight":qrcompoundWeight,"compoundedWeightFormula":qrcompoundWeightFormula}
                                            #contains the technical criteria (might be several) for each rule, we keep the fist one
                                            for tccont in qmitem['compoundedWeightTerms']:
                                                term = tccont['term'] 
                                                #tqiqm[qrid] = {tccont['technicalCriterion']['key']: tccont['technicalCriterion']['name']} 
                                                #TODO: add qrcompoundWeight and/or qrcompoundWeightFormula
                                                tqiqm.get(qrid).get("tc").update({tccont['technicalCriterion']['key']: tccont['technicalCriterion']['name']})
                                                
                                        json_snapshot_quality_model = None
                                        
                                    progressmsg = 'Initialization (step 3/5)'
                                    print(progressmsg)
                                    logger.info(progressmsg) 
                                    mapbctc = None                                     
                                    if not bload_bc_tch_mapping:
                                        logger.info("NOT Extracting the snapshot business criteria => technical criteria mapping")                                          
                                    else:    
                                        mapbctc = initialize_bc_tch_mapping(logger, connection, warname, user, password, apikey,domain, applicationid, snapshotid, bcids)
                                    
                                    # Components PRI
                                    progressmsg = 'Initialization (step 4/5)'
                                    print(progressmsg)
                                    logger.info(progressmsg) 
                                    comppri = None
                                    transactionlist = {}
                                    
                                    if not bload_components_pri:
                                        logger.info("NOT extracting the components PRI for the business criteria")
                                    else: 
                                        if detaillevel == 'Intermediate' or detaillevel == 'Full':
                                            try : 
                                                comppri = initialize_components_pri(logger, connection, warname, user, password, apikey,domain, applicationid, snapshotid, bcids,nbrows)
                                            except ValueError:
                                                None
                                            transactionlist = init_transactions(logger, connection, warname, user, password, apikey,domain, applicationid, snapshotid,criticalrulesonlyfilter, violationstatusfilter, technofilter,nbrows)
                                    
                                    ###################################################################
                                    # table containing the scheduled exclusions to create
                                    json_new_scheduledexclusions = []
                                    # table containing the scheduled exclusions to create
                                    json_new_actionplans = []
                                    iCounterFilteredViolations = 0
                                    iCouterRestAPIViolations = 0

                                    progressmsg = 'Initialization (step 5/5)'
                                    print(progressmsg)
                                    logger.info(progressmsg)                                      
                                    # quality rules details (nb violations, % compliance)
                                    json_qr_results = None
                                    if not bload_qr_results:
                                        logger.info("NOT Extracting the quality rules details")                                          
                                    else:    
                                        json_qr_results = get_qualityrules_results(logger, connection, warname, user, password, apikey, domain, applicationid, criticalrulesonlyfilter, nbrows)
                                    if json_qr_results != None:
                                        for res in json_qr_results:
                                            for res2 in res['applicationResults']:
                                                if res2['type'] == 'quality-rules': 
                                                    try:
                                                        grade = res2['result']['grade']
                                                    except KeyError:
                                                        grade = None
                                                    try:
                                                        key = res2['reference']['key']
                                                    except KeyError:
                                                        key = None                                                    
                                                    try:
                                                        failedchecks = res2['result']['violationRatio']['failedChecks']
                                                    except KeyError:
                                                        failedchecks = None                                                          
                                                    try:
                                                        successfulChecks = res2['result']['violationRatio']['successfulChecks']
                                                    except KeyError:
                                                        successfulChecks = None                                                             
                                                    try:
                                                        totalChecks = res2['result']['violationRatio']['totalChecks']
                                                    except KeyError:
                                                        totalChecks = None                                                         
                                                    try:
                                                        ratio = res2['result']['violationRatio']['ratio']
                                                    except KeyError:
                                                        ratio = None                                                            
                                                    try:
                                                        addedViolations = res2['result']['evolutionSummary']['addedViolations']                                              
                                                    except KeyError:
                                                        addedViolations = None   
                                                    try:
                                                        removedViolations = res2['result']['evolutionSummary']['removedViolations']
                                                    except KeyError:
                                                        removedViolations = None                                                          
                                                    if key != None and tqiqm.get(key) != None:
                                                        tqiqm.get(key).update({"failedchecks":failedchecks,"successfulChecks":successfulChecks,"totalChecks":totalChecks,"ratio":ratio,"addedViolations":addedViolations,"removedViolations":removedViolations})
                                                    
                                            #    res2['']
                                                # only the last snapshot
                                            #    break                                                
                                            # only the last snapshot
                                            break

                                    progressmsg = 'Extracting violations'
                                    print(progressmsg)
                                    logger.info(progressmsg)
                                    progressmsg = 'Loading violations & components data from the REST API'
                                    print(progressmsg)
                                    logger.info(progressmsg)                                    
                                    json_violations = get_snapshot_violations(logger, connection, warname, user, password, apikey,domain, applicationid, snapshotid,  criticalrulesonlyfilter, violationstatusfilter, businesscriterionfilter, technofilter,nbrows)
                                    if json_violations != None:
                                        msg = 'Application name;Date;Version;Count (Filter)'
                                        #msg += ';Count (Rest API);Total # violations (Rest API)'
                                        msg += ';Total # critical violations;Total # violations'
                                        msg += ';QR Id;QR Name;QR Critical;Max Weight;Compounded Weight;Compounded Weight Formula;QR failed checks;QR Compliance ratio;QR Added violations;QR Removed violations'
                                        msg += ';Component type;Component name location;Violation status;Component status;Associated value label;Associated value'
                                        msg += ';Technical criteria;Business Criteria;Quality standards;PRI for selected Business criterion;PRI Security;PRI Efficiency;PRI Robustness;PRI Transferability;PRI Changeability'
                                        msg += ';Number of transactions;Transaction list;'
                                        msg += 'Efficiency - Number of transactions;Efficiency - Max TRI;Efficiency - Transactions TRI'
                                        msg += ';Robustness - Number of transactions;Robustness - Max TRI;Robustness - Transactions TRI'
                                        msg += ';Security - Number of transactions;Security - Max TRI;Security - Transactions TRI'
                                        msg += ';Critical violations;Cyclomatic complexity;LOC;CommentLines;Ratio CommentLines/CodeLines'
                                        msg += ';Action plan status;Action plan tag;Action plan comment'
                                        msg += ';Exclusion request;Exclusion request comment'
                                        msg += ';Parameters;URL;Quality rule URI;Component URI;Violation findings URI;Violation id;Bookmarks;Source code sniplet'
                                        #print(msg)
                                        #logger.debug(msg)
                                        if csvfile:
                                            #for it in msg.split(";"):
                                            #    csvdata.append(it)
                                            csvdatas.append(msg)

                                        lastProgressReported = None
                                        for violation in json_violations:
                                            iCouterRestAPIViolations += 1
                                            currentviolurl = ''
                                            violations_size = len(json_violations)
                                            imetricprogress = int(100 * (iCouterRestAPIViolations / violations_size))
                                            '''
                                            if imetricprogress in (9,19,29,39,49,59,69,79,89,99) : 
                                                if lastProgressReported == None or lastProgressReported != imetricprogress:
                                                    progressmsg = ' ' + str(imetricprogress+1) + '% of the violations processed (' + str(iCouterRestAPIViolations) + "/" + str(violations_size) + ')'
                                                    logger.info(progressmsg)
                                                    print(progressmsg)
                                                    lastProgressReported = imetricprogress                                            
                                            '''
                                            if iCouterRestAPIViolations==1 or iCouterRestAPIViolations==violations_size or iCouterRestAPIViolations%500 == 0:
                                                msg = "processing violation " + str(iCouterRestAPIViolations) + "/" + str(violations_size)  + ' (' + str(imetricprogress) + '%)'
                                                print(msg)
                                                logger.info(msg)
                                            try:
                                                qrname = violation['rulePattern']['name']
                                            except KeyError:
                                                qrname = None    
                                            qrcritical = '<Not extracted>'
                                            try:
                                                qrcritical = str(violation['rulePattern']['critical'])
                                            except KeyError:
                                                # in earlier versions of the rest API this information was not available, taking the value from another location when possible
                                                if tqiqm != None and tqiqm[qrid] != None and tqiqm[qrid].get("critical") != None:
                                                    qrcritical = str(tqiqm[qrid].get("critical"))                                                    
                                            try:                                    
                                                qrrulepatternhref = violation['rulePattern']['href']
                                            except KeyError:
                                                qrrulepatternhref = None
                                            
                                            qrid = ''
                                            qrrulepatternsplit = qrrulepatternhref.split('/')
                                            for elem in qrrulepatternsplit:
                                                # the last element is the id
                                                qrid = elem
                                                
                                            # filter on quality rule id or name, if the filter match
                                            if qridfilter != None and not re.match(qridfilter, str(qrid)):
                                                continue
                                            if qrnamefilter != None and not re.match(qrnamefilter, qrname):
                                                continue
                                                
                                            try:                                    
                                                actionPlan = violation['remedialAction']
                                            except KeyError:
                                                actionPlan = None
                                            # filter the violations already in the action plan 
                                            if actionplanfilter != None and actionplanfilter == 'WithActionPlan' and actionPlan == None:
                                                continue
                                            # filter the violations not in the action plan 
                                            if actionplanfilter != None and actionplanfilter == 'WithoutActionPlan' and actionPlan != None:
                                                continue
                                                
                                            try:                                    
                                                exclusionRequest = violation['exclusionRequest']
                                            except KeyError:
                                                exclusionRequest = None
                                            # filter the violations already in the exclusion list 
                                            if exclusionrequestfilter != None and exclusionrequestfilter == 'Excluded' and exclusionRequest != None:
                                                continue
                                            # filter the violations not in the exclusion list 
                                            if exclusionrequestfilter != None and exclusionrequestfilter == 'NotExcluded' and exclusionRequest == None:
                                                continue
                                                
                                            try:                                    
                                                violationsStatus = violation['diagnosis']['status']
                                            except KeyError:
                                                violationsStatus = None
                                            try:
                                                componentHref = violation['component']['href']
                                            except KeyError:
                                                componentHref = None

                                            componentid = ''
                                            rexcompid = "/components/([0-9]+)/snapshots/"
                                            m0 = re.search(rexcompid, componentHref)
                                            if m0: 
                                                componentid = m0.group(1)

                                            # filter the components that are not in the list if a list of component href is provided
                                            if componentsfilter != None and componentHref not in componentsfilter:
                                                # example DOMAIN08/components/165586,DOMAIN08/components/166686
                                                continue

                                            # filter the violations that are not in the list if a list of violations href is provided
                                            if violationsfilter != None and qrrulepatternhref+'#'+componentHref not in violationsfilter: 
                                                # example : DOMAIN08/rule-patterns/7778#DOMAIN08/components/137407/snapshots/21,DOMAIN08/rule-patterns/7776#DOMAIN08/components/13766/snapshots/21                                          
                                                continue
                                                
                                            try:
                                                componentShortName = violation['component']['shortName']
                                            except KeyError:
                                                componentShortName = None                                        
                                            try:
                                                componentNameLocation = violation['component']['name']
                                            except KeyError:
                                                componentNameLocation = None                                        
                                            # filter on component name location
                                            if componentnamelocationfilter != None and not re.match(componentnamelocationfilter, componentNameLocation):
                                                continue
                                                
                                            try:
                                                componentStatus = violation['component']['status']
                                            except KeyError:
                                                componentStatus = None                                            
                                            # filter on component status
                                            if componentstatusfilter != None and componentStatus != None and componentstatusfilter != componentStatus:
                                                continue
    
                                            try:
                                                findingsHref = violation['diagnosis']['findings']['href']
                                            except KeyError:
                                                findingsHref = None                                            
                                            try:
                                                componentTreeNodeHref = violation['component']['treeNodes']['href']
                                            except KeyError:
                                                componentTreeNodeHref = None                                        
                                            try:
                                                sourceCodesHref = violation['component']['sourceCodes']['href']
                                            except KeyError:
                                                sourceCodesHref = None
                                            
                                            try:
                                                propagationRiskIndex = violation['component']['propagationRiskIndex']
                                            except KeyError:
                                                propagationRiskIndex = None                                        
                                            # filter on a minimum PRI value 
                                            if priminvaluefilter != None:
                                                if propagationRiskIndex != None and propagationRiskIndex != None and propagationRiskIndex < priminvaluefilter:
                                                    continue
                                            
                                            firsttechnicalcriterionid = ''
                                            technicalcriteriaidandnames = ''
                                            for key in tqiqm[qrid].get("tc").keys():
                                                firsttechnicalcriterionid = key
                                                technicalcriteriaidandnames += firsttechnicalcriterionid+'#'+tqiqm[qrid].get("tc").get(key) + ','
                                            technicalcriteriaidandnames = technicalcriteriaidandnames[:-1]
                                            
                                            ######################################################################################################################################                                           
                                            # get more details from the component URI
                                            json_component = None
                                            if not bload_objectviolation_metrics:
                                                logger.debug("NOT Extracting the component metrics") 
                                            else:
                                                if detaillevel == 'Full':
                                                    #TODO:add a cache to avoid reloading several time the same object
                                                    json_component = get_objectviolation_metrics(logger, connection, warname, user, password, apikey,componentHref)
                                            
                                            componentType = '<Not extracted>'
                                            criticalViolations = '<Not extracted>'
                                            cyclomaticComplexity = '<Not extracted>'
                                            codeLines = '<Not extracted>'
                                            commentLines = '<Not extracted>'
                                            ratioCommentLinesCodeLines = '<Not extracted>'
                                            if json_component != None:
                                                try:
                                                    componentType = json_component['type']['label']
                                                except KeyError:
                                                    None                              
                                                try:
                                                    codeLines = json_component['codeLines']
                                                    if codeLines == None :  codeLines = 0
                                                except KeyError:
                                                    codeLines = 0
                                                try:
                                                    commentedCodeLines = json_component['commentedCodeLines']
                                                    if commentedCodeLines == None :  commentedCodeLines = 0
                                                except KeyError:
                                                    commentedCodeLines = 0                                          
                                                try:
                                                    commentLines = json_component['commentLines']
                                                    if commentLines == None :  commentLines = 0
                                                except KeyError:
                                                    commentLines = 0
                                                      
                                                try:
                                                    fanIn = json_component['fanIn']
                                                except KeyError:
                                                    fanIn = 0
                                                try:
                                                    fanOut = json_component['fanOut']
                                                except KeyError:
                                                    fanOut = 0 
                                                try:
                                                    cyclomaticComplexity = json_component['cyclomaticComplexity']
                                                except KeyError:
                                                    cyclomaticComplexity ='Not available'   
                                                '''
                                                Incorrect ratio, recomputing manually
                                                try:
                                                    ratioCommentLinesCodeLines = json_component['ratioCommentLinesCodeLines']
                                                except KeyError:
                                                    ratioCommentLinesCodeLines = None
                                                '''
                                                ratioCommentLinesCodeLines = None
                                                if codeLines != None and commentLines != None and codeLines != 'Not available' and commentLines != 'Not available' and (codeLines + commentLines != 0) :
                                                    ratioCommentLinesCodeLines = commentLines / (codeLines + commentLines) 
                                                else:
                                                    ratioCommentLinesCodeLines = 0
                                                try:
                                                    halsteadProgramLength = json_component['halsteadProgramLength']
                                                except KeyError:
                                                    halsteadProgramLength = 0
                                                try:
                                                    halsteadProgramVocabulary = json_component['halsteadProgramVocabulary']
                                                except KeyError:
                                                    halsteadProgramVocabulary = 0
                                                try:
                                                    halsteadVolume = json_component['halsteadVolume']
                                                except KeyError:
                                                    halsteadVolume = 0 
                                                try:
                                                    distinctOperators = json_component['distinctOperators']
                                                except KeyError:
                                                    distinctOperators = 0 
                                                try:
                                                    distinctOperands = json_component['distinctOperands']
                                                except KeyError:
                                                    distinctOperands = 0                                             
                                                try:
                                                    integrationComplexity = json_component['integrationComplexity']
                                                except KeyError:
                                                    integrationComplexity = 0
                                                try:
                                                    criticalViolations = json_component['criticalViolations']
                                                except KeyError:
                                                    criticalViolations = 'Not available'
                                            json_component = None

                                            #####################################################################################################

                                            associatedValueName = None
                                            strqualitystandards = '<Not extracted>'
                                            json_rulepattern = None
                                            if not bload_rule_pattern:
                                                logger.debug("NOT Extracting the rule pattern details")                                                
                                            else:
                                                if detaillevel == 'Full':
                                                    #TODO:add a cache to avoid reloading several time the same rule
                                                    json_rulepattern = get_rule_pattern(logger, connection, warname, user, password, apikey,qrrulepatternhref)
                                            if json_rulepattern != None:
                                                try:
                                                    associatedValueName = json_rulepattern['associatedValueName']
                                                except KeyError:
                                                    None
                                                try:
                                                    strqualitystandards = ''
                                                    qslist = json_rulepattern['qualityStandards']
                                                    for qs in qslist:
                                                        strqualitystandards += qs['standard']+"/"+qs['id'] + ","
                                                    if strqualitystandards != '': strqualitystandards = strqualitystandards[:-1]
                                                except KeyError:
                                                    None
                                            if associatedValueName == None : associatedValueName = ''
                                            json_rulepattern = None

                                            #####################################################################################################
                                            associatedvaluelabel = '<Not extracted>'
                                            associatedvalue = '<Not extracted>'
                                            strbookmarks = '<Not extracted>'
                                            strparams = '<Not extracted>'
                                            json_findings = None
                                            srcCode = []

                                            if not bload_objectviolation_findings:
                                                logger.info("NOT Extracting the component findings")
                                            elif detaillevel == 'Full':
                                            # we skip if the associated value contains a path that is not managed and can be very time consuming
                                            # for rules like Avoid indirect String concatenation inside loops (more than 1 mn per api call)
                                                if not 'path' in associatedValueName.lower():
                                                    json_findings = get_objectviolation_findings(logger, connection, warname, user, password, apikey,componentHref, qrid)
                                                
                                                if json_findings != None: 
                                                    fin_name = json_findings['name']
                                                    fin_type = json_findings['type']
                                                    fin_values = json_findings['values']
                                                    fin_bookmarks = json_findings['bookmarks']
                                                    fin_parameters = json_findings['parameters']
                                                    
                                                    associatedvalue = ''
                                                    associatedvaluelabel = ''
                                                    strbookmarks = ''
                                                    strparams = ''
                                                    
                                                    logger.debug("          fin_name=" + str(fin_name))
                                                    logger.debug("          fin_type=" + str(fin_type))
                                                    logger.debug("          fin_values=" + str(fin_values))
                                                    logger.debug("          fin_bookmarks=" + str(fin_bookmarks))
                                                    logger.debug("          fin_parameters=" + str(fin_parameters))
                                                
                                                    if fin_type != None and fin_values != None:  
                                                        associatedvaluelabel = fin_name
                                                        if fin_type == 'integer' or fin_type == 'text': 
                                                            # possible multiple values 
                                                            for val in fin_values: 
                                                                associatedvalue += str(val) + ','
                                                        elif fin_type == 'object':
                                                            for val in fin_values: 
                                                                associatedvalue += str(val['component']['name']) + ','
                                                        elif fin_type == 'group':
                                                            for val in fin_values: 
                                                                for val2 in val:
                                                                    associatedvalue += str(val2['component']['name']) + ','
                                                        if associatedvalue != '': associatedvalue = associatedvalue[:-1]
        
                                                    if fin_bookmarks != None:
                                                        icountbkm = 0
                                                        for bkm in fin_bookmarks:
                                                            for bkm2 in bkm:
                                                                try:
                                                                    icountbkm += 1
                                                                    startLine = bkm2['codeFragment']['startLine']
                                                                    endLine = bkm2['codeFragment']['endLine']
                                                                    strbookmarks += '#' + str(icountbkm) + ':' + str(startLine)+'=>' + str(endLine) + ','
                                                                except KeyError:
                                                                    None
                                                        if strbookmarks != '': strbookmarks = strbookmarks[:-1]
                                                        
                                                    if fin_parameters != None:
                                                        for param in fin_parameters:
                                                            strparams += param['name'] + '='
                                                            for value in param['values']:
                                                                strparams += str(value) + '|'
                                                            strparams = strparams[:-1] 
                                                            strparams += ';'
                                                        strparams = strparams[:-1]
                                                json_findings = None
                                                
                                            # Do not export the code for QR 7294 Avoid cyclical calls and inheritances between namespaces content
                                            if qrid == 7294:
                                                continue
                                            #AED5/local-sites/162402639/file-contents/140 lines 167=>213
                                            if displaysource: 
                                                if sourceCodesHref != None:
                                                    json_sourcescode = get_sourcecode(logger, connection, sourceCodesHref, warname, user, password, apikey)
                                                    if json_sourcescode != None:
                                                        for src in json_sourcescode:
                                                            filereference = ''
                                                            filename = src['file']['name']
                                                            filehref = src['file']['href']
                                                            filesize = src['file']['size']
                                                            srcstartline = src['startLine']
                                                            srcendline = src['endLine']
                                                            filereference = filename
                                                            strstartendlineparams = ''
                                                            if srcstartline >= 0 and srcendline >= 0:
                                                                filereference += ': lines ' + str(srcstartline) + ' => ' +str(srcendline)

                                                            partialfiletxt = get_sourcecode_file(logger, connection, warname, filehref, srcstartline, srcendline, user, password, apikey)
                                                            if partialfiletxt != None:
                                                                filewithlinesnumber = ''
                                                            if qrid != 7294:
                                                                if srcstartline >= 0 :
                                                                    filelines = partialfiletxt.split("\n")
                                                                    iline = srcstartline
                                                                    for line in filelines:
                                                                        filewithlinesnumber += str(iline) + ' ' +  line + '\n'
                                                                        iline += 1
                                                                    srcCode.append(filereference + '\n' + filewithlinesnumber)
                                                                else: srcCode.append(filereference + '\n' + partialfiletxt)
                                                            elif qrid == 7294:
                                                                # do not export the code for QR 7294 Avoid cyclical calls and inheritances between namespaces content
                                                                # only the file name is enough, cause it's not providing much value 
                                                                srcCode.append(filereference)
                                                            partialfiletxt = None     
                                                    json_sourcescode = None
                                            else:
                                                srcCode.append('<Not extracted>')
                                            # No code, should we look at the tree node, but I don't think there is something to show there
                                            # for example for java packages, no code to show
                                            # so we don't do anything for now  
                                            #elif componentTreeNodeHref != None:
                                            #    json_treenode = execute_request(logger, connection, 'GET', componentTreeNodeHref, warname, user, password, apikey, None)
                                                    
                                            #####################################################################################################
                                            # building the reporting
                                            iCounterFilteredViolations += 1
                                            strprogress = str(iCounterFilteredViolations) + "/" + str(violations_size) + "/" + str(intotalviol)
                                            strtotalviol = str(intotalviol)[:-2]
                                            strtotalcritviol = str(intotalcritviol)[:-2]
                                            msg = appName + ";" + str(snapshotdate) + ";" + str(snapshotversion) +  ";" + str(iCounterFilteredViolations) 
                                            #msg +=  ";" + str(iCouterRestAPIViolations)  +  ";" + str(violations_size) + 
                                            msg +=  ";" + strtotalcritviol + ";" + strtotalviol 
                                            msg += ";" + str(qrid)+ ";" + str(qrname) + ";" +  str(qrcritical) + ";" + str(tqiqm[qrid].get('maxWeight')) + ";" + str(tqiqm[qrid].get('compoundedWeight')) + ";" + tqiqm[qrid].get('compoundedWeightFormula') 
                                            msg += ";" + str(tqiqm[qrid].get('failedchecks')) + ";" + str(tqiqm[qrid].get('ratio')) + ";" + str(tqiqm[qrid].get('addedViolations')) + ";" + str(tqiqm[qrid].get('removedViolations'))

                                            msg += ";" + str(componentType) + ";" + str(componentNameLocation) + ";"+ str(violationsStatus) + ";" + str(componentStatus) + ";" + str(associatedvaluelabel)+ ";" +  str(associatedvalue)
                                            msg += ";" + str(technicalcriteriaidandnames)
                                            #
                                            strlistbc = ''
                                            #mapbctc
                                            if mapbctc != None and tqiqm != None:
                                                for bcid in bcids:
                                                    listtc = mapbctc.get(bcid)
                                                    for tc in listtc:
                                                        qrlisttc = tqiqm[qrid].get('tc').keys()
                                                        for tcid in qrlisttc:
                                                            if tc == tcid:
                                                                # found 
                                                                if bcid == "60016": 
                                                                    strlistbc = strlistbc + '60016#Security,'
                                                                if bcid == "60014": 
                                                                    strlistbc = strlistbc + '60014#Efficiency,'
                                                                if bcid == "60013": 
                                                                    strlistbc = strlistbc + '60013#Robustness,'
                                                                if bcid == "60011": 
                                                                    strlistbc = strlistbc + '60011#Transferability,'
                                                                if bcid == "60012": 
                                                                    strlistbc = strlistbc + '60012#Changeability,'
                                            if strlistbc != '': strlistbc = strlistbc[:-1]
                                            msg += ";" + strlistbc
                                            msg += ";" + strqualitystandards
                                                                                                                                                                                                                                        
                                            #########################################################################
                                            # current PRI focus
                                            msg += ";"
                                            
                                            if propagationRiskIndex != None: 
                                                msg += str(propagationRiskIndex)
                                            else: 
                                                msg += 'No BC selected'
                                            # PRI Security
                                            msg += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60016").get(componentid))
                                            except KeyError:
                                                None
                                            msg += pri
                                            # PRI Efficiency
                                            msg += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60014").get(componentid))
                                            except KeyError:
                                                None
                                            msg += pri
                                            # PRI Robusustness
                                            msg += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60013").get(componentid))
                                            except KeyError:
                                                None
                                            msg += pri         
                                            # PRI Transferability
                                            msg += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60011").get(componentid))
                                            except KeyError:
                                                None
                                            msg += pri    
                                            # PRI Changeability
                                            msg += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60012").get(componentid))
                                            except KeyError:
                                                None
                                            msg += pri
                                            #########################################################################  
                                            # TQI - Number of transactions & transactions list
                                            msg += ";" 
                                            numtrans = 0
                                            strtrans = '<Not extracted>'
                                            try:
                                                bctrans = transactionlist.get("60017") 
                                                if bctrans != None:
                                                    strtrans = ''
                                                    for trans in bctrans:
                                                        tobeadded = False
                                                        for comp in trans.get("componentsWithViolations"):
                                                            if comp == componentHref:
                                                                #The component has violation on this transaction
                                                                tobeadded = True
                                                                break
                                                        if tobeadded:
                                                            strtrans += trans.get("name") + ','
                                                            numtrans+=1
                                                        #trans.get("transactionRiskIndex")
                                                    if strtrans != '': strtrans = strtrans[:-1]
                                            except KeyError:
                                                None
                                            if strtrans != "<Not extracted>": 
                                                msg += str(numtrans)
                                            msg += ";"
                                            msg += strtrans

                                            # Effiency - Number of transactions & transactions list & TRI
                                            msg += ";" 
                                            numtrans = 0
                                            maxtri = 0
                                            strtrans = '<Not extracted>'
                                            try:
                                                bctrans = transactionlist.get("60014") 
                                                if bctrans != None:
                                                    strtrans = ''
                                                    for trans in bctrans:
                                                        tobeadded = False
                                                        for comp in trans.get("componentsWithViolations"):
                                                            if comp == componentHref:
                                                                #The component has violation on this transaction
                                                                tobeadded = True
                                                                break
                                                        if tobeadded:
                                                            transname = trans.get("name")
                                                            tri = trans.get("transactionRiskIndex")
                                                            if tri != None and tri > maxtri : maxtri = tri
                                                            strtrans += transname + ':' + str(tri) + ','
                                                            numtrans+=1
                                                        #trans.get("transactionRiskIndex")
                                                    if strtrans != '': strtrans = strtrans[:-1]
                                            except KeyError:
                                                None
                                            if strtrans != "<Not extracted>": 
                                                msg += str(numtrans)
                                            msg += ";" + str(maxtri)                                            
                                            msg += ";" +  strtrans 
                                          
                                            # Robustness - Number of transactions & transactions list & TRI
                                            msg += ";" 
                                            numtrans = 0
                                            maxtri = 0
                                            strtrans = '<Not extracted>'
                                            try:
                                                bctrans = transactionlist.get("60013") 
                                                if bctrans != None:
                                                    strtrans = ''
                                                    for trans in bctrans:
                                                        tobeadded = False
                                                        for comp in trans.get("componentsWithViolations"):
                                                            if comp == componentHref:
                                                                #The component has violation on this transaction
                                                                tobeadded = True
                                                                break
                                                        if tobeadded:
                                                            transname = trans.get("name")
                                                            tri = trans.get("transactionRiskIndex")
                                                            if tri != None and tri > maxtri : maxtri = tri
                                                            strtrans += transname + ':' + str(tri) + ','
                                                            numtrans+=1
                                                        #trans.get("transactionRiskIndex")
                                                    if strtrans != '': strtrans = strtrans[:-1]
                                            except KeyError:
                                                None
                                            if strtrans != "<Not extracted>": 
                                                msg += str(numtrans)
                                            msg += ";" + str(maxtri)                                            
                                            msg += ";" +  strtrans                                             
                                          
                                            
                                            # Security - Number of transactions & transactions list & TRI
                                            msg += ";" 
                                            numtrans = 0
                                            maxtri = 0
                                            strtrans = '<Not extracted>'
                                            try:
                                                bctrans = transactionlist.get("60016") 
                                                if bctrans != None:
                                                    strtrans = ''
                                                    for trans in bctrans:
                                                        tobeadded = False
                                                        for comp in trans.get("componentsWithViolations"):
                                                            if comp == componentHref:
                                                                #The component has violation on this transaction
                                                                tobeadded = True
                                                                break
                                                        if tobeadded:
                                                            transname = trans.get("name")
                                                            tri = trans.get("transactionRiskIndex")
                                                            if tri != None and tri > maxtri : maxtri = tri
                                                            strtrans += transname + ':' + str(tri) + ','
                                                            numtrans+=1
                                                        #trans.get("transactionRiskIndex")
                                                    if strtrans != '': strtrans = strtrans[:-1]
                                            except KeyError:
                                                None
                                            if strtrans != "<Not extracted>": 
                                                msg += str(numtrans)
                                            msg += ";" + str(maxtri)                                            
                                            msg += ";" +  strtrans                                           
                                            #########################################################################                                                                                        
                                            msg += ";"
                                            if criticalViolations != None: msg += str(criticalViolations)
                                            msg += ";"
                                            if cyclomaticComplexity != None: msg += str(cyclomaticComplexity)
                                            msg += ";"
                                            if codeLines != None: msg += str(codeLines)
                                            msg += ";"
                                            if commentLines != None: msg += str(commentLines)
                                            msg += ";"
                                            if ratioCommentLinesCodeLines != None: msg += str(ratioCommentLinesCodeLines)

    
                                            #########################################################################                                  
                                            
                                            if actionPlan != None:
                                                actionplanstatus = actionPlan['status']
                                                actionplantag = actionPlan['tag']
                                                actionplancomment = actionPlan['comment']
                                                # status
                                                msg += ";" + actionplanstatus 
                                                # tag
                                                msg += ";" + actionplantag
                                                # comment
                                                msg += ";" + actionplancomment
                                            else:
                                                msg += ";;;" 
                                            if exclusionRequest != None:
                                                exclusionRequest = exclusionRequest['comment']
                                                # Exclusion request exists
                                                msg += ";true"
                                                # Exclusion request comment
                                                msg += ";" + exclusionRequest
                                            else:
                                                msg += ";;"                                            

                                            #########################################################################
                                            msg += ";"+ strparams
                                            #########################################################################
                                            currentviolurl = ''
                                            currentviolpartialurl= snapHref + '/business/60017/qualityInvestigation/0/60017/' + firsttechnicalcriterionid + '/' + qrid + '/' + componentid
                                            currentviolfullurl= rootedurl + '/engineering/index.html#' + snapHref + '/business/60017/qualityInvestigation/0/60017/' + firsttechnicalcriterionid + '/' + qrid + '/' + componentid
                                            currentviolurl = currentviolfullurl
                                            msg += ";" + currentviolurl
                                            msg += ";"+ str(qrrulepatternhref) + ";" + str(componentHref) + ";" +str(findingsHref)         
                                            msg += ";"+ str(qrrulepatternhref) + "#" + str(componentHref)
                                            msg += ";"+ strbookmarks
                                            # remove unicode characters that are making the reporting fails
                                            msg = remove_unicode_characters(msg)
                                                                                        
                                            #########################################################################
                                            # Show the progress (without the source code)
                                            logger.debug(msg)
                                            #print(msg)
                                            #print(strprogress + "=>" + currentviolurl + '#' +qrrulepatternhref+ '#'+componentHref)
                                            #########################################################################
                                            try:
                                                if len(srcCode) > 0:
                                                    for src in srcCode:
                                                        #msg += ';"'+ str(src).replace('"', '""') + '"'
                                                        # we add only the first 5000 characters
                                                        msg += ';"'+ str(src).replace('"','""')[0:5000] + '"'
                                                else:
                                                    msg += ';N/A'
                                            except: # catch *all* exceptions
                                                msg += ';Error'
                                                tb = traceback.format_exc()
                                                #e = sys.exc_info()[0]
                                                logging.error('  Error to get the source code %s' % tb)

                                            # remove unicode characters that are making the reporting fails
                                            msg = remove_unicode_characters(msg)                                            
                                            #########################################################################
                                            # append the data
                                            if csvfile:
                                                #for it in msg.split(";"):
                                                #    csvdata.append(it)
                                                #csvdatas.append(csvdata)
                                                csvdatas.append(msg)
                                            
                                            #########################################################################
                                            if createexclusions and exclusionRequest == None:
                                                logger.info("Excluding the violation")
                                                # create exclusions with the exclusions selected / filtered
                                                json_new_exclusion_dict = {
                                                    "rulePattern": {"href":qrrulepatternhref}, 
                                                    "component": { "href": componentHref },
                                                    "exclusionRequest": {"comment": comment}
                                                }
                                                json_new_scheduledexclusions.append(json_new_exclusion_dict)
                                                
                                            if createactionplans and actionPlan == None:
                                                logger.info("Adding the violation to action plan")
                                                
                                                json_ap_new = {
                                                      "component": { "href": componentHref },
                                                      "rulePattern": { "href": qrrulepatternhref },
                                                      "remedialAction": { "comment": comment, "tag": actionplaninputtag } 
                                                }                                        
                                                '''
                                                #All types of a serializable Class must be serializable (ASCRM-RLB-2)
                                                #org.owasp.webgoat.HammerHead.webgoatContext
                                                json_ap_new = {
                                                      "component": { "href": "AED5/components/11159/snapshots/3" },
                                                      "rulePattern": { "href": "AED5/rule-patterns/7650" },
                                                      "remedialAction": { "comment": "My ap comment", "tag": "moderate" } 
                                                }
                                                '''
                                                json_new_actionplans.append(json_ap_new)                                                
                                                
                                            #########################################################################
                                        json_violations = None

                                    #########################################################################

                                    
                                    strAppHref = domain + '/applications/' + str(applicationid)
                                    if createexclusions and json_new_scheduledexclusions != None and len(json_new_scheduledexclusions) > 0:
                                        logger.info("Creating "  + str(len(json_new_scheduledexclusions)) + " new exclusions : " + str(json_new_scheduledexclusions))
                                        create_scheduledexclusions(logger, connection, warname, user, password, apikey,strAppHref, json_new_scheduledexclusions)
                                    else:
                                        logger.info("No exclusion created")
                                        
                                    if createactionplans and json_new_actionplans != None:
                                        logger.info("Creating "  + str(len(json_new_actionplans)) + "action plan items " + str(json_new_actionplans))
                                        create_actionplans(logger, connection, warname, user, password, apikey,strAppHref, json_new_actionplans)
                                    else:
                                        logger.info("No action plan created")                                    
                                    
                                    # Summary in the log for this application snapshot
                                    msg = "******************************\n"
                                    msg += "Application name : " + appName + "\n"
                                    msg += "Snapshot : " + snapHref + "\n"
                                    msg += "Total number of violations: " + str(intotalviol) + "\n"
                                    msg += "Total number of critical violations: " + str(intotalcritviol) + "\n"
                                    msg += "Number of violations from the Rest API w/filters business criteria, critical, violations status: " + str(iCouterRestAPIViolations) + "\n"
                                    msg += "Number of violations filtered with the other filters: " + str(iCounterFilteredViolations) + "\n"
                                    msg += "Exclusions created: "
                                    if createexclusions: msg += msg + str(iCounterFilteredViolations) +  "\n"
                                    else: msg += "0\n"
                                    msg += "Action plans created: "
                                    if createactionplans: msg += msg + str(iCounterFilteredViolations) +  "\n"
                                    else: msg += "0\n"
                                    logger.info(msg)

                                    # generated csv file if required                                    
                                    if csvfile != None and csvfile:
                                        fpath = get_csvfilepath(outputfolder, appName)
                                        logger.info("Generating csv file " + fpath)
                                        generate_csvfile(logger, csvdatas, fpath)
                                    # keep only last snapshot
                                    break
        close_connection(logger, connection)   
    except: # catch *all* exceptions
        tb = traceback.format_exc()
        #e = sys.exc_info()[0]
        logging.error('  Error during the processing %s' % tb)
        logging.info(' Last violation URL:' + currentviolfullurl + "=> " + qrrulepatternhref + '#' + componentHref)
