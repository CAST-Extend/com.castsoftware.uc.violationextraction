import json
import argparse
import logging
import logging.handlers
import re
import sys
import traceback
import time
import csv
import xml.etree.ElementTree as ET
import os

import pandas as pd
from io import StringIO
import xlsxwriter
from utils.utils import RestUtils, AIPRestAPI, LogUtils, ObjectViolationMetric, RulePatternDetails, FileUtils, StringUtils, Violation, ViolationFilter,\
    ViolationOutput, QualityStandard, Metric
from model.modelclasses import ArchitectureModel, Property, Layer, Criteria
from model import metamodel

'''
 Author : MMR
 Feb 2020
'''
#Security,Efficiency,Robustness,Transferability,Changeability
bcids = ["60016","60014","60013","60012","60011"]

########################################################################

def init_parse_argument():
    # get arguments
    parser = argparse.ArgumentParser(add_help=True)
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
    
    requiredNamed.add_argument('-automatedactionplan_create', required=False, dest='automatedactionplan_create', help='Create automated actions plan')
    requiredNamed.add_argument('-automatedactionplan_maxnumber', required=False, dest='automatedactionplan_maxnumber', help='Max num of action plan items to create')
    
    
    requiredNamed.add_argument('-detaillevel', required=False, dest='detaillevel', help='Report detail level (Simple|Intermediate|Full) default = Intermediate')
    requiredNamed.add_argument('-outputextension', required=False, dest='outputextension', help='Output file (xlsx|csv) default = csv')
    requiredNamed.add_argument('-loglevel', required=False, dest='loglevel', help='Log level (INFO|DEBUG) default = INFO')
    requiredNamed.add_argument('-nbrows', required=False, dest='nbrows', help='max number of rows extracted from the rest API, default = 1000000000')
    requiredNamed.add_argument('-extensioninstallationfolder', required=False, dest='extensioninstallationfolder', help='extension installation folder')    
    
    requiredNamed.add_argument('-generate_ac_model', required=False, dest='generate_ac_model', help='Generate architecture model for QR violations')
    
    return parser
########################################################################

def generate_output_file(logger, outputextension, header, outputdata, filepath):
    if outputdata != None:
        '''if outputextension == 'csv':
                # Not working, using below basic preocessing instead 
                #with open(filepath, mode='w', newline='') as csv_file:
                #csv_writer = csv.writer(csv_file, delimiter=';')
                # write in csv file
                #csv_writer.writerows(outputdata)
            file = open(filepath, 'w')
            for line in outputdata:
                #linesplited = line.split(';')
                #msg = 'writing line ' + line#linesplited[0] 
                #logger.debug(msg)
                file.write(line + '\n')
        elif outputextension == 'xlsx':
            #df_outputdata = pd.read_csv(StringIO(remove_unicode_characters(str_readme_content)), sep=";",engine='python',quoting=csv.QUOTE_NONE)
            None
        '''
        if outputextension == 'csv':
            file = open(filepath, 'w')
            file.write(outputdata)            
        elif outputextension == 'xlsx':
            df_data = '' 
            try: 
                df_data = pd.read_csv(StringIO(outputdata), sep=";",engine='python',quoting=csv.QUOTE_NONE)
            except: 
                tb = traceback.format_exc()
                LogUtils.logerror(logger,'csv.Error: unexpected end of data ' + tb,True)
                # we generate an empty file with only the header line
                df_data = pd.read_csv(StringIO(header), sep=";",engine='python',quoting=csv.QUOTE_NONE)
            file = open(filepath, 'w')
            with pd.ExcelWriter(filepath,engine='xlsxwriter') as writer:
                df_data.to_excel(writer, sheet_name='Violations', index=False)
                workbook = writer.book
                worksheet = writer.sheets['Violations']
                header_format = workbook.add_format({'bold': True,'text_wrap': True,'valign': 'middle','fg_color': '#D7E4BC','border': 1}) 
                worksheet.set_zoom(70)
                #TODO: ajust size autofilter
                worksheet.autofilter('BH1:BH10000')
                # Write the column headers with the defined format.
                for col_num, value in enumerate(df_data.columns.values):
                    worksheet.write(0, col_num, value, header_format)        
        
        LogUtils.loginfo(logger,'File ' + filepath + ' generated',True)
        
########################################################################

def get_filepath(outputfolder, appName, outputextension, ):
    fpath = ''
    if outputfolder != None:
        fpath = outputfolder + '/'
    fpath += appName + "_violations." + outputextension
    return fpath 

########################################################################

def add_violations_for_automated_ap(qrid, set_qr_already_processed, dic_violations_by_qualityrule, i_violations_processed, automatedactionplan_maxnumber, list_violations_to_add_to_ap):
    if qrid in set_qr_already_processed:
        LogUtils.loginfo(logger, "  Quality ryle already %s, skipping it " % str(qrid), False)
        return

    if dic_violations_by_qualityrule.get(qrid) != None:
        for componentid in dic_violations_by_qualityrule[qrid]:
            if i_violations_processed < automatedactionplan_maxnumber:
                i_violations_processed += 1
                cur_violation = dic_violations_by_qualityrule[qrid][componentid]
                if not cur_violation.violation.hasActionPlan:  
                    list_violations_to_add_to_ap.append(cur_violation)
                    LogUtils.loginfo(logger, "    +" + str(i_violations_processed) + " Adding violation to automated ap %s|%s (%s|%s pri=%s existing ap=%s) " % (str(qrid),str(componentid), str(cur_violation.violation.qrname), str(cur_violation.violation.componentNameLocation), str(cur_violation.pri_selected_bc), str(cur_violation.violation.hasActionPlan)), True)
                else:
                    LogUtils.loginfo(logger, "    +" + str(i_violations_processed) + " Not adding violation to automated ap, already in action plan ap %s|%s (%s|%s pri=%s existing ap=%s) " % (str(qrid),str(componentid), str(cur_violation.violation.qrname), str(cur_violation.violation.componentNameLocation), str(cur_violation.pri_selected_bc), str(cur_violation.violation.hasActionPlan)), True) 
    
    
    return i_violations_processed, list_violations_to_add_to_ap
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
    
    automatedactionplan_create = False
    if args.automatedactionplan_create  != None and (args.automatedactionplan_create == 'True' or args.automatedactionplan_create == 'true'):
        automatedactionplan_create = True        
    
    automatedactionplan_maxnumber = 10
    if args.automatedactionplan_maxnumber  != None and args.automatedactionplan_maxnumber.isnumeric():
        automatedactionplan_maxnumber = int(args.automatedactionplan_maxnumber)
    
    comment = 'Default comment'
    if args.comment == None:
        if createexclusions: comment = 'Automated exclusion'
        elif createactionplans or automatedactionplan_create: comment = 'Automated action plan'
    elif args.comment  != None:
        comment = args.comment
    detaillevel = 'Intermediate'
    if args.detaillevel != None and (args.detaillevel == 'Simple' or args.detaillevel == 'Intermediate' or args.detaillevel == 'Full'):
        detaillevel = args.detaillevel
    
    generate_ac_model = False
    if args.generate_ac_model  != None and (args.generate_ac_model == 'True' or args.generate_ac_model == 'true'):
        generate_ac_model = True
    
    outputextension = 'csv'
    if args.outputextension != None:
        outputextension = args.outputextension 
    nbrows = 1000000000
    if args.nbrows != None and type(nbrows) == int: 
        nbrows=args.nbrows
    extensioninstallationfolder = "."
    if args.extensioninstallationfolder != None:
        extensioninstallationfolder = args.extensioninstallationfolder
    # add trailing / if not exist 
    if extensioninstallationfolder[-1:] != '/' and extensioninstallationfolder[-1:] != '\\' :
        extensioninstallationfolder += '/'
            
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
    bload_distributions = bload_all_data

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
        # Version
        script_version = 'Unknown'
        try:
            pluginfile = extensioninstallationfolder + 'plugin.nuspec'
            LogUtils.loginfo(logger,pluginfile,True)
            tree = ET.parse(pluginfile)
            root = tree.getroot()
            namespace = "{http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd}"
            for versiontag in root.findall('{0}metadata/{0}version'.format(namespace)):
                script_version = versiontag.text
        except:
            None        
        
        currentviolurl = ''
        qrrulepatternhref = ''
        componentHref = ''
        currentviolpartialurl = ''
        currentviolfullurl = ''
        protocol = 'Undefined'
        host = 'Undefined'
        warname = 'Undefined'
        rootedurl = 'Undefined'
        
        # split the URL to extract the warname, host, protocol ... 
        rexURL = "(([hH][tT][tT][pP][sS]*)[:][/][/]([A-Za-z0-9_:\.-]+)([/]([A-Za-z0-9_\.-]+))*[/]*)"
        m0 = re.search(rexURL, restapiurl)
        if m0:
            protocol = m0.group(2)
            host = m0.group(3)
            warname = m0.group(5)
  
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
        LogUtils.loginfo(logger,'script_version='+script_version,True)
        logger.info('python version='+sys.version)
        logger.info('****************** params ******************')
        logger.info('restapiurl='+restapiurl)
        logger.info('edurl='+edurl)
        logger.info('rootedurl='+rootedurl)
        logger.info('host='+host)
        logger.info('protocol='+protocol)
        logger.info('warname='+str(warname))
        logger.info('user='+str(user))
        if password == None or password == "N/A":
            logger.info('password=' + password)
        else: 
            logger.info('password=*******')
        if apikey == None or apikey== "N/A":
            logger.info('apikey='+str(apikey))
        else:
            logger.info('pwd=*******') 
        LogUtils.loginfo(logger,'log file='+log,True)
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
        logger.info('outputextension='+str(outputextension))
        logger.info('displaysource='+str(displaysource))
        logger.info('output folder='+str(outputfolder))
        
        logger.info('automatedactionplan_create='+str(automatedactionplan_create))
        logger.info('automatedactionplan_maxnumber='+str(automatedactionplan_maxnumber))
        
        
        logger.info('bload_all_data='+str(bload_all_data))
        logger.info('bload_objectviolation_metrics='+str(bload_objectviolation_metrics))
        logger.info('bload_rule_pattern='+str(bload_rule_pattern))
        logger.info('bload_objectviolation_findings='+str(bload_objectviolation_findings))
        logger.info('bload_qr_results='+str(bload_qr_results))
        logger.info('bload_bc_tch_mapping='+str( bload_bc_tch_mapping))
        logger.info('bload_components_pri='+str(bload_components_pri))
        logger.info('bload_serverdetail='+str(bload_serverdetail))
        logger.info('bload_quality_model='+str(bload_quality_model))
        
        # create output folders, when required
        if outputfolder != None and not os.path.exists(outputfolder):
            os.makedirs(outputfolder)
        logfolder = os.path.basename(log)
        logger.info('log folder='+str(logfolder))
        if logfolder != None and logfolder != outputfolder and not os.path.isfile(logfolder) and not os.path.exists(logfolder):
            try:
                os.makedirs(logfolder)
            except PermissionError:
                None
        
        logger.info('********************************************') 
        rest_utils = RestUtils(logger, restapiurl, RestUtils.CLIENT_REQUESTS, user, password, apikey)
        rest_utils.open_session()
        rest_service_aip = AIPRestAPI(rest_utils) 
    
        LogUtils.loginfo(logger,'Initialization',True)
        # few checks on the server
        server = rest_service_aip.get_server()
        if server != None: logger.info('server version=%s, memory (free)=%s' % (str(server.version), str(server.freememory)))
        
        # retrieve the domains & the applications in those domains 
        json_domains = rest_service_aip.get_domains_json()
        if json_domains != None:
            idomain = 0
            for item in json_domains:
                idomain += 1
                domain = ''
                try:
                    domain = item['href']
                except KeyError:
                    pass
                
                LogUtils.loginfo(logger,"Domain " + domain + " | progress:" + str(idomain) + "/" + str(len(json_domains)),True)
                # only engineering domains
                if domain != 'AAD':  #and domain == 'AED_AYYILDIZ':
                    json_apps = rest_service_aip.get_applications_json(domain)
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
                            LogUtils.loginfo(logger,"Processing application " + appName,True)
                            csvdatas = [] 
                            if outputextension != None and outputextension:
                                # testing if output file can be written
                                fpath = get_filepath(outputfolder, appName, outputextension)
                                filelocked = False
                                icount = 0
                                while icount < 10 and FileUtils.is_file_locked(fpath):
                                    icount += 1
                                    filelocked = True
                                    LogUtils.logwarning(logger,'File %s is locked. Please unlock it ! Waiting 5 seconds before retrying (try %s/10) ' % (fpath, str(icount)),True)
                                    time.sleep(5)
                                if FileUtils.is_file_locked(fpath):
                                    LogUtils.logerror(logger,'File %s is locked, aborting for application %s' % (fpath,appName),True)
                                    continue
                            # snapshot list
                            json_snapshots = rest_service_aip.get_application_snapshots_json(domain, applicationid)
                            if json_snapshots != None:
                                for snap in json_snapshots:
                                    csvdata = []
                                    
                                    outputdata = ''
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

                                    
                                    ###################################################################
                                    # Number of violations / snapshots
                                    LogUtils.loginfo(logger,'Initialization (step 1/6) - Number of violations',True)
                                    json_tot_violations = rest_service_aip.get_total_number_violations_json(domain, applicationid, snapshotid)
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
                                                                        
                                    ###################################################################
                                    # retrieve the mapping quality url id => technical criterion id
                                    tqiqm = {}
                                    json_snapshot_quality_model = None
                                    LogUtils.loginfo(logger,'Initialization (step 2/6) - Quality model',True)
                                    if not bload_quality_model:
                                        logger.info("NOT Extracting the snapshot quality model")                                           
                                    else:
                                        json_snapshot_quality_model = rest_service_aip.get_snapshot_tqi_quality_model_json(domain, snapshotid)
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
                                    
                                    ###################################################################    
                                    LogUtils.loginfo(logger,'Initialization (step 3/6) - Technical criteria contributions',True)
                                    mapbctc = None                                     
                                    if not bload_bc_tch_mapping:
                                        logger.info("NOT Extracting the snapshot business criteria => technical criteria mapping")                                          
                                    else:    
                                        mapbctc = rest_service_aip.initialize_bc_tch_mapping(domain, applicationid, snapshotid, bcids)
                                    
                                    ###################################################################
                                    # Components PRI
                                    LogUtils.loginfo(logger,'Initialization (step 4/6) - Components PRI',True)
                                    comppri = None
                                    transactionlist = {}
                                    
                                    if not bload_components_pri:
                                        logger.info("NOT extracting the components PRI for the business criteria")
                                    else: 
                                        if 1 == 1:
                                            try : 
                                                comppri = rest_service_aip.initialize_components_pri(domain, applicationid, snapshotid, bcids,nbrows)
                                            except ValueError:
                                                None
                                        if detaillevel == 'Intermediate' or detaillevel == 'Full':
                                            transactionlist = rest_service_aip.init_transactions(domain, applicationid, snapshotid, criticalrulesonlyfilter, violationstatusfilter, technofilter,nbrows)
                                    
                                    ###################################################################
                                    LogUtils.loginfo(logger,'Initialization (step 5/6) - Distributions',True)
                                    dictdistributions = {}
                                    if not bload_distributions:
                                        logger.info("NOT extracting the distributions")
                                    else: 
                                        if detaillevel == 'Intermediate' or detaillevel == 'Full':
                                            try : 
                                                dictdistributions = rest_service_aip.get_distributions_details(domain, applicationid, snapshotid, nbrows)
                                            except:
                                                LogUtils.logwarning(logger, 'Error extracting the distributions', True)
                                    ###################################################################
                                    # table containing the scheduled exclusions to create
                                    json_new_scheduledexclusions = []
                                    # table containing the scheduled exclusions to create
                                    json_new_actionplans = []
                                    iCounterFilteredViolations = 0
                                    iCouterRestAPIViolations = 0

                                    LogUtils.loginfo(logger, 'Initialization (step 6/6) - Quality metrics results',True)
                                    # quality rules details (nb violations, % compliance)
                                    json_qr_results = None
                                    
                                    if generate_ac_model:
                                        acmodel = ArchitectureModel(appName + ' quality-rules',appName + ' quality-rules.CASTArchitect', ArchitectureModel.TYPE_FORBIDDEN, 'JEE,SQL,HTML5,Cobol')
                                        ac_model_content = {}
                                    
                                    if not bload_qr_results:
                                        logger.info("NOT Extracting the quality metrics results")                                          
                                    else:    
                                        
                                        #def get_qualitymetrics_results_json(self, domainname, applicationid, snapshotfilter, snapshotids, criticalonly,  modules=None, nbrows=10000000):
                                        json_qr_results = rest_service_aip.get_qualitymetrics_results_json(domain, applicationid, '-1', None, criticalrulesonlyfilter, None, nbrows)
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
                                                    
                                            # only the last snapshot
                                            break

                                    LogUtils.loginfo(logger, 'Extracting violations',True)
                                    LogUtils.loginfo(logger, 'Loading violations & components data from the REST API',True)
                                    list_outputviolations = []
                                    dic_violations_by_qualityrule = {}

                                    violationfilter = ViolationFilter(criticalrulesonlyfilter, businesscriterionfilter, technofilter, None, qridfilter, qrnamefilter, nbrows)
                                    json_violations = rest_service_aip.get_snapshot_violations_json(domain, applicationid, snapshotid, violationfilter)
                                    header = ''
                                    if json_violations != None:
                                        outputline = 'Application name;Date;Version;Count (Filter)'
                                        #outputline += ';Count (Rest API);Total # violations (Rest API)'
                                        outputline += ';Total # critical violations;Total # violations'
                                        outputline += ';QR Id;QR Name;QR Critical;Max Weight;Compounded Weight;Compounded Weight Formula;QR failed checks;QR Compliance ratio;QR Added violations;QR Removed violations'
                                        outputline += ';Component type;Component name location;Violation status;Component status;Associated value label;Associated value'
                                        outputline += ';Technical criteria;Business Criteria;Quality standards;PRI for selected Business criterion;PRI Security;PRI Efficiency;PRI Robustness;PRI Transferability;PRI Changeability'
                                        outputline += ';Number of transactions;Transaction list;'
                                        outputline += 'Efficiency - Number of transactions;Efficiency - Max TRI;Efficiency - Transactions TRI'
                                        outputline += ';Robustness - Number of transactions;Robustness - Max TRI;Robustness - Transactions TRI'
                                        outputline += ';Security - Number of transactions;Security - Max TRI;Security - Transactions TRI'
                                        
                                        outputline += ';Cyclomatic complexity dist.;Cost complexity dist.;Fan-Out dist.;Fan-In dist.;Size dist.;Coupling dist.;SQL complexity dist' 
                                        outputline += ';Critical violations;Cyclomatic complexity;LOC;CommentLines;Ratio CommentLines/CodeLines'
                                        outputline += ';Action plan status;Action plan tag;Action plan comment'
                                        outputline += ';Exclusion request;Exclusion request comment'
                                        outputline += ';Parameters;URL;Quality rule URI;Component URI;Violation findings URI;Violation id;Bookmarks;Source code sniplet'
                                        header = outputline 
                                        #print(outputline)
                                        #logger.debug(outputline)
                                        if outputextension in ('csv', 'xlsx'):
                                            #for it in outputline.split(";"):
                                            #    csvdata.append(it)
                                            csvdatas.append(outputline)
                                            outputdata += outputline + '\n'

                                        # object cache to avoid redoing the same Rest API Calls
                                        dicObjectViolationMetrics = {}
                                        dictQualityPatternDetails = {}

                                        lastProgressReported = None
                                        
                                        
                                        for violation in json_violations:
                                            iCouterRestAPIViolations += 1
                                            currentviolurl = ''
                                            violations_size = len(json_violations)
                                            imetricprogress = int(100 * (iCouterRestAPIViolations / violations_size))
                                            if iCouterRestAPIViolations==1 or iCouterRestAPIViolations==violations_size or iCouterRestAPIViolations%500 == 0:
                                                LogUtils.loginfo(logger, "processing violation " + str(iCouterRestAPIViolations) + "/" + str(violations_size)  + ' (' + str(imetricprogress) + '%)',True)
                                            objviol = Violation()
                                            objviol_output = ViolationOutput() 
                                            objviol_output.violation = objviol
                                            objviol_output.inputcomment = comment
                                            objviol_output.actionplaninputtag = actionplaninputtag 
                                            
                                            try:                                    
                                                qrrulepatternhref = violation['rulePattern']['href']
                                                objviol_output.qrrulepatternhref = qrrulepatternhref
                                            except KeyError:
                                                qrrulepatternhref = None
                                                                                            
                                            objviol.qrid = ''
                                            qrrulepatternsplit = qrrulepatternhref.split('/')
                                            for elem in qrrulepatternsplit:
                                                # the last element is the id
                                                objviol.qrid = elem                                            
                                            
                                            try:
                                                objviol.qrname = violation['rulePattern']['name']
                                            except KeyError:
                                                None    
                                                
                                            # filter on quality rule id or name, if the filter match
                                            if qridfilter != None and not re.match(qridfilter, str(objviol.qrid)):
                                                continue
                                            if qrnamefilter != None and not re.match(qrnamefilter, objviol.qrname):
                                                continue                                                
                                                
                                            objviol.qrcritical = '<Not extracted>'
                                            qrdetails = tqiqm[objviol.qrid]
                                            try:
                                                if tqiqm != None and qrdetails != None and qrdetails.get("critical") != None:
                                                    objviol.qrcritical = str(qrdetails.get("critical"))
                                            except KeyError:
                                                None
                                           
                                            
                                            try:                                    
                                                objviol.actionPlan = violation['remedialAction']
                                                if objviol.actionPlan != None:
                                                    objviol.hasActionPlan = True
                                            except KeyError:
                                                objviol.hasActionPlan = None
                                            # filter the violations already in the action plan 
                                            if actionplanfilter != None and actionplanfilter == 'WithActionPlan' and objviol.hasActionPlan == None:
                                                continue
                                            # filter the violations not in the action plan 
                                            if actionplanfilter != None and actionplanfilter == 'WithoutActionPlan' and objviol.hasActionPlan != None:
                                                continue
                                                
                                            try:                                    
                                                objviol.exclusionRequest = violation['exclusionRequest']
                                            except KeyError:
                                                objviol.exclusionRequest = None
                                            # filter the violations already in the exclusion list 
                                            if exclusionrequestfilter != None and exclusionrequestfilter == 'Excluded' and objviol.exclusionRequest != None:
                                                continue
                                            # filter the violations not in the exclusion list 
                                            if exclusionrequestfilter != None and exclusionrequestfilter == 'NotExcluded' and objviol.exclusionRequest == None:
                                                continue
                                                
                                            try:                                    
                                                violationsStatus = violation['diagnosis']['status']
                                            except KeyError:
                                                violationsStatus = None
                                            try:
                                                componentHref = violation['component']['href']
                                                objviol_output.componentHref = componentHref
                                            except KeyError:
                                                componentHref = None

                                            objviol.componentid = ''
                                            rexcompid = "/components/([0-9]+)/snapshots/"
                                            m0 = re.search(rexcompid, componentHref)
                                            if m0: 
                                                objviol.componentid = m0.group(1)

                                            # filter the components that are not in the list if a list of component href is provided
                                            if componentsfilter != None and componentHref not in componentsfilter:
                                                # example DOMAIN08/components/165586,DOMAIN08/components/166686
                                                continue

                                            # filter the violations that are not in the list if a list of violations id is provided
                                            objviol.violationid = qrrulepatternhref+'#'+componentHref 
                                            if violationsfilter != None and objviol.violationid not in violationsfilter: 
                                                # example : DOMAIN08/rule-patterns/7778#DOMAIN08/components/137407/snapshots/21,DOMAIN08/rule-patterns/7776#DOMAIN08/components/13766/snapshots/21                                          
                                                continue
                                                
                                            try:
                                                objviol.componentShortName = violation['component']['shortName']
                                            except KeyError:
                                                objviol.componentShortName = None                                        
                                            try:
                                                objviol.componentNameLocation = violation['component']['name']
                                            except KeyError:
                                                objviol.componentNameLocation = None                                        
                                            # filter on component name location
                                            if componentnamelocationfilter != None and not re.match(componentnamelocationfilter, objviol.componentNameLocation):
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
                                            for key in qrdetails.get("tc").keys():
                                                firsttechnicalcriterionid = key
                                                technicalcriteriaidandnames += firsttechnicalcriterionid+'#'+qrdetails.get("tc").get(key) + ','
                                            technicalcriteriaidandnames = technicalcriteriaidandnames[:-1]
                                            
                                            ######################################################################################################################################                                           
                                            # get more details from the component URI
                                            objViolationMetric = None
                                            if not bload_objectviolation_metrics:
                                                logger.debug("NOT Extracting the component metrics") 
                                            else:
                                                if detaillevel == 'Full':
                                                    #Looking in the cache first
                                                    objViolationMetric = dicObjectViolationMetrics.get(componentHref)
                                                    #If cache is empty we load from the rest api 
                                                    if objViolationMetric == None:
                                                        objViolationMetric = rest_service_aip.get_objectviolation_metrics(componentHref)
                                                        if objViolationMetric != None:
                                                            dicObjectViolationMetrics.update({componentHref:objViolationMetric})
                                                    else:
                                                        None
                                            #####################################################################################################
                                            objRulePatternDetails = None
                                            json_rulepattern = None
                                            if not bload_rule_pattern:
                                                logger.debug("NOT Extracting the rule pattern details")                                                
                                            else:
                                                if detaillevel == 'Full':
                                                    #Looking in the cache first
                                                    objRulePatternDetails = dictQualityPatternDetails.get(qrrulepatternhref)                                                    
                                                    #If cache is empty we load from the rest api
                                                    if objRulePatternDetails == None:
                                                        objRulePatternDetails = rest_service_aip.get_rule_pattern(qrrulepatternhref)
                                                        if objRulePatternDetails != None:
                                                            dictQualityPatternDetails.update({qrrulepatternhref:objRulePatternDetails})
                                                    else:
                                                        None                                                            
                                            associatedValueName = ''
                                            if objRulePatternDetails != None and objRulePatternDetails.associatedValueName != None:
                                                associatedValueName = objRulePatternDetails.associatedValueName
                                            strqualitystandards = '<Not extracted>'
                                            
                                            if objRulePatternDetails != None: 
                                                qs = objRulePatternDetails.get_quality_standards()
                                                if qs != None:
                                                    strqualitystandards = qs

                                            #####################################################################################################
                                            associatedvaluelabel = '<Not extracted>'
                                            associatedvalue = '<Not extracted>'
                                            strbookmarks = '<Not extracted>'
                                            strparams = '<Not extracted>'
                                            json_findings = None
                                            srcCode = []
                                            srcCodeReference = []

                                            if not bload_objectviolation_findings:
                                                logger.info("NOT Extracting the component findings")
                                            elif detaillevel == 'Full':
                                            # we skip if the associated value contains a path that is not managed and can be very time consuming
                                            # for rules like Avoid indirect String concatenation inside loops (more than 1 mn per api call)
                                                if not 'path' in associatedValueName.lower():
                                                    json_findings = rest_service_aip.get_objectviolation_findings_json(componentHref, objviol.qrid)
                                                
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
                                                        prevfile = ''
                                                        for bkm in fin_bookmarks:
                                                            for bkm2 in bkm:
                                                                try:
                                                                    icountbkm += 1
                                                                    # we add a " at the beginning to manage the multiline for code source in excel int the same cell
                                                                    if strbookmarks == '': strbookmarks ='"'
                                                                    curfile = bkm2['codeFragment']['file']['name']
                                                                    startLine = bkm2['codeFragment']['startLine']
                                                                    endLine = bkm2['codeFragment']['endLine']
                                                                    if curfile != prevfile:
                                                                        strbookmarks += curfile + '\n'
                                                                    strbookmarks += '#' + str(icountbkm) + ' line ' + str(startLine)+' => ' + str(endLine) + '\n'
                                                                    prevfile = curfile
                                                                except KeyError:
                                                                    None
                                                        if strbookmarks == '' or strbookmarks == '"':
                                                            strbookmarks = ''
                                                        # we add a " at the end to manage the multiline for code source in excel int the same cell
                                                        else: strbookmarks = strbookmarks + '"'
                                                        
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
                                            #if objviol.qrid == "7294":
                                            #    continue
                                            #AED5/local-sites/162402639/file-contents/140 lines 167=>213
                                            if displaysource: 
                                                if sourceCodesHref != None:
                                                    json_sourcescode = rest_service_aip.get_sourcecode_json(sourceCodesHref)
                                                    if json_sourcescode != None:
                                                        for src in json_sourcescode:
                                                            filereference = ''
                                                            filename = src['file']['name']
                                                            filehref = src['file']['href']
                                                            filesize = src['file']['size']
                                                            srcstartline = None
                                                            srcendline = None
                                                            try:
                                                                srcstartline = src['startLine']
                                                            except:
                                                                None
                                                            try:
                                                                srcendline = src['endLine']
                                                            except:
                                                                None                                                                
                                                            filereference = filename
                                                            strstartendlineparams = ''
                                                            if srcstartline >= 0 and srcendline >= 0:
                                                                filereference += ': lines ' + str(srcstartline) + ' => ' +str(srcendline)
                                                            srcCodeReference.append(filereference)
                                                            partialfiletxt = rest_service_aip.get_sourcecode_file_json(filehref, srcstartline, srcendline)
                                                            if partialfiletxt == None:
                                                                logger.info("Second try without the line numbers")
                                                                partialfiletxt = rest_service_aip.get_sourcecode_file_json(filehref, None, None)
                                                                if partialfiletxt != None:
                                                                    logger.info("Second try worked")
                                                            if partialfiletxt == None:
                                                                logger.warning("Couldn't extract the file " + filehref)
                                                            if partialfiletxt != None:
                                                                filewithlinesnumber = ''
                                                                srcToBeAddedToCsv = ''
                                                                # do not export the code for QR 7294 Avoid cyclical calls and inheritances between namespaces content
                                                                if objviol.qrid != "7294":
                                                                    txtSrcCode = ''
                                                                    if srcstartline >= 0 :
                                                                        filelines = partialfiletxt.split("\n")
                                                                        iline = srcstartline
                                                                        for line in filelines:
                                                                            # add line number and remove ; characters from the code
                                                                            filewithlinesnumber += str(iline) + ' ' +  line.replace(";", "<#>") + '\n'
                                                                            iline += 1
                                                                        txtSrcCode = filereference + '\n' + filewithlinesnumber
                                                                    else: 
                                                                        txtSrcCode = filereference + '\n' + partialfiletxt
                                                                    srcToBeAddedToCsv = txtSrcCode 
                                                                    
                                                                elif objviol.qrid == "7294":
                                                                    # do not export the code for QR 7294 Avoid cyclical calls and inheritances between namespaces content
                                                                    # only the file name is enough, cause it's not providing much value 
                                                                    srcToBeAddedToCsv = filereference
                                                                srcCode.append(srcToBeAddedToCsv)
                                                                #print(srcToBeAddedToCsv)
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
                                            objviol_output.appName = appName
                                            objviol_output.snapshotdate = snapshotdate 
                                            objviol_output.snapshotversion = snapshotversion
                                            objviol_output.iCounterFilteredViolations = iCounterFilteredViolations
                                            objviol_output.totalviol = str(intotalviol)[:-2]
                                            objviol_output.totalcritviol = str(intotalcritviol)[:-2]
                                            
                                            objViolationMetric = dicObjectViolationMetrics.get(componentHref)
                                            objviol_output.violation_metrics = objViolationMetric
                                            if objViolationMetric == None:
                                                objViolationMetric = ObjectViolationMetric() 
                                            objviol_output.violation_metrics = objViolationMetric
                                            objviol_output.maxWeight = qrdetails.get('maxWeight')
                                            objviol_output.compoundedWeight = qrdetails.get('compoundedWeight')
                                            objviol_output.compoundedWeightFormula = qrdetails.get('compoundedWeightFormula')
                                            
                                            objviol_output.failedchecks = qrdetails.get('failedchecks')
                                            objviol_output.ratio = qrdetails.get('ratio')    
                                            objviol_output.addedViolations = qrdetails.get('addedViolations')
                                            objviol_output.removedViolations = qrdetails.get('removedViolations')  
                                            objviol_output.violationsStatus = violationsStatus
                                            objviol_output.componentStatus = componentStatus
                                            objviol_output.associatedvaluelabel = associatedvaluelabel
                                            objviol_output.associatedvalue = associatedvalue
                                            objviol_output.technicalcriteriaidandnames = technicalcriteriaidandnames
                                                         
                                            outputline = objviol_output.appName + ";" + str(objviol_output.snapshotdate) + ";" + str(objviol_output.snapshotversion) +  ";" + str(objviol_output.iCounterFilteredViolations) 
                                            #outputline +=  ";" + str(iCouterRestAPIViolations)  +  ";" + str(violations_size) + 
                                            outputline +=  ";" + str(objviol_output.totalcritviol) + ";" + str(objviol_output.totalviol) 
                                            outputline += ";" + str(objviol_output.violation.qrid)+ ";" + str(objviol_output.violation.qrname) + ";" +  str(objviol_output.violation.qrcritical) + ";" + str(objviol_output.maxWeight) + ";" + str(objviol_output.compoundedWeight) + ";" + objviol_output.compoundedWeightFormula 
                                            outputline += ";" + str(objviol_output.failedchecks) + ";" + str(objviol_output.ratio) + ";" + str(objviol_output.addedViolations) + ";" + str(objviol_output.removedViolations)

                                            outputline += ";" + str(objviol_output.violation_metrics.componentType) + ";" + str(objviol_output.violation.componentNameLocation) + ";"+ str(objviol_output.violationsStatus) + ";" + str(objviol_output.componentStatus) + ";" + str(objviol_output.associatedvaluelabel)+ ";" +  str(objviol_output.associatedvalue)
                                            outputline += ";" + str(objviol_output.technicalcriteriaidandnames)
                                            
                                            ##############################
                                            # update the architecture model     
                                            if generate_ac_model and detaillevel == 'Full' and objviol_output.violation_metrics.componentType != None and objviol.componentNameLocation != None:
                                                set_name = "set-" + objviol.qrname.replace("\"","")
                                                str_type = metamodel.get_metamodel_type(logger, objviol_output.violation_metrics.componentType)
                                                if ac_model_content.get(set_name) == None:
                                                    ac_model_content[set_name] = {"set":set_name, "types":{}}
                                                if ac_model_content[set_name].get("types").get(str_type) == None:
                                                    ac_model_content[set_name]["types"][str_type] = []
                                                ac_model_content[set_name]["types"][str_type].append(objviol.componentNameLocation)
                                            #
                                            strlistbc = ''
                                            #mapbctc
                                            if mapbctc != None and tqiqm != None:
                                                for bcid in bcids:
                                                    listtc = mapbctc.get(bcid)
                                                    for tc in listtc:
                                                        qrlisttc = qrdetails.get('tc').keys()
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
                                            objviol_output.strlistbc = strlistbc
                                            outputline += ";" + objviol_output.strlistbc
                                            objviol_output.strqualitystandards = strqualitystandards
                                            outputline += ";" + str(objviol_output.strqualitystandards)
                                                                                                                                                                                                                                        
                                            #########################################################################
                                            # current PRI focus
                                            outputline += ";"
                                            
                                            if propagationRiskIndex != None: 
                                                objviol_output.pri_selected_bc = str(propagationRiskIndex)
                                            else: 
                                                objviol_output.pri_selected_bc = 'No BC selected'
                                            outputline += objviol_output.pri_selected_bc
                                            # PRI Security
                                            outputline += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60016").get(objviol.componentid))
                                            except KeyError:
                                                None
                                            objviol_output.pri_security = StringUtils.NonetoEmptyString(pri)
                                            outputline += objviol_output.pri_security
                                            # PRI Efficiency
                                            outputline += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60014").get(objviol.componentid))
                                            except KeyError:
                                                None
                                            objviol_output.pri_efficiency = StringUtils.NonetoEmptyString(pri)
                                            outputline += objviol_output.pri_efficiency
                                            # PRI Robusustness
                                            outputline += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60013").get(objviol.componentid))
                                            except KeyError:
                                                None
                                            objviol_output.pri_robustness = StringUtils.NonetoEmptyString(pri)
                                            outputline += objviol_output.pri_robustness          
                                            # PRI Transferability
                                            outputline += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60011").get(objviol.componentid))
                                            except KeyError:
                                                None
                                            objviol_output.pri_transferability = StringUtils.NonetoEmptyString(pri)
                                            outputline += objviol_output.pri_transferability     
                                            # PRI Changeability
                                            outputline += ";"
                                            pri = '<Not extracted>'
                                            try:
                                                if comppri != None:
                                                    pri = str(comppri.get("60012").get(objviol.componentid))
                                            except KeyError:
                                                None
                                            objviol_output.pri_changeability = StringUtils.NonetoEmptyString(pri)
                                            outputline += objviol_output.pri_changeability 
                                            
                                            #########################################################################  
                                            # TQI - Number of transactions & transactions list
                                            outputline += ";" 
                                            objviol_output.transactions_number = 0
                                            objviol_output.transactions_list = '<Not extracted>'
                                            try:
                                                bctrans = transactionlist.get("60017") 
                                                if bctrans != None:
                                                    objviol_output.transactions_list = ''
                                                    for trans in bctrans:
                                                        tobeadded = False
                                                        for comp in trans.get("componentsWithViolations"):
                                                            if comp == componentHref:
                                                                #The component has violation on this transaction
                                                                tobeadded = True
                                                                break
                                                        if tobeadded:
                                                            objviol_output.transactions_list += trans.get("name") + ','
                                                            objviol_output.transactions_number+=1
                                                        #trans.get("transactionRiskIndex")
                                                    if objviol_output.transactions_list != '': objviol_output.transactions_list = objviol_output.transactions_list[:-1]
                                            except KeyError:
                                                None
                                            if objviol_output.transactions_list != "<Not extracted>": 
                                                outputline += str(objviol_output.transactions_number)
                                            outputline += ";"
                                            outputline += objviol_output.transactions_list

                                            # Effiency - Number of transactions & transactions list & TRI
                                            outputline += ";" 
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
                                            objviol_output.transactions_efficiency_number = numtrans
                                            objviol_output.transactions_efficiency_tri = strtrans
                                            objviol_output.transactions_efficiency_maxtri = maxtri
                                            if strtrans != "<Not extracted>": 
                                                outputline += str(numtrans)
                                            outputline += ";" + str(maxtri)                                            
                                            outputline += ";" +  strtrans 
                                          
                                            # Robustness - Number of transactions & transactions list & TRI
                                            outputline += ";" 
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
                                            objviol_output.transactions_robustness_number = numtrans
                                            objviol_output.transactions_robustness_tri = strtrans
                                            objviol_output.transactions_robustness_maxtri = maxtri                                                
                                            if strtrans != "<Not extracted>": 
                                                outputline += str(numtrans)
                                            outputline += ";" + str(maxtri)                                            
                                            outputline += ";" +  strtrans                                             
                                          
                                            
                                            # Security - Number of transactions & transactions list & TRI
                                            outputline += ";" 
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
                                            objviol_output.transactions_security_number = numtrans
                                            objviol_output.transactions_security_tri = strtrans
                                            objviol_output.transactions_security_maxtri = maxtri                                             
                                            if strtrans != "<Not extracted>": 
                                                outputline += str(numtrans)
                                            outputline += ";" + str(maxtri)                                            
                                            outputline += ";" +  strtrans                                           
                                            #########################################################################      
                                            # Distributions
                                            # Cyclomatic complexity dist. 
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("65501").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_cyclomaticcomplexity = strdist
                                            outputline += ';' + strdist

                                            # Cost complexity dist. 
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("67001").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_costcomplexity = strdist
                                            outputline += ';' + strdist
                                            
                                            # Fan-Out dist.
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("66020").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_fanout = strdist
                                            outputline += ';' + strdist
                                            
                                            # Fan-In dist
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("66021").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_fanin = strdist
                                            outputline += ';' + strdist
                                            
                                            # Size dist.
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("65105").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_size =  strdist                                              
                                            outputline += ';' + strdist
                                            
                                            # Coupling dist.
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("65350").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_coupling =  strdist
                                            outputline += ';' + strdist                                            
                                            
                                            # SQL complexity dist.
                                            strdist = '<Not extracted>'
                                            try:
                                                strdist = dictdistributions.get("65801").get(componentHref)
                                                if strdist == None: strdist = ''
                                            except:
                                                None
                                            objviol_output.distribution_sqlcomplexity =  strdist
                                            outputline += ';' + strdist                                             
                                            
                                            #########################################################################                                                                                                                              
                                            outputline += ";"
                                            if objviol_output.violation_metrics.criticalViolations != None: outputline += str(objviol_output.violation_metrics.criticalViolations)
                                            outputline += ";"
                                            if objviol_output.violation_metrics.cyclomaticComplexity != None: outputline += str(objviol_output.violation_metrics.cyclomaticComplexity)
                                            outputline += ";"
                                            if objviol_output.violation_metrics.codeLines != None: outputline += str(objviol_output.violation_metrics.codeLines)
                                            outputline += ";"
                                            if objviol_output.violation_metrics.commentLines != None: outputline += str(objviol_output.violation_metrics.commentLines)
                                            outputline += ";"
                                            if objviol_output.violation_metrics.ratioCommentLinesCodeLines != None: outputline += str(objviol_output.violation_metrics.ratioCommentLinesCodeLines)
    
                                            #########################################################################                                  
                                            
                                            if objviol.hasActionPlan:
                                                actionplanstatus = objviol_output.violation.actionPlan['status']
                                                actionplantag = objviol_output.violation.actionPlan['tag']
                                                actionplancomment = objviol_output.violation.actionPlan['comment']
                                                # status
                                                outputline += ";" + actionplanstatus 
                                                # tag
                                                outputline += ";" + actionplantag
                                                # comment
                                                outputline += ";" + actionplancomment
                                            else:
                                                outputline += ";;;" 
                                            if objviol.exclusionRequest != None:
                                                exclusionRequest = objviol_output.violation.exclusionRequest['comment']
                                                # Exclusion request exists
                                                outputline += ";true"
                                                # Exclusion request comment
                                                outputline += ";" + exclusionRequest
                                            else:
                                                outputline += ";;"                                            

                                            #########################################################################
                                            outputline += ";"+ strparams
                                            #########################################################################
                                            currentviolurl = ''
                                            currentviolpartialurl= snapHref + '/business/60017/qualityInvestigation/0/60017/' + firsttechnicalcriterionid + '/' + objviol_output.violation.qrid + '/' + objviol_output.violation.componentid
                                            currentviolfullurl= rootedurl + '/engineering/index.html#' + snapHref + '/business/60017/qualityInvestigation/0/60017/' + firsttechnicalcriterionid + '/' + objviol_output.violation.qrid + '/' + objviol_output.violation.componentid
                                            currentviolurl = currentviolfullurl
                                            outputline += ";" + currentviolurl
                                            outputline += ";"+ str(qrrulepatternhref) + ";" + str(componentHref) + ";" +str(findingsHref)         
                                            outputline += ";"+ objviol_output.violation.violationid
                                            outputline += ";"+ strbookmarks
                                            # remove unicode characters that are making the reporting fails
                                            outputline = StringUtils.remove_unicode_characters(outputline)
                                                                                        
                                            #########################################################################
                                            # Show the progress (without the source code)
                                            logger.debug(outputline)
                                            #########################################################################
                                            try:
                                                '''
                                                # log only the file reference instead of code
                                                if len(srcCodeReference) > 0:
                                                    for srcref in srcCodeReference:
                                                        outputline += ';"'+ srcref + '"'                                    
                                                '''
                                                if len(srcCode) > 0:
                                                    iNbCodeCol = 0
                                                    for src in srcCode:
                                                        iNbCodeCol += 1
                                                        # Stop at 100 columns
                                                        if iNbCodeCol > 100:
                                                            outputline += ';...'
                                                            break
                                                        if src=='<Not Extracted>':
                                                            outputline += ';' + src
                                                        else:
                                                            #outputline += ';"'+ str(src).replace('"', '""') + '"'
                                                            # we add only the first 5000 characters
                                                            outputline += ';"'
                                                            # if ends with " we need to double this character, else the return chariot will not work in Excel
                                                            strsrcTruncated = str(src).replace('"','""')[0:5000]
                                                            outputline += strsrcTruncated
                                                            # last character is a " and the previous character is not a "
                                                            if outputline[-1:] == '"' and outputline[-2:-1] != '"':
                                                                outputline += '"'
                                                            outputline += '"'
                                                else:
                                                    outputline += ';N/A'
                                                #print(remove_unicode_characters(outputline))
                                            except: # catch *all* exceptions
                                                outputline += ';Error'
                                                tb = traceback.format_exc()
                                                #e = sys.exc_info()[0]
                                                logging.error('  Error to get the source code %s' % tb)

                                            # remove unicode characters that are making the reporting fails
                                            outputline = StringUtils.remove_unicode_characters(outputline)                                            
                                            #########################################################################
                                            # append the data
                                            if outputextension in ('csv','xlsx'):
                                                #for it in outputline.split(";"):
                                                #    csvdata.append(it)
                                                csvdatas.append(outputline)
                                                outputdata += outputline + '\n'
                                        
                                            list_outputviolations.append(objviol_output)
                                            if dic_violations_by_qualityrule.get(objviol_output.violation.qrid) == None:
                                                dic_violations_by_qualityrule[objviol_output.violation.qrid] = {}
                                            if dic_violations_by_qualityrule[objviol_output.violation.qrid].get(objviol_output.violation.componentid) == None:
                                                dic_violations_by_qualityrule[objviol_output.violation.qrid][objviol_output.violation.componentid] = objviol_output
                                            
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
                                                
                                            if createactionplans and not objviol_output.violation.actionPlan:
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

                                    # generate model file
                                    if generate_ac_model and detaillevel == 'Full':
                                        logger.info("Creating file %s"  + acmodel.filename)
                                        for set_name in ac_model_content:
                                            s=Layer(set_name, Layer.TYPE_SET, False)
                                            i_index = 0
                                            for str_type in ac_model_content[set_name]["types"]:
                                                i_index += 1
                                                if i_index == 1:
                                                    crit=Criteria(Criteria.TYPE_SELECTION_CRITERIA, False, False)
                                                else:
                                                    crit=Criteria(Criteria.TYPE_OR, False, False)
                                                
                                                p_type=Property(Property.NAME_TYPE,Property.OP_EQUALS,[str_type])
                                                crit.add_property(p_type)
                                                p_name=Property(Property.NAME_FULLNAME,Property.OP_EQUALS,ac_model_content[set_name]["types"][str_type])
                                                crit.add_property(p_name)
    
                                                s.add_criteria(crit)
                                            acmodel.add_layer(s)
                                        acmodel.generate_model()
                                    #########################################################################

                                    #TODO: change to requests lib - exclusion 
                                    if createexclusions and json_new_scheduledexclusions != None and len(json_new_scheduledexclusions) > 0:
                                        logger.info("Creating "  + str(len(json_new_scheduledexclusions)) + " new exclusions : " + str(json_new_scheduledexclusions))
                                        rest_service_aip.create_scheduledexclusions(domain, applicationid,snapshotid, json_new_scheduledexclusions)
                                    else:
                                        logger.info("No exclusion created")
                                        
                                    if createactionplans and json_new_actionplans != None:
                                        str_json_action_plans = str(json_new_actionplans).replace("'", '"')
                                        
                                        logger.info("Creating "  + str(len(json_new_actionplans)) + " action plan items " + str_json_action_plans)
                                        if  str_json_action_plans == '[]':
                                            logger.info("No action plan itea to create, items were already created")
                                        else:
                                            rest_service_aip.create_actionplans_json(domain, applicationid,snapshotid, str_json_action_plans)
                                            logger.info("Action plan items created")
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

                                    # generated output file if required                                    
                                    if outputextension != None:
                                        fpath = get_filepath(outputfolder, appName, outputextension)
                                        logger.info("Generating " + outputextension + " file " + fpath)
                                        if outputextension == 'csv' or outputextension == 'xlsx':
                                            generate_output_file(logger, outputextension, header, outputdata, fpath)
                                    # keep only last snapshot
                                    break
                            
                            ########################################################################################################
                            # Create automated action plan, using standards and quality rules prioritized
                            if automatedactionplan_create:
                                logger.info("Generating automated action plan")
                                list_priority_qs_input = []
                                list_priority_qr_input = []
                                mapping_qs_qr_used = {}
                                list_priority_qr_process = []
                                # read the file containing the quality standard to add in priority in automated action plan
                                try:
                                    with open(extensioninstallationfolder + 'quality standards priority for action plan.csv', 'r') as file:
                                        reader = csv.reader(file,delimiter  = ';')
                                        iline = 0
                                        for each_row in reader:
                                            if iline > 0:
                                                firstcol = each_row[0]
                                                if firstcol != None: 
                                                    #print("=>" + str(firstcol))
                                                    qs = QualityStandard()
                                                    qs.id = str(firstcol)
                                                    list_priority_qs_input.append(qs.id)
                                            iline+=1
                                except:
                                    LogUtils.logwarning(logger, 'Not able to load file "quality standards priority for action plan.csv"', True)
                                # read the file containing the quality rules to add in priority in automated action plan
                                try:
                                    with open(extensioninstallationfolder + 'quality rules priority for action plan.csv', 'r') as file:
                                        iline = 0
                                        reader = csv.reader(file,delimiter  = ';')
                                        for each_row in reader:
                                            if iline > 0:
                                                firstcol = each_row[0]
                                                if firstcol != None: 
                                                    #print("=>" + str(firstcol))
                                                    qr = Metric()
                                                    qr.id = str(firstcol)    
                                                    list_priority_qr_input.append(qr.id)                                                
                                            iline+=1
                                except:
                                    LogUtils.logwarning(logger, 'Not able to load file "quality rules priority for action plan.csv"', True)                                
                                
                                set_quality_standard_used_in_app = set()
                                
                                # Feed the list of standards used in the set of violations filtered
                                # and the mapping between those standard and the quality rules ids used in the app
                                for viol_qr_id in dic_violations_by_qualityrule:
                                    violation_outputs = dic_violations_by_qualityrule[viol_qr_id]
                                    for componentid in violation_outputs: 
                                        qstandards = violation_outputs[componentid].strqualitystandards
                                        break
                                    list_standards_for_qr = qstandards.split(",")
                                    for qs in list_standards_for_qr:
                                        set_quality_standard_used_in_app.add(qs)
                                        if mapping_qs_qr_used.get(qs) == None:
                                            mapping_qs_qr_used[qs] = set()
                                        mapping_qs_qr_used[qs].add(viol_qr_id)

                                list_violations_to_add_to_ap = []
                                i_violations_processed = 0
                                set_qs_already_processed = set()
                                set_qr_already_processed = set()
                                set_violation_ids_processed = set()
                                
                                # Process the priority standards that are associated to filtered violations
                                for qs in list_priority_qs_input:
                                    if i_violations_processed < automatedactionplan_maxnumber:
                                        if qs in set_quality_standard_used_in_app:
                                            if qs in set_qs_already_processed:
                                                continue
                                            set_qs_already_processed.add(qs)
                                            LogUtils.loginfo(logger, "Prioritizing quality standard %s " % str(qs), True)
                                            qs_qr_set = mapping_qs_qr_used[qs]
                                            for qrid in list_priority_qr_input:
                                                if i_violations_processed < automatedactionplan_maxnumber and qrid in qs_qr_set:
                                                    if dic_violations_by_qualityrule.get(qrid) == None:
                                                        continue
                                                    LogUtils.loginfo(logger, "  Prioritizing & processing quality rule %s (%s violations)" % (str(qrid),len(dic_violations_by_qualityrule[qrid])), True)
                                                    i_violations_processed, list_violations_to_add_to_ap = add_violations_for_automated_ap(qrid, set_qr_already_processed, dic_violations_by_qualityrule, i_violations_processed, automatedactionplan_maxnumber, list_violations_to_add_to_ap)
                                                    set_qr_already_processed.add(qrid)
                                    
                                            # parsing all quality rules in case we still have violations to add, inside the qs
                                            for qrid in qs_qr_set:
                                                if i_violations_processed < automatedactionplan_maxnumber and not qrid in set_qr_already_processed:
                                                    if dic_violations_by_qualityrule.get(qrid) == None:
                                                        continue                                                    
                                                    LogUtils.loginfo(logger, "  Processing quality rule %s (%s violations)" % (str(qrid),len(dic_violations_by_qualityrule[qrid])), True)
                                                    i_violations_processed, list_violations_to_add_to_ap = add_violations_for_automated_ap(qrid, set_qr_already_processed, dic_violations_by_qualityrule, i_violations_processed, automatedactionplan_maxnumber, list_violations_to_add_to_ap)
                                                    set_qr_already_processed.add(qrid)
                                

                                # parsing all quality rules in case we still have violations to add, outside the qs
                                if i_violations_processed < automatedactionplan_maxnumber:
                                    for qrid in list_priority_qr_input:
                                        if i_violations_processed < automatedactionplan_maxnumber and not qrid in set_qr_already_processed:
                                            if dic_violations_by_qualityrule.get(qrid) == None:
                                                continue                                            
                                            LogUtils.loginfo(logger, "Prioritizing & processing quality rule %s (%s violations)" % (str(qrid),len(dic_violations_by_qualityrule[qrid])), True)
                                            i_violations_processed, list_violations_to_add_to_ap = add_violations_for_automated_ap(qrid, set_qr_already_processed, dic_violations_by_qualityrule, i_violations_processed, automatedactionplan_maxnumber, list_violations_to_add_to_ap)
                                            set_qr_already_processed.add(qrid)

                                
                                # parsing all quality rules again in case we still have violations to add, outside the prioritized qs and qr
                                if i_violations_processed < automatedactionplan_maxnumber:
                                    for qrid in dic_violations_by_qualityrule:
                                        if i_violations_processed < automatedactionplan_maxnumber and not qrid in set_qr_already_processed:
                                            LogUtils.loginfo(logger, "Processing quality rule %s (%s violations)" % (str(qrid),len(dic_violations_by_qualityrule[qrid])), True)
                                            i_violations_processed, list_violations_to_add_to_ap = add_violations_for_automated_ap(qrid, set_qr_already_processed, dic_violations_by_qualityrule, i_violations_processed, automatedactionplan_maxnumber, list_violations_to_add_to_ap)
                                            set_qr_already_processed.add(qrid)                                
                                
                                # Adding the items to automated action plan
                                i_adding = 0
                                json_str_automated_action_plan = '['
                                for violation_output in list_violations_to_add_to_ap:
                                    i_adding += 1
                                    if not violation_output.violation.hasActionPlan:
                                        json_str_automated_action_plan += '{'
                                        json_str_automated_action_plan += '"component":{"href":"' + violation_output.componentHref + '"},'
                                        json_str_automated_action_plan += '"rulePattern":{"href":"'+ violation_output.qrrulepatternhref + '"},'
                                        json_str_automated_action_plan +=  '"remedialAction":{"comment":"' + violation_output.inputcomment + '","tag":"'+ violation_output.actionplaninputtag + '"}'
                                        json_str_automated_action_plan += '},'
                                json_str_automated_action_plan += ']'
                                if json_str_automated_action_plan != '[]': 
                                    json_str_automated_action_plan = json_str_automated_action_plan[:-2] + ']' 
                                logger.info("json_str_automated_action_plan=%s" % json_str_automated_action_plan)
                                LogUtils.loginfo(logger, "Number of violations selected for automated action plan (including violations already in action plan) : %s" % (str(i_violations_processed)), True)
                                LogUtils.loginfo(logger, "Number of violations to be added to automated action plan : %s" % (str(i_adding)), True)
                                logger.info("Creating automated action plan items ")
                                if  json_str_automated_action_plan == '[]':
                                    logger.info("No automated action plan item to create, items were already created")
                                else:
                                    rest_service_aip.create_actionplans_json(domain, applicationid,snapshotid, json_str_automated_action_plan)
                                    logger.info("Action plan automated items created")
                                
    except: # catch *all* exceptions
        tb = traceback.format_exc()
        #e = sys.exc_info()[0]
        logging.error('  Error during the processing %s' % tb)
        logging.info(' Last violation URL:' + currentviolfullurl + "=> " + qrrulepatternhref + '#' + componentHref)
    
    
