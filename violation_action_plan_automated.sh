#!/bin/bash

#######################################################################
# configure python path, not required if python is on the path
PYTHONPATH=
# PYTHONPATH=C:\Python\Python37\
PYTHONCMD=/usr/bin/python3.7/python
if "$PYTHONPATH" != ""; then PYTHONCMD="$PYTHONPATH""/python";fi

echo "================================="
$PYTHONCMD -V
echo "================================="

#######################################################################
# install the additional python lib required
# IF NOT "%PYTHONPATH%" == "" "%PYTHONPATH%\Scripts\pip" install pandas
# IF NOT "%PYTHONPATH%" == "" "%PYTHONPATH%\Scripts\pip" install requests
# IF NOT "%PYTHONPATH%" == "" "%PYTHONPATH%\Scripts\pip" install xlsxwriter

#######################################################################

# REST API URL : http|https://host(:port)(/WarName)/rest
RESTAPIURL=https://server:port/rest

#When the Engineering dashboard URL and Rest API don't have the same root, fill the below parameter
#if empty will take above URL without /rest
# Engineering dahsboard URL  : http|https://host(:port)(/EngineeringWarName)
#EDURL=https://demo-eu.castsoftware.com/Engineering

APIKEY=ApiKeyValue
USER=admin
#PASSWORD=cast

#######################################################################

# Level of detail : Full|Intermediate|Simple, default is Intermediate (better performance than Full)
DETAILLEVEL=Full

# Application name regexp filter
#APPFILTER=Webgoat^|eComm.*
APPFILTER=ApplicationName

# Critical rules violations filter: true|false (default = false)
CRITICALONLYFILTER=true

# Display the source code in violation in the csv file : true|false, default = false
# DISPLAYSOURCE=true

#######################################################################

# Business criterion filter : 60017 (Total Quality Index)|60016 (Security)|60014 (Efficiency)|60013 (Robustness)|60011 (Transferability)|60012 (Changeability)
# to filter the violations and retrieve the PRI for this business criterion (if only one is selected). (default = no filter)
#BCFILTER=60016,60014
BCFILTER=60016

# Filter the violations : WithActionPlan=in the action plan|WithoutActionPlan=not in the action plan|empty=no filter
#ACTIONPLANFILTER=WithActionPlan

# Technology list filter
#TECHNOFILTER=JEE,SQL

# Filter the violations having an exclusion request: Excluded=have an exclusion request|NotExcluded=no exclusion request|empty=no filter
#EXCLUDEQUESTFILTER=Excluded

# Violation status filter: added|unchanged (default = no filter)
#VIOLATIONSTATUSFILTER=added

# Component status filter: added|updated|unchanged (default = no filter)
#COMPONSTATUSFILTER=added

# Quality rule id regexp filter (default = no filter)
# QRIDFILTER=

# Quality rule name regexp  filter (default = no filter)
# QRNAMEFILTER=

# Component location regexp (aka object full name) filter. (default = no filter)
#COMPONLOCATIONFILTER=.*/Web/.*

# Minimum PRI value filter, applicable only if businesscriterionfilter is filled with one business criterion
#PRIMINVALUEFILTER=500

# Components filter list, using the Rest API component href
#COMPONENTSFILTER=DOMAIN08/components/121756,DOMAIN08/components/12875

# Violations id filter list, using the Rest API quality rule href and component href, separated by # and , separator for multiple values
#VIOLATIONSFILTER=DOMAIN08/rule-patterns/4678#DOMAIN08/components/121756,DOMAIN08/rule-patterns/4678#DOMAIN08/components/12875

# Create exclusion requests, for all selected violations
#CREATEEXCLUSIONS=false

# Create automated action plan
AUTOMATEDACTIONPLANCREATE=true
AUTOMATEDACTIONPLANMAXNUMBER=10

# Add the violations to the action plan, for all selected violations
#CREATEACTIONPLANS=false

# Action plan tag, for action plan creation
ACTIONPLANINPUTTAG=high

# Comment, for action plan or exclusion request creation
#COMMENT=This is an action plan generated/

# Outputextension : csv|xlsx, default = csv
#OUTPUTEXTENSION=csv

#######################################################################
# Build the command line
path="$( dirname "$( which "$0" )" )"
CMD="$PYTHONCMD $path""/violation_extraction.py"

if [ -v RESTAPIURL ];then                               CMD+=" -restapiurl $RESTAPIURL";fi
if [ -v EDURL ];then                                    CMD+=" -edurl $EDURL";fi

if [ ! -v USER ];then                                   USER="N/A";fi
if [ ! -v PASSWORD ];then                       		PASSWORD="N/A";fi
if [ ! -v APIKEY ];then                                 APIKEY="N/A";fi
CMD+=" -user $USER -password $PASSWORD -apikey $APIKEY"

CURRENTFOLDER="$path"
OUTPUTFOLDER="$path"

LOGFILE="$path""/violation_action_plan_automated.log"
if [ -v LOGFILE ];then                                  CMD+=" -log $LOGFILE";fi
if [ -v OUTPUTFOLDER ];then                     		CMD+=" -of $OUTPUTFOLDER";fi

EXTENSIONINSTALLATIONFOLDER="$CURRENTFOLDER"
CMD+=" -extensioninstallationfolder $EXTENSIONINSTALLATIONFOLDER"

echo APPFILTER="$APPFILTER"
if [ -v APPFILTER ];then                                CMD+=" -applicationfilter $APPFILTER";fi
if [ -v DETAILLEVEL ];then                              CMD+=" -detaillevel $DETAILLEVEL";fi
if [ -v CRITICALONLYFILTER ];then                       CMD+=" -criticalrulesonlyfilter $CRITICALONLYFILTER";fi
if [ -v DISPLAYSOURCE ];then                            CMD+=" -displaysource $DISPLAYSOURCE";fi

if [ -v QRIDFILTER ];then                               CMD+=" -qridfilter $QRIDFILTER";fi
if [ -v QRNAMEFILTER ];then                             CMD+=" -qrnamefilter $QRNAMEFILTER";fi
if [ -v BCFILTER ];then                                 CMD+=" -businesscriterionfilter $BCFILTER";fi
if [ -v TECHNOFILTER ];then                             CMD+=" -technofilter $TECHNOFILTER";fi
if [ -v COMPONLOCATIONFILTER ];then             		CMD+=" -componentnamelocationfilter $COMPONLOCATIONFILTER";fi
if [ -v ACTIONPLANFILTER ];then                         CMD+=" -actionplanfilter $ACTIONPLANFILTER";fi
if [ -v EXCLUDEQUESTFILTER ];then                   	CMD+=" -exclusionrequestfilter $EXCLUDEQUESTFILTER";fi
if [ -v VIOLATIONSTATUSFILTER ];then            		CMD+=" -violationstatusfilter $VIOLATIONSTATUSFILTER";fi
if [ -v COMPONSTATUSFILTER ];then                       CMD+=" -componentstatusfilter $COMPONSTATUSFILTER";fi
if [ -v BCFILTER ];then                                 CMD+=" -businesscriterionfilter $BCFILTER";fi
if [ -v PRIMINVALUEFILTER ];then                        CMD+=" -priminvaluefilter $PRIMINVALUEFILTER";fi
if [ -v COMPONENTSFILTER ];then                         CMD+=" -componentsfilter $COMPONENTSFILTER";fi
if [ -v VIOLATIONSFILTER ];then                         CMD+=" -violationsfilter $VIOLATIONSFILTER";fi

if [ -v CREATEEXCLUSIONS ];then                         CMD+=" -createexclusions $CREATEEXCLUSIONS";fi
if [ -v CREATEACTIONPLANS ];then                        CMD+=" -createactionplans $CREATEACTIONPLANS";fi
if [ -v ACTIONPLANINPUTTAG ];then                       CMD+=" -actionplaninputtag $ACTIONPLANINPUTTAG";fi
if [ -v COMMENT ];then                                  CMD+=" -comment$COMMENT";fi
if [ -v OUTPUTEXTENSION ];then                          CMD+=" -outputextension$OUTPUTEXTENSION";fi
if [ -v AUTOMATEDACTIONPLANCREATE ];then                CMD+=" -automatedactionplan_create $AUTOMATEDACTIONPLANCREATE";fi
if [ -v AUTOMATEDACTIONPLANMAXNUMBER ];then 			CMD+=" -automatedactionplan_maxnumber $AUTOMATEDACTIONPLANMAXNUMBER";fi

# Max nbRows for the Rest API calls
#NBROWS=100000000
if [ -v NBROWS ];then                                   CMD+=" -nbrows $NBROWS";fi

#######################################################################

echo "Running the command line"
echo "$CMD"
$CMD
RETURNCODE=$?
echo "RETURNCODE $RETURNCODE"

#######################################################################

# read -rsp $"Press enter to continue..."tt
