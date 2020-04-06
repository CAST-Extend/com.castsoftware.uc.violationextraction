@echo off

SET AIP_DEFAULT_BIN_DIR=C:\Program Files\CAST\8.3
IF "%PYTHONPATH%"=="" SET PYTHONPATH=%AIP_DEFAULT_BIN_DIR%\ThirdParty\Python34

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Rest API URL  : http|https://host(:port)(/EngineeringWarName) or http|https://host(:port)(/CAST-RESTAPIWarName) 
SET RESTAPIURL=https://demo-eu.castsoftware.com/Engineering
SET CMD_RESTAPIURL=-restapiurl "%RESTAPIURL%"

::When the Engineering dashboard URL and Rest API are different, fill the below parameter 
:: Engineering dahsboard URL  : http|https://host(:port)(/EngineeringWarName) 
::SET EDURL=https://demo-eu.castsoftware.com/Engineering
SET CMD_EDURL=
::SET CMD_EDURL=-edurl "%RESTAPIURL%"

::SET USER=N/A
SET USER=CIO
SET CMD_USER=-user "%USER%"
::SET PASSWORD=N/A
SET PASSWORD=cast
SET CMD_PASSWORD=-password "%PASSWORD%"
SET APIKEY=N/A
SET CMD_APIKEY=-apikey "%APIKEY%"

:: Output folder
SET OUTPUTFOLDER=C:\Users\mmr\workspace\com.castsoftware.uc.violationextraction
SET CMD_OUTPUTFOLDER=-of "%OUTPUTFOLDER%"

SET LOGFILE=%OUTPUTFOLDER%\violation_data_extraction.log
SET CMD_LOGFILE=-log "%LOGFILE%"
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: Level of detail : Full|Intermediate|Simple, default is Intermediate (better performance than Full)
SET DETAILLEVEL=Intermediate
SET CMD_DETAILLEVEL=
SET CMD_DETAILLEVEL=-detaillevel "%DETAILLEVEL%"

:: Application name regexp filter
::SET APPFILTER=Webgoat^|eComm.*
SET APPFILTER=Webgoat
SET CMD_APPFILTER=
SET CMD_APPFILTER=-applicationfilter "%APPFILTER%"


:: Quality rule id regexp filter
::SET QRIDFILTER=7802|7804
SET CMD_QRIDFILTER=
::SET CMD_QRIDFILTER=%QRIDFILTER%


:: Quality rule name regexp  filter
::SET QRNAMEFILTER=
SET CMD_QRNAMEFILTER=
::SET CMD_QRIDFILTER=-qridfilter "%QRNAMEFILTER%"


:: Component location regexp (aka object full name) filter
::SET COMPONLOCATIONFILTER=.*/Web/.*
SET CMD_COMPONLOCATIONFILTER=
::SET CMD_COMPONLOCATIONFILTER=-componentnamelocationfilter "%COMPONLOCATIONFILTER%"


:: Filter the violations : WithActionPlan|WithoutActionPlan
:: WithActionPlan : in the action plan
:: WithoutActionPlan : not in the action plan
:: empty : no filter
::SET ACTIONPLANFILTER=WithActionPlan
SET CMD_ACTIONPLANFILTER=
::SET CMD_ACTIONPLANFILTER=-actionplanfilter "%ACTIONPLANFILTER%"


:: Filter the violations having an exclusion request: Excluded|NotExcluded
:: Excluded : have an exclusion request
:: NotExcluded : no exclusion request
:: empty : no filter
::SET EXCLUREQUESTFILTER=Excluded
SET CMD_EXCLUREQUESTFILTER=
::SET CMD_EXCLUREQUESTFILTER=-exclusionrequestfilter "%EXCLUREQUESTFILTER%"


:: Critical rules violations filter: true|false
::SET CRITICALONLYFILTER=true
SET CMD_CRITICALONLYFILTER=
::SET CMD_CRITICALONLYFILTER=-criticalrulesonlyfilter "%CRITICALONLYFILTER%"


:: Violation status filter: added|unchanged
::SET VIOLATIONSTATUSFILTER=added
SET CMD_VIOLATIONSTATUSFILTER=
::SET CMD_VIOLATIONSTATUSFILTER=-violationstatusfilter "%VIOLATIONSTATUSFILTER%"


:: Component status filter: added|updated|unchanged
::SET COMPONSTATUSFILTER=added
SET CMD_COMPONSTATUSFILTER=
::SET CMD_COMPONSTATUSFILTER=-componentstatusfilter "%COMPONSTATUSFILTER%"


:: Business criterion filter : 60017 (Total Quality Index)|60016 (Security)|60014 (Efficiency)|60013 (Robustness)|60011 (Transferability)|60012 (Changeability)
:: to filter the violations and retrieve the PRI for this business criterion (if only one is selected)
::SET BCFILTER=60016,60014
::SET BCFILTER=60016
SET CMD_BCFILTER=
::SET CMD_BCFILTER=-businesscriterionfilter "%BCFILTER%"

:: Minimum PRI value filter, applicable only if businesscriterionfilter is filled with one business criterion
::SET PRIMINVALUEFILTER=500
SET CMD_PRIMINVALUEFILTER=
::SET CMD_PRIMINVALUEFILTER=-priminvaluefilter "%PRIMINVALUEFILTER%"


:: Technology list filter
::SET TECHNOFILTER=JEE,SQL
SET CMD_TECHNOFILTER=
::SET CMD_TECHNOFILTER=-priminvaluefilter "%TECHNOFILTER%"


:: Components filter list, using the Rest API component href
::SET COMPONENTSFILTER=DOMAIN08/components/121756,DOMAIN08/components/12875
SET CMD_COMPONENTSFILTER=
::SET CMD_COMPONENTSFILTER=-componentsfilter "%COMPONENTSFILTER%"


:: Violations id filter list, using the Rest API quality rule href and component href, separated by # and , separator for multiple values
::SET VIOLATIONSFILTER=DOMAIN08/rule-patterns/4678#DOMAIN08/components/121756,DOMAIN08/rule-patterns/4678#DOMAIN08/components/12875
SET CMD_VIOLATIONSFILTER=
::SET CMD_VIOLATIONSFILTER=-violationsfilter "%VIOLATIONSFILTER%"


:: Create exclusion requests, for all selected violations
::SET CREATEEXCLUSIONS=false
SET CMD_CREATEEXCLUSIONS=
::SET CMD_CREATEEXCLUSIONS=-createexclusions "%CREATEEXCLUSIONS%"

:: Add the violations to the action plan, for all selected violations
::SET CREATEACTIONPLANS=false
SET CMD_CREATEACTIONPLANS=
::SET CMD_CREATEACTIONPLANS=-createactionplans "%CREATEACTIONPLANS%"

:: Action plan tag, for action plan creation
::SET ACTIONPLANINPUTTAG=high
SET CMD_ACTIONPLANINPUTTAG=
::SET CMD_ACTIONPLANINPUTTAG=-actionplaninputtag "%ACTIONPLANINPUTTAG%"



:: Comment, for action plan or exclusion request creation
::SET COMMENT=This is an action plan generated/
SET CMD_COMMENT=
::SET CMD_COMMENT=-comment "%COMMENT%"


:: Generate a csv of detail : true|false, default = false
SET CSVFILE=true
SET CMD_CSVFILE=
SET CMD_CSVFILE=-csvfile "%CSVFILE%"

:: Max nbRows for the Rest API calls
::SET NBROWS=100000000
SET CMD_NBROWS=
::SET CMD_NBROWS=-nbrows "%NBROWS%"

:: Display the source code in violation in the csv file : true|false, default = false
::SET DISPLAYSOURCE=true
SET CMD_DISPLAYSOURCE=
::SET CMD_DISPLAYSOURCE=-displaysource "%DISPLAYSOURCE%"

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
ECHO Running the command line 
SET CMD="%PYTHONPATH%\python" "%~dp0violation_extraction.py" %CMD_RESTAPIURL% %CMD_EDURL% %CMD_USER% %CMD_PASSWORD% %CMD_APIKEY% %CMD_LOGFILE% %CMD_OUTPUTFOLDER% %CMD_APPFILTER% %CMD_QRIDFILTER% %CMD_QRNAMEFILTER% %CMD_COMPONLOCATIONFILTER% %CMD_ACTIONPLANFILTER% %CMD_EXCLUREQUESTFILTER% %CMD_CRITICALONLYFILTER% %CMD_VIOLATIONSTATUSFILTER% %CMD_COMPONSTATUSFILTER% %CMD_BCFILTER% %CMD_PRIMINVALUEFILTER% %CMD_TECHNOFILTER% %CMD_COMPONENTSFILTER% %CMD_VIOLATIONSFILTER% %CMD_CREATEEXCLUSIONS% %CMD_CREATEACTIONPLANS% %CMD_ACTIONPLANINPUTTAG% %CMD_COMMENT% %CMD_DETAILLEVEL% %CMD_CSVFILE% %CMD_NBROWS% %CMD_DISPLAYSOURCE%
ECHO %CMD%
%CMD%
SET RETURNCODE=%ERRORLEVEL%
ECHO RETURNCODE %RETURNCODE% 

PAUSE