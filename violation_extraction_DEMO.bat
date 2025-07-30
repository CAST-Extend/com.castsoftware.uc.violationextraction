@echo off

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REM configure python path, not required if python is on the path
SET PYTHONPATH=
REM SET PYTHONPATH=C:\Python\Python37\
SET PYTHONCMD=python
IF NOT "%PYTHONPATH%" == "" SET PYTHONCMD=%PYTHONPATH%\python

ECHO =================================
"%PYTHONCMD%" -V
ECHO =================================

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REM install the additional python lib required
REM see also Requirements.txt
REM IF NOT "%PYTHONPATH%" == "" "%PYTHONPATH%\Scripts\pip" install pandas
REM IF NOT "%PYTHONPATH%" == "" "%PYTHONPATH%\Scripts\pip" install requests 
REM IF NOT "%PYTHONPATH%" == "" "%PYTHONPATH%\Scripts\pip" install xlsxwriter

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: REST API URL : http|https://host(:port)(/WarName)/rest
SET RESTAPIURL=https://demo-eu.castsoftware.com/Engineering/rest

::When the Engineering dashboard URL and Rest API don't have the same root, fill the below parameter
::if empty will take above URL without /rest 
:: Engineering dahsboard URL  : http|https://host(:port)(/EngineeringWarName) 
::SET EDURL=https://demo-eu.castsoftware.com/Engineering

::SET APIKEY=N/A
SET USER=demo
SET PASSWORD=

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: Level of detail : Full|Intermediate|Simple, default is Intermediate (better performance than Full)
SET DETAILLEVEL=Simple

:: Application name regexp filter
::SET APPFILTER=Webgoat^|eComm.*
SET APPFILTER=WebGoat

:: Critical rules violations filter: true|false (default = false)
SET CRITICALONLYFILTER=true

:: Business criterion filter : 60017 (Total Quality Index)|60016 (Security)|60014 (Efficiency)|60013 (Robustness)|60011 (Transferability)|60012 (Changeability)
:: to filter the violations and retrieve the PRI for this business criterion (if only one is selected). (default = no filter)
::SET BCFILTER=60016,60014
::SET BCFILTER=60016

:: Technical criterion filter : 61014 (Programming Practices - Error and Exception Handling)|61027 (Dead code)|...
:: to filter the violations and retrieve the PRI for this business criterion (if only one is selected). (default = no filter)
::SET TCFILTER=60016,60014
::SET TCFILTER=61027

:: Quality rule id regexp filter (default = no filter) - cannot be combined with above two filters
:: SET QRIDFILTER=

:: Display the source code in violation in the csv file : true|false, default = false
SET DISPLAYSOURCE=true
:: Is a mainframe application, processing the source code bookmarks is differente for Mainframe
:: requires the level of detail to be Full
::SET IS_MAINFRAME=true

:: Options : modules, ...
:: both params are required if we want to have the module(s) for each violation  
SET OPTIONS=modules
SET MODULEFILTER=$all

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Filter the violations : WithActionPlan=in the action plan|WithoutActionPlan=not in the action plan|empty=no filter
::SET ACTIONPLANFILTER=WithActionPlan

:: Technology list filter
::SET TECHNOFILTER=JEE,SQL

:: Filter the violations having an exclusion request: Excluded=have an exclusion request|NotExcluded=no exclusion request|empty=no filter
::SET EXCLUDEQUESTFILTER=Excluded

:: Violation status filter: added|unchanged (default = no filter)
::SET VIOLATIONSTATUSFILTER=added

:: Component status filter: added|updated|unchanged (default = no filter)
::SET COMPONSTATUSFILTER=added



:: Quality rule name regexp  filter (default = no filter)
:: SET QRNAMEFILTER=

:: Component location regexp (aka object full name) filter. (default = no filter)
::SET COMPONLOCATIONFILTER=.*/Web/.*

:: Minimum PRI value filter, applicable only if businesscriterionfilter is filled with one business criterion
::SET PRIMINVALUEFILTER=500

:: Components filter list, using the Rest API component href
::SET COMPONENTSFILTER=DOMAIN08/components/121756,DOMAIN08/components/12875

:: Violations id filter list, using the Rest API quality rule href and component href, separated by # and , separator for multiple values
::SET VIOLATIONSFILTER=DOMAIN08/rule-patterns/4678#DOMAIN08/components/121756,DOMAIN08/rule-patterns/4678#DOMAIN08/components/12875

:: Create exclusion requests, for all selected violations
::SET CREATEEXCLUSIONS=false

:: Add the violations to the action plan, for all selected violations
::SET CREATEACTIONPLANS=false

:: Action plan tag, for action plan creation
::SET ACTIONPLANINPUTTAG=high

:: Comment, for action plan or exclusion request creation
::SET COMMENT=This is an action plan generated/

:: Outputextension : csv|xlsx, default = csv
::SET OUTPUTEXTENSION=csv


:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REM Build the command line
SET CMD="%PYTHONCMD%" "%~dp0violation_extraction.py" 

IF DEFINED RESTAPIURL 				SET CMD=%CMD% -restapiurl "%RESTAPIURL%"
IF DEFINED EDURL					SET CMD=%CMD% -edurl "%EDURL%"

IF NOT DEFINED USER 				SET USER=N/A
IF NOT DEFINED PASSWORD 			SET PASSWORD=N/A
IF NOT DEFINED APIKEY 				SET APIKEY=N/A
SET CMD=%CMD% -user "%USER%" -password "%PASSWORD%" -apikey "%APIKEY%"

SET CURRENTFOLDER=%~dp0
:: remove trailing \
SET CURRENTFOLDER=%CURRENTFOLDER:~0,-1%

SET OUTPUTFOLDER=%CURRENTFOLDER%

SET LOGFILE=%CURRENTFOLDER%\violation_data_extraction.log
IF DEFINED LOGFILE					SET CMD=%CMD% -log "%LOGFILE%"
IF DEFINED OUTPUTFOLDER 			SET CMD=%CMD% -of "%OUTPUTFOLDER%"

SET EXTENSIONINSTALLATIONFOLDER=%CURRENTFOLDER%
SET CMD=%CMD% -extensioninstallationfolder "%EXTENSIONINSTALLATIONFOLDER%"

ECHO APPFILTER=%APPFILTER%
IF DEFINED APPFILTER 				SET CMD=%CMD% -applicationfilter "%APPFILTER%"
IF DEFINED DETAILLEVEL				SET CMD=%CMD% -detaillevel "%DETAILLEVEL%"
IF DEFINED CRITICALONLYFILTER		SET CMD=%CMD% -criticalrulesonlyfilter "%CRITICALONLYFILTER%"
IF DEFINED DISPLAYSOURCE			SET CMD=%CMD% -displaysource "%DISPLAYSOURCE%"
IF DEFINED IS_MAINFRAME				SET CMD=%CMD% -is_mainframe "%IS_MAINFRAME%"
IF DEFINED OPTIONS					SET CMD=%CMD% -options "%OPTIONS%"

IF DEFINED QRIDFILTER				SET CMD=%CMD% -qridfilter %QRIDFILTER%
IF DEFINED QRNAMEFILTER				SET CMD=%CMD% -qrnamefilter "%QRNAMEFILTER%"
IF DEFINED BCFILTER					SET CMD=%CMD% -businesscriterionfilter "%BCFILTER%"
IF DEFINED TCFILTER					SET CMD=%CMD% -technicalcriterionfilter "%TCFILTER%"
IF DEFINED TECHNOFILTER				SET CMD=%CMD% -technofilter "%TECHNOFILTER%"
IF DEFINED COMPONLOCATIONFILTER		SET CMD=%CMD% -componentnamelocationfilter "%COMPONLOCATIONFILTER%"
IF DEFINED ACTIONPLANFILTER			SET CMD=%CMD% -actionplanfilter "%ACTIONPLANFILTER%"
IF DEFINED EXCLUDEQUESTFILTER		SET CMD=%CMD% -exclusionrequestfilter "%EXCLUDEQUESTFILTER%"
IF DEFINED VIOLATIONSTATUSFILTER	SET CMD=%CMD% -violationstatusfilter "%VIOLATIONSTATUSFILTER%"
IF DEFINED COMPONSTATUSFILTER		SET CMD=%CMD% -componentstatusfilter "%COMPONSTATUSFILTER%"
IF DEFINED BCFILTER					SET CMD=%CMD% -businesscriterionfilter "%BCFILTER%"
IF DEFINED PRIMINVALUEFILTER		SET CMD=%CMD% -priminvaluefilter "%PRIMINVALUEFILTER%"
IF DEFINED COMPONENTSFILTER			SET CMD=%CMD% -componentsfilter "%COMPONENTSFILTER%"
IF DEFINED VIOLATIONSFILTER			SET CMD=%CMD% -violationsfilter "%VIOLATIONSFILTER%"
IF DEFINED MODULEFILTER				SET CMD=%CMD% -modulefilter "%MODULEFILTER%"


IF DEFINED CREATEEXCLUSIONS 		SET CMD=%CMD% -createexclusions "%CREATEEXCLUSIONS%"
IF DEFINED CREATEACTIONPLANS		SET CMD=%CMD% -createactionplans "%CREATEACTIONPLANS%"
IF DEFINED ACTIONPLANINPUTTAG		SET CMD=%CMD% -actionplaninputtag "%ACTIONPLANINPUTTAG%"
IF DEFINED COMMENT					SET CMD=%CMD% -comment "%COMMENT%"
IF DEFINED OUTPUTEXTENSION			SET CMD=%CMD% -outputextension "%OUTPUTEXTENSION%"

:: Max nbRows for the Rest API calls
::SET NBROWS=100000000
IF DEFINED NBROWS					SET CMD=%CMD% -nbrows "%NBROWS%"

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

ECHO Running the command line 
ECHO %CMD%
%CMD%
SET RETURNCODE=%ERRORLEVEL%
ECHO RETURNCODE %RETURNCODE% 

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

PAUSE