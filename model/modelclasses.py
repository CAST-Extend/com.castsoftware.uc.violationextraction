import logging
import os
import zipfile
import json
import datetime

'''
Created on 11 avr. 2020

@author: MMR
'''

class ArchitectureModel:
    TYPE_AUTHORIZED = 'AuthorizedLinks'
    TYPE_FORBIDDEN = 'ForbiddenLinks'
    
    # Constructor
    #TODO: Not working with deserialization, to be fixed
    #def __init__(self, layers, modelname:str ='Architecture checker model', filename:str ='Architecture checker model.CASTArchitect', ruleType:str = 'ForbiddenLinks', technology:str ='JEE'): 
    def __init__(self, modelname:str ='Architecture checker model', filename:str ='Architecture checker model.CASTArchitect', ruleType:str = TYPE_FORBIDDEN, technologies:str ='JEE', workfolder = '.'): 
        self.filename = filename
        self.modelname = modelname
        self.ruleType = ruleType
        self.technologies = technologies
        #default version
        self.modelversion = '1.0.1.1'
        #TODO: Not working with deserialization, to be fixed
        #self.layers = layers
        self.workfolder = workfolder
        self.layers = []
        self.links = []
        
        #self.create_default_sets()
    
    def setmodelversion(self, modelversion):
        self.modelversion = modelversion
    
    '''
    # Constructor using json, for testing
    def __init__(self, json_model): 
        # default values
        self.filename = 'Architecture checker model.CASTArchitect'
        self.modelname = 'Architecture checker model'
        self.ruleType = 'ForbiddenLinks'
        self.technology = 'JEE'
        self.sets = []
        
        #self.load_json(json_model)
        self.__dict__ = json.loads(json_model)
    '''    
                
    
    ############################################################################################"
    
    @classmethod
    def from_json(cls, data):
        return cls(**data)
        
    ############################################################################################"        
        
    # add a set or layer
    def add_layer(self, alayer): 
        self.layers.append(alayer)

    ############################################################################################"        
    # add a link
    def add_link(self, alink): 
        self.links.append(alink)

    ############################################################################################"
    
    # Constructor using json, for testing
    def load_json (self, json_model):
        # from JSON 
        if json_model != None:
            try:
                self.filename = json_model['filename']
            except KeyError:
                logging.warning('Read json file : empty filename')
            try:
                self.modelname = json_model['modelname']
            except KeyError:
                logging.warning('Read json file : empty modelname')            
            try:
                self.ruleType = json_model['ruleType']
            except KeyError:
                logging.warning('Read json file : empty ruleType')            
            try:
                self.technology = json_model['technology']
            except KeyError:
                None        

    ############################################################################################"
     
    def generate_model(self):
        self.create_file()
        
    ############################################################################################"
     
    def create_unassigned(self):
        s=Layer(Layer.layer_UNASSIGNED, Layer.TYPE_LAYER, False, 220, 100)
        self.add_layer(s)     
    ############################################################################################"
        
    def create_default_sets(self):
        # Unassigned    
        self.create_unassigned()
        
        # Instantiated method, function, constructor, method, for JEE
        if self.technologies != None: 
            if 'JEE' in self.technologies:
                p=Property(Property.NAME_TYPE,Property.OP_EQUALS,[
                    'JV_INST_CLASS' , 
                    'JV_INST_CTOR', 
                    'JV_INST_INTERFACE', 
                    'JV_INST_METHOD',
                ])
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_property(p)
                s=Layer(Layer.set_Java_Instantiated, Layer.TYPE_SET, False)
                s.add_criteria(c)
                self.add_layer(s)
            
            
                p=Property(Property.NAME_TYPE,Property.OP_EQUALS,[
                    'JSP_PROPERTIES_FILE',
                ])
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_property(p)
                s=Layer(Layer.set_Java_Properties_File, Layer.TYPE_SET, False)
                s.add_criteria(c)
                self.add_layer(s)
                
            if 'C#' in self.technologies:
                p=Property(Property.NAME_TYPE,Property.OP_EQUALS,[
                    'CAST_DotNet_InstantiatedGenericClassCSharp' , 
                    'CAST_DotNet_InstantiatedGenericDelegateCSharp', 
                    'CAST_DotNet_InstantiatedGenericInterfaceCSharp', 
                    'CAST_DotNet_InstantiatedGenericMethodCSharp',
                    'CAST_DotNet_InstantiatedGenericStructureCSharp',                
                ])
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_property(p)
                s=Layer(Layer.set_CSharp_Instantiated, Layer.TYPE_SET, False)
                s.add_criteria(c)
                self.add_layer(s)
            if 'SQL' in self.technologies:
                p=Property(Property.NAME_TYPE,Property.OP_EQUALS,[
                    'SQLScriptView',
                    'SQLScriptTable',
                    'SQLScriptTableColumn',
                    'SQLScriptViewSynonym',
                    'SQLScriptTableSynonym',
                    'SQLScriptIndex',
                    'FormsScriptDataBlock',
                    'FormsScriptDataBlockItem',
                    'SQLScriptForeignKey',
                    'SQLScriptUniqueConstraint',
                ])
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_property(p)
                s=Layer(Layer.set_SQL_Database_Data, Layer.TYPE_SET, False)
                s.add_criteria(c)
                self.add_layer(s)
                
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_memberofset(MemberOf(Layer.set_SQL_Database_Data))
                s=Layer(Layer.layer_SQL_Database_Data, Layer.TYPE_LAYER, True)
                s.add_criteria(c)
                self.add_layer(s) 
                
                p=Property(Property.NAME_TYPE,Property.OP_EQUALS,[
                    'SQLScriptEvent',
                    'FormsScriptFunction',
                    'FormsScriptModule',
                    'FormsScriptPackage',
                    'FormsScriptProcedure',
                    'FormsScriptTrigger',
                    'SQLScriptFunction',
                    'SQLScriptPackage',
                    'SQLScriptProcedure',
                    'SQLScriptMethod',
                    'SQLScriptMacro',
                    'SQLScriptFunctionSynonym',
                    'SQLScriptPackageSynonym',
                    'SQLScriptProcedureSynonym',
                    'SQLScriptTypeSynonym',
                    'SQLScriptTrigger',  
                ])
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_property(p)
                s=Layer(Layer.set_SQL_Database_Logic, Layer.TYPE_SET, False)
                s.add_criteria(c)
                self.add_layer(s)   
                
                c=Criteria(Criteria.TYPE_SELECTION_CRITERIA, True, True)
                c.add_memberofset(MemberOf(Layer.set_SQL_Database_Logic))
                s=Layer(Layer.layer_SQL_Database_Logic, Layer.TYPE_LAYER, True)
                s.add_criteria(c)
                self.add_layer(s) 
    ############################################################################################"    
    
    def get_file_criterias(self, c):
        strCrit = ''
        if c.criteriaType in (Criteria.TYPE_SELECTION_CRITERIA, Criteria.TYPE_OR) :
            strsubobjects = "yes"
            
            if c.subobjects != None and not c.subobjects: strsubobjects = "no"
            strexternalobjects = "yes"
            if c.externalobjects != None and not c.externalobjects: strexternalobjects = "no"        
            
            strCrit += '    <selection-criteria subobjects="' + strsubobjects + '" externalobjects="' + strexternalobjects + '">\n'
            if c.criteriaType == Criteria.TYPE_OR:
                strCrit += '    <or>\n'
            for p in c.memberofsets:
                # Member of sets
                strCrit += '      <member-of set="' + p.layername + '"/>\n'
            for p in c.excludedfromsets:
                # Excluded from set
                strCrit += '      <excluded-from set="' + p.layername + '"/>\n'
            for p in c.properties:
                # Properties
                # Path Like
                strCrit += '      <property name="' + p.propertyname +'" operator="' + p.propertyoperator + '" >\n'
                for value in p.values:
                    strCrit += "        <value>" + value + "</value>\n"
                strCrit += '      </property>\n'

        # recursive criterias
        for sub_crit in c.criterias:
            strCrit +=  self.get_file_criterias(self, sub_crit)

        if c.criteriaType in (Criteria.TYPE_SELECTION_CRITERIA, Criteria.TYPE_OR) :
            if c.criteriaType == Criteria.TYPE_OR:
                strCrit += '    </or>\n'
            strCrit += '    </selection-criteria>\n'
        
        return strCrit

    ############################################################################################"
        
    def loginfo(self, msg, tostout=True):
        if tostout != None and tostout:
            print(msg)
        logging.info(msg)
        
    ############################################################################################"
        
    # create the file
    def create_file(self):
        currentdate = datetime.datetime.today()
        
        # layers.xml file
        layers_path = os.path.join(self.workfolder, 'layers.xml')
        fo = open(layers_path, "wt")
        fo.write("<sets name=\"Layers\" version=\"" + self.modelversion + "\" date=\""+ currentdate.ctime()+"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"CAST-Sets.xsd\">\n");             
        strfile = ''
        for s in self.layers:
            # prefix
            strset = '  <set name="' + str(s.layername) + '" type="' + str(s.layertype) + '">\n'
            for c in s.criterias:
                strset += self.get_file_criterias(c)
            strset += '  </set>\n\n'
            strfile += strset
        strfile += '</sets>\n\n'            
        fo.write(strfile);  
        fo.close()           

        # archi_project.arm file
        archi_project_path = os.path.join(self.workfolder, 'archi_project.arm')
        fo2 = open(archi_project_path, "wt") 
        

        fo2.write("<project name=\"" + self.modelname + "\" version=\"" + self.modelversion + "\" date=\""+ currentdate.ctime()+"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"CAST-ArchiCheckerModel.xsd\">\n")
        fo2.write("  <rule type=\"" + self.ruleType + "\" />\n")
        fo2.write("  <datasets name=\"layers.xml\" />\n")
        fo2.write("  <dependencies name=\"dependencies.xml\" />\n")
        fo2.write("  <positions>\n")
        
        #strdefaultwidthheight 
        for s in self.layers:
            if s.showOnView:
                fo2.write("    <dataset name=\"" + s.layername + "\" x=\""+str(s.x)+"\" y=\""+str(s.y)+"\" width=\""+str(s.width)+"\" height=\""+str(s.height)+"\" />\n")
                
        fo2.write("  </positions>\n")
        fo2.write("</project>\n")
        fo2.close()

        # dependencies.xml
        dependencies_path = os.path.join(self.workfolder, 'dependencies.xml')
        fo3 = open(dependencies_path, "wt") 
                
        fo3.write("<rules name=\"Rules\" version=\"" + self.modelversion + "\" date=\""+ currentdate.ctime()+"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"CAST-Rules.xsd\">\n")
        fo3.write(" <rule name = \"default\">\n")
        strtaglink = ''
        if self.ruleType == ArchitectureModel.TYPE_AUTHORIZED:
            strtaglink = 'allow-link' 
        elif self.ruleType == ArchitectureModel.TYPE_FORBIDDEN:
            strtaglink = 'forbid-link'
        for l in self.links:
            fo3.write("  <" + strtaglink + ">\n")
            fo3.write("   <caller layer=\""+ l.caller + "\"/>\n")
            fo3.write("   <callee layer=\""+ l.callee + "\"/>\n")
            fo3.write("  </" + strtaglink + ">\n")
            
        # fo3.write("      <forbid-link>\n")
        # fo3.write("           <caller layer=\"fr.edf.as.archimed.ioflow.clustering\"/>\n")
        # fo3.write("      </forbid-link>\n")
        fo3.write(" </rule>\n")
        fo3.write("</rules>\n")
        fo3.close()

        archi_model_path = os.path.join(self.workfolder, self.filename)
        
        z = zipfile.ZipFile(archi_model_path, "w") 
        z.write(archi_project_path)
        z.write(layers_path)
        z.write(dependencies_path)
        z.close()
        
        self.loginfo("Generated Architecture Model file %s" % archi_model_path)
        self.loginfo("Files are generated in %s" % self.workfolder)
        
        os.remove(archi_project_path)
        #os.remove(layers_path)
        os.remove(dependencies_path)

##################################################################################################
class Criteria:
    
    TYPE_SELECTION_CRITERIA = "SelectionCriteria"
    TYPE_OR = "Or"
    
    # Constructor
    def __init__(self, criteriaType, subobjects, externalobjects): 
        self.criteriaLevel = 1
        self.criteriaType = criteriaType
        self.subobjects = subobjects
        self.externalobjects = externalobjects     
        self.criterias = []
        self.properties = []
        self.excludedfromsets = []
        self.memberofsets = []        
        
    def add_criteria(self, criteria): 
        criteria.criteriaLevel =  self.criteriaLevel + 1
        self.criterias.append(criteria)
        
    def add_property(self, aproperty): 
        self.properties.append(aproperty)

    def add_excludedfromset(self, aset): 
        self.excludedfromsets.append(aset)
        
    def add_memberofset(self, aset): 
        self.memberofsets.append(aset)
  
    @classmethod
    def from_json(cls, data):
        return cls(**data)
        
        
##################################################################################################
        
class Property:
    
    NAME_PATH = "path"
    NAME_TYPE = "type"
    NAME_FULLNAME = "fullname"
    NAME_NAME = "name"
    NAME_AU = "analysis unit name"
    NAME_MODULE = "module name"
    
    OP_EQUALS = "eq"
    OP_NOT_EQUALS = "neq"
    OP_LIKE = "like"
    OP_NOT_LIKE = "notlike"
    OP_SUP = ">"
    OP_SUP_EQUALS = ">="
    OP_INF = "<"
    OP_INF_EQUALS = "<="
    
    # Constructor
    def __init__(self, propertyname, propertyoperator, values): 
        self.propertyname = propertyname
        self.propertyoperator = propertyoperator
        self.values = values

    @classmethod
    def from_json(cls, data):
        return cls(**data)


##################################################################################################

class MemberOf:
    # Constructor
    def __init__(self, setname): 
        self.layername = setname

    @classmethod
    def from_json(cls, data):
        return cls(**data)


##################################################################################################

class ExcludedFrom:
    # Constructor
    def __init__(self, setname): 
        self.layername = setname
 
    @classmethod
    def from_json(cls, data):
        return cls(**data)

##################################################################################################
        
class Layer:
    TYPE_SET = 'set' 
    TYPE_LAYER = 'layer'
    
    layer_UNASSIGNED='Unassigned'
    set_Java_Instantiated = 'set Java Instantiated'
    set_CSharp_Instantiated = 'set C# Instantiated'
    set_Java_Properties_File = 'set Java Properties File' 
    set_SQL_Database_Data = 'set Database Data'    
    set_SQL_Database_Logic = 'set Database Logic' 
    layer_SQL_Database_Data = 'Database - Data'
    layer_SQL_Database_Logic = 'Database - Logic'
    
    # Constructor
    def __init__(self, layername, layertype, showOnView=False, width=220, height=100, x=50, y=50): 
        self.layername = layername
        self.layertype = layertype
        self.criterias = []
        # default values for the display on the view, if applicable
        # visible on the AC view
        self.showOnView = showOnView
        self.width = width
        self.height = height
        self.x = x
        self.y = y
        
        
    def add_criteria(self, criteria):
        criteria.criteriaLevel = 1
        self.criterias.append(criteria) 
   
    @classmethod
    def from_json(cls, data):
        return cls(**data)

##################################################################################################

class Link:
    def __init__(self, caller, callee):
        self.caller = caller
        self.callee = callee
##################################################################################################
