import xml.etree.ElementTree as ET
import ipaddress
import logging
from io import BytesIO
import re
import csv
from io import StringIO

from bs4 import BeautifulSoup
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from system.db import Database

from lxml import etree
import os
def validate_xml(xml_file, xsd_file):
    try:
        # Carica il file XSD (usa rb per leggere come bytes)
        with open(xsd_file, 'rb') as schema_file:
            schema_root = etree.XML(schema_file.read())

        schema = etree.XMLSchema(schema_root)

        # Carica il file XML (usa rb per leggere come bytes)
        with open(xml_file, 'rb') as xml_file:
            xml_doc = etree.XML(xml_file.read())

        # Valida XML con XSD
        schema.assertValid(xml_doc)
        print("Il file XML è valido rispetto allo schema XSD.")
    except etree.XMLSyntaxError as e:
        print(f" Errore di sintassi XML: {e}")
    except etree.DocumentInvalid as e:
        print(f" Il file XML NON è valido: {e}")


# Route name and tools description
route_name = "reducer"

tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/DVWwGcS/redcheck.png",
        "Official name": "Reducer",
        "Short name": "reducer",
        "Description": "Remove unnecessary warnings",
        "URL": "https://www.redcheck.ru/",
        "Plugin author": "@drakylar"
    }
]

####### Input arguments ########
# FlaskWTF forms
class ToolArguments(FlaskForm):
    xml_files = MultipleFileField(
        label='xml_files',
        description='.xml reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".xml"}
    )


########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    # fields variables
    print("Current directory:", os.getcwd())
    xml_files = input_dict["xml_files"]
    xsd_file = "/routes/ui/tools_addons/import_plugins/reducer/new.xsd"
    for bin_data in xml_files:
        try:
            if bin_data:
                print("ls")
                xml_data = bin_data.decode("charmap") 
                '''
                if not validate_xml(xml_data, xsd_file):
                    return "XML validation failed!"
                '''
                scan_result = BeautifulSoup(xml_data, "html.parser")
                query_list = scan_result.find_all("query")
                for query in query_list:
                    vulnerability_name = re.sub(' Version:[0-9]+', '', query.attrs['querypath'].split('\\')[-1])
                    language = query.attrs['language']
                    cwe = query.attrs['cweid']
                    vuln_array = query.find_all("result")
                    for vuln_example in vuln_array:
                        criticality = vuln_example.attrs['severity']  # High
                        filename = vuln_example.attrs['filename']
                        path_find = vuln_example.find_all("path")
                        paths_str_arrays = []
                        for path_obj in path_find:
                            paths_str = ''
                            path_nodes = vuln_example.find_all("pathnode")
                            if path_nodes:
                                paths_str = '########## Path {} ###########\n'.format(path_find.index(path_obj) + 1)
                            for path_node in path_nodes:
                                filename = path_node.find_all("filename")[0].text
                                line_num = int(path_node.find_all("line")[0].text)
                                colum_num = int(path_node.find_all("column")[0].text)
                                code_arr = path_node.find_all("code")
                                node_str = 'Filename: {}\nLine: {} Column: {}'.format(filename, line_num, colum_num)
                                for code in code_arr:
                                    node_str += '\n' + code.text.strip(' \t')
                                paths_str += node_str + '\n\n'

                            if paths_str:
                                paths_str_arrays.append(paths_str + '\n\n')
                        all_paths_str = '\n'.join(paths_str_arrays)

                        if criticality == 'High':
                            cvss = 9.5
                        elif criticality == 'Medium':
                            cvss = 8.0
                        elif criticality == 'Low':
                            cvss = 2.0
                        else:
                            cvss = 0
                        issue_id = db.insert_new_issue(vulnerability_name,
                                                       'Language: {}\n'.format(language) + all_paths_str, filename,
                                                       cvss, current_user['id'],
                                                       {}, 'need to check', current_project['id'], cwe=cwe,
                                                       issue_type='custom')
        except Exception as e:
            logging.error("Exception during file import: {}".format(e))
            return "One of files was corrupted!"
    return ""
