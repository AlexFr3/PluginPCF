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
import socket
def validate_xml(xml_content, xsd_file):
    """Valida un file XML rispetto ad uno schema XSD"""
    try:
        with open(xsd_file, 'rb') as schema_file:
            schema_root = etree.XML(schema_file.read())

        schema = etree.XMLSchema(schema_root)
        xml_doc = etree.fromstring(xml_content.encode('utf-8'))
        schema.assertValid(xml_doc)
        print("Il file XML è valido rispetto allo schema XSD.")
        return True
    except etree.XMLSyntaxError as e:
        logging.error(f"Errore di sintassi XML: {e}")
        return False
    except etree.DocumentInvalid as e:
        logging.error(f"Il file XML NON è valido: {e}")
        return False
def getDataSoup(xml_data):
    soup = BeautifulSoup(xml_data, "xml")
    site = soup.find("site")
    if not site:
        print("Nessun <site> trovato nell'XML!")
        return None,None,None,None,None,None
    site_name = site.get("name", "Unknown")
    host = site.get("host", "Unknown")
    port = site.get("port", "Unknown")
    ssl = site.get("ssl", "Unknown")
    return soup,site,site_name,host,port,ssl
def clean_html_entities(text):
    """Rimuove le entità HTML da una stringa di testo"""
    soup = BeautifulSoup(text, "html.parser")
    return soup.get_text()
def split_sentences_safely(text):
    """Aggiunge newline tra le frasi di un testo, evitando duplicati"""
    # Split tra i punti che non sono parte di numeri o IP
    sentences = re.split(r'(?<!\d)\.(?!\d|\(|\))', text)
    sentences = [sentence.strip() for sentence in sentences if sentence.strip()]  # Rimuovi spazi extra

    seen_phrases = set()
    unique_sentences = []

    for sentence in sentences:
        if sentence not in seen_phrases:
            seen_phrases.add(sentence)
            unique_sentences.append(sentence)

    # Aggiungi un punto a ciascuna frase, ma solo se non è già presente alla fine
    for i in range(len(unique_sentences)):
        if not unique_sentences[i].endswith('.'):
            unique_sentences[i] += '.'

    # Unisci le frasi con '\n'
    result = '\n'.join(unique_sentences)

    # Rimuovi il punto finale extra se presente
    if result.endswith('.'):
        result = result[:-1]

    return result
def confidenceRisk_toText(risk,confidence):
    if confidence == 0:
        confidence = "Info"
    elif confidence == 1:
        confidence = "Low"
    elif confidence == 2:
        confidence = "Medium"
    elif confidence == 3:
        confidence = "High"
        
    if risk == 0:
        risk = "Info"
    elif risk == 1:
        risk = "Low"
    elif risk == 2:
        risk = "Medium"
    elif risk == 3:
        risk = "High"
        
    risk_str=f"Risk: {risk}\n Confidence: {confidence}"
    return risk_str

def get_otherInfo(alert):
    otherInfo_items = alert.find_all("otherinfo")

    # Crea una lista di testi, aggiungendo il newline dopo ogni frase
    seen_phrases = set()
    # Crea una lista di testi, aggiungendo il newline dopo ogni frase, senza bisogno di controllare duplicati
    otherInfo_cleaned = [
        split_sentences_safely(otherInfo.get_text(strip=True))
            for otherInfo in otherInfo_items
                    if (otherInfo_text := otherInfo.get_text(strip=True)) 
                    and otherInfo_text 
                    not in seen_phrases 
                    and not seen_phrases.add(otherInfo_text)#utilizzando set per evitare duplicati
    ]
    # Unisci il testo dei <otherinfo> separato da \n
    otherInfo_complete = '\n'.join(otherInfo_cleaned)
    otherInfo = clean_html_entities(otherInfo_complete)
    return otherInfo
def technical_description(site_name, host, port, ssl, language, otherInfo):
    """Genera una descrizione tecnica basata su vari parametri"""
    technical_parts = []
    if site_name: technical_parts.append(f"Site: {site_name}")
    if host: technical_parts.append(f"Host: {host}")
    if port: technical_parts.append(f"Port: {port}")
    if ssl: technical_parts.append(f"SSL: {ssl}")
    if language: technical_parts.append(f"Language: {language}")
    if otherInfo: technical_parts.append(f"OtherInfo: {otherInfo}")

    return "\n".join(technical_parts)
def verify_host(host_id,db):
    """Verifica che l'host sia presente nel db"""
    current_host = db.select_host(host_id)  # Metodo CORRETTO
    if current_host:
        print("Host confermato nel DB")
    else:
        logging.error(f"ERRORE: Host con ID {host_id} non trovato!")
        return f"Errore: Host non trovato dopo l'inserimento."
    return
def create_services_dict(pcf_port_id, pcf_hostname_id):
    """
    Crea un dizionario services nel formato:
    { idService: [ "[\"0\",\"idHostname\"]" ] }

    Dove:
      - idService è il pcf_port_id
      - "0" indica che non c'è una porta associata (solo IP)
      - idHostname è il pcf_hostname_id
    """
    # Costruisce il dizionario invece di una stringa formattata
    inner_value = ["0", str(pcf_hostname_id)]  # La lista invece della stringa
    return { pcf_port_id: inner_value }

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
    #StringField cambiato in hidden perchè è automatico
    hostnames_file = HiddenField(
            label='hostnames_file',
            description='or take IPs from this field',
            default='127.0.0.1\n',
            validators=[],
            _meta={"display_row": 3, "display_column": 1, "multiline": False}
        )
    
    auto_resolve = BooleanField(label='auto_resolve',
                                description="Automatic resolve ip from PCF server",
                                default=True,
                                validators=[],
                                _meta={"display_row": 2, "display_column": 1})
    
    hosts_description = StringField(
            label='hosts_description',
            description='Host description',
            default='Added from Reducer',
            validators=[],
            _meta={"display_row": 1, "display_column": 2, "multiline": False}
        )
    
    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostname description',
        default='Added from Reducer',
        validators=[],
        _meta={"display_row": 3, "display_column": 2, "multiline": False}
    )

########### Request processing

def process_request(
        current_user: dict,  # current_user['id'] - UUID of current user
        current_project: dict,  # current_project['id'] - UUID of current project
        db: Database,  # object of Database() class /system/db.py
        input_dict: object,  # dict with keys - input field names, and values.
        global_config: object  # dict with keys - setting.ini file data
) -> str:  # returns error text or "" (if finished successfully)

    xml_files = input_dict['xml_files']
    if not xml_files:
        return "Nessun file XML ricevuto!"
    
    xsd_file = os.path.join(os.getcwd(), "routes/ui/tools_addons/import_plugins/reducer/zap.xsd")
    for bin_data in xml_files:
        try:
            if not bin_data:
                continue  # Evita file vuoti

            # Decodifica con UTF-8
            xml_data = bin_data.decode("utf-8")
            print("File XML ricevuto!")
            # Valida XML rispetto allo schema XSD (attivare se necessario)
            if not validate_xml(xml_data, xsd_file):
                return "XML validation failed!"
            
            # Estraggo i dati XML con BeautifulSoup e ElementTree
            soup, site, site_name, host, port, ssl = getDataSoup(xml_data)
            ip_obj = socket.gethostbyname(host)
            print(f"IP: {ip_obj}")
            
            try:
                print("--------------------------------------------------------")
                print(f"current_project:{current_project['id']}")
                
                # 1. CERCO HOST PER IP NEL PROGETTO CORRENTE
                current_host = db.select_project_host_by_ip(
                    project_id=current_project['id'],
                    ip=str(ip_obj)
                )
                
                if current_host:  # Host già esistente
                    current_host = current_host[0]
                    host_id = current_host['id']
                    print(f"Host trovato: {host_id}")
                else:  # Host non trovato, creazione nuovo
                    print(" Nessun host trovato, lo inserisco nel DB")
                    host_id = db.insert_host(
                        project_id=current_project['id'], 
                        ip=str(ip_obj), 
                        user_id=current_user['id'],
                        comment=input_dict['hosts_description'],
                        threats=[],  
                        os=''        
                    )
                    verify_host(host_id,db)
                    
            except Exception as e:
                logging.error(f"Errore nella selezione dell'host: {str(e)}")
                return f"Errore nel recupero dell'host: {str(e)}"
            '''-----------------------------------------------------------------''' 
            # gestione hostname
            pcf_hostname_id = "0"
            
            if host:
                current_hostname = db.select_ip_hostname(host_id, host)
                if current_hostname:
                    hostname_id = current_hostname[0]['id']
                else:   
                    hostname_id = db.insert_hostname(host_id, host,
                                                    input_dict['hostnames_description'],
                                                    current_user['id'])
            pcf_hostname_id = hostname_id
            '''-----------------------------------------------------------------'''
            # Gestione porta
            try:
                port = int(site.get("port", "0"))
            except ValueError:
                logging.error(f"Porta non valida: {site.get('port')}")
                return f"Porta non valida: {site.get('port')}"
            ###################
            #Aggiungere controlli per determinare se tcp o no
            is_tcp = True  # Impostazione di default
            if port != 0:
                is_tcp = True  

            # Verifica se la porta esiste nel DB
            print("-" * 40)
            print(f"Prima di inserimento\nhost_id: {host_id}, port: {port}, is_tcp: {is_tcp}")
            existing_port = db.select_host_port(host_id, port, is_tcp)
            if not existing_port:
                db.insert_host_port(
                    host_id, 
                    port, 
                    is_tcp, 
                    input_dict['hosts_description'], 
                    "Porta rilevata dall'analisi XML di ZAP", 
                    str(current_user['id']), 
                    str(current_project['id'])
                )
                print("Port inserita: " + str(existing_port))

            
            print(f"Dopo inserimento\nhost_id: {host_id}, port: {port}, is_tcp: {is_tcp}")
            existing_port = db.select_host_port(host_id, port, is_tcp)
            print(f"Porta esistente: {existing_port}")
            print("-" * 40)
            
            port_id = existing_port[0]['id']
            web_dict = {
                'pcf_port_id': port_id,
                'pcf_host_id': host_id,
                'pcf_hostname_id': pcf_hostname_id
            } 
            print("*" * 40)
            print(f"PCF Port ID: {web_dict['pcf_port_id']}")
            print(f"PCF Host ID: {web_dict['pcf_host_id']}")
            print(f"PCF Hostname ID: {web_dict['pcf_hostname_id']}")
            print("*" * 40)
            '''-----------------------------------------------------------------'''
            # Estrai tutte le istanze della vulnerabilità
            # Analizza gli alert di vulnerabilità
            alert_items = soup.find_all("alertitem")
            if not alert_items:
                print("Nessun alert trovato.")
                continue
            # All'interno del ciclo per ogni alert
            for alert in alert_items:
                vulnerability_name = alert.find("name").text.strip()
                risk=int(alert.find("riskcode").text.strip())
                
                #############################
                #contrallare se si possono eliminare
                
                instances = alert.find_all("instance")
                all_paths = []
                if instances:
                    for instance in instances:
                        uri = instance.find("uri").text.strip()
                        method = instance.find("method").text.strip()
                        evidence = instance.find("evidence").text.strip()
                        all_paths.append(f"{method} {uri} - Evidenza: {evidence}")


                all_paths_str = "\n".join(all_paths) if all_paths else "Nessuna evidenza trovata"
                
                '''-----------------------------------------------------------------'''
                '''Valori per il DB'''
                report = soup.find("OWASPZAPReport")
                filename = report.get("programName", "zap_scan.xml")
                language = report.get("language", "")
                cwe = alert.find("cweid").text.strip()
                desc= clean_html_entities(alert.find("desc").text.strip())
                solution= clean_html_entities(alert.find("solution").text.strip())
                references= clean_html_entities(alert.find("reference").text.strip())

                confidence_complete=clean_html_entities(alert.find("confidence").text.strip())
                confidence = int(confidence_complete) if alert.find("confidence") else alert.find("confidencedesc").text.strip() if alert.find("confidencedesc") else 0
                
                otherInfo = get_otherInfo(alert)

                technical=technical_description(site_name, host, port, ssl, language, otherInfo)
                
                '''-----------------------------------------------------------------'''
                # Verifica che current_user e current_project abbiano gli ID validi
                user_id = current_user['id']
                project_id = current_project['id']

                if not user_id or not project_id:
                    print("Errore: ID utente o progetto non valido!")
                    continue
                
                services = create_services_dict(port_id, hostname_id)
                print(services)
                print(f"vulnerability_name: {vulnerability_name} \n, cwe: {cwe}\n, desc: {desc}\n, solution: {solution}\n, confidence: {confidence}\n, references: {references}\n, technical: {technical}\n, services: {services}\n, filename: {filename}\n, user_id: {user_id}\n, project_id: {project_id}")
                issue_id = db.insert_new_issue_no_dublicate(
                    f"{vulnerability_name} - {filename} Imported",
                    desc,
                    url_path="",
                    cvss=0,
                    user_id=user_id,
                    services=services,
                    status='Need to check',
                    project_id=project_id,
                    cwe=cwe,
                    issue_type='custom',
                    fix=solution,
                    technical=technical,
                    risks=confidenceRisk_toText(risk,confidence),
                    references=references
                    )
                
                '''
                self, name, description, url_path, cvss, user_id,
                         services, status, project_id, cve='', cwe=0,
                         issue_type='custom', fix='', param='', fields={},
                         technical='', risks='', references='', intruder=''):
                '''
                print(f"📌 Salvato nel DB con issue_id: {issue_id}")
                print("-" * 40)

        except Exception as e:
            logging.error(f"Errore durante l'importazione del file: {e}", exc_info=True)
            return "Uno dei file è corrotto!"

    return ""
'''
{
  "issues": [
    {
      "name": "SSRF",
      "fields": {
        "nessus_id": {
          "type": "number",
          "val": 1337
        }
      }
    }
  ]
}
'''
