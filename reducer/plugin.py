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
import json
class Config:
    XSD_PATH = os.path.join(os.getcwd(), "routes/ui/tools_addons/import_plugins/reducer/zap.xsd")
def extract_services(s):
    # Trova l'indice del primo ":" e dell'ultima "}"
    start = s.find(':')
    end = s.rfind('}')
    if start == -1 or end == -1:
        return None
    # Estrae la parte compresa tra i due
    result = s[start+1:end].strip()
    return result
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
    """Rimuove entità HTML e formatta il testo in modo pulito."""
    # Decodifica entità HTML (es: &amp; -> &)
    text = BeautifulSoup(text, "html.parser").get_text()
    
    # Rimuovi spazi multipli e newline inconsistenti
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Ripristina newline logici dopo punti
    text = re.sub(r'(?<!\d)\.(\s+)', '.\n', text)

    return text
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
def extract_ips(text):
    """Trova tutti gli indirizzi IP validi all'interno del testo."""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b')  # Gestisce IP con e senza porta
    found_ips = set()

    for match in ip_pattern.findall(text):
        try:
            ip = ipaddress.ip_address(match.split(":")[0])  # Separa eventuali porte
            found_ips.add(match)
        except ValueError:
            pass  # Ignora se non è un IP valido

    return found_ips

def split_sentences_safely(text):
    """Divide il testo in frasi senza spezzare IP, abbreviazioni o nomi di dominio."""
    if not text:
        return ""

    # Mantieni abbreviazioni comuni e previeni la separazione di IP
    abbreviations = {"e.g.", "i.e.", "etc.", "vs.", "Mr.", "Dr."}
    
    # Usa regex per trovare i punti che separano le frasi (evitando numeri e abbreviazioni)
    sentence_endings = re.finditer(r'(?<!\d)\. (?=[A-Z])', text)

    sentences = []
    last_index = 0

    for match in sentence_endings:
        end = match.end() - 1
        sentence = text[last_index:end].strip()

        # Controlla che la "frase" non sia un'abbreviazione o un IP
        if sentence not in abbreviations and not re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', sentence):
            sentences.append(sentence)
            last_index = match.end()

    # Aggiungi l'ultima parte del testo
    final_sentence = text[last_index:].strip()
    if final_sentence:
        sentences.append(final_sentence)

    return "\n".join(sentences)

def get_otherInfo(alert):
    """Estrae e formatta il contenuto di <otherinfo>, rimuovendo duplicati e gestendo gli IP."""
    otherInfo_items = alert.find_all("otherinfo")

    unique_sentences = set()
    ordered_sentences = []
    ip_addresses = set()

    for item in otherInfo_items:
        text = item.get_text(" ", strip=True) if item else ""
        text = clean_html_entities(text) if text else ""

        if not text:
            continue

        # Estrai gli IP prima di pulire il testo
        ip_addresses.update(extract_ips(text))

        sentences = split_sentences_safely(text).split("\n") if text else []

        for sentence in sentences:
            sentence_clean = sentence.strip()
            if sentence_clean and sentence_clean.lower() not in unique_sentences:
                unique_sentences.add(sentence_clean.lower())
                ordered_sentences.append(sentence_clean)

    if ip_addresses:
        ordered_sentences.append("\nIP rilevati:")
        ordered_sentences.extend(sorted(ip_addresses))

    return "\n".join(ordered_sentences) if ordered_sentences else ""

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
    current_host = db.select_host(host_id)  
    if current_host:
        print("Host confermato nel DB")
    else:
        logging.error(f"ERRORE: Host con ID {host_id} non trovato!")
        return f"Errore: Host non trovato dopo l'inserimento."
    return
def replace_single_quotes_with_double(input_str):
    """Converte gli apici singoli in doppi in una stringa JSON"""
    try:
        # Prima converte in dizionario
        data = json.loads(input_str.replace("'", '"'))
        # Poi riserializza correttamente
        return json.dumps(data)
    except Exception as e:
        logging.error(f"Error converting quotes: {str(e)}")
        return input_str
def extract_services(input_string):
    # Trova tutto ciò che è tra parentesi graffe
    match = re.search(r'\{(.*)\}', input_string)
    if match:
        return [match.group(1).strip()]  # Restituisce il contenuto dentro le parentesi graffe come lista
    else:
        return []  # Restituisce una lista vuota se non trova parentesi graffe
    
def create_services_dict(pcf_port_id, pcf_hostname_id, issue_id=None, project_id=None, db=None, old_services=None):
    """
    Crea un dizionario services nel formato:
    { idPort: [ "[\"0\",\"idHostname\"]" ] }

    Dove:
      - idService è il pcf_port_id
      - "0" indica che non c'è una porta associata (solo IP)
      - idHostname è il pcf_hostname_id
    """
    
    # Costruisce il dizionario invece di una stringa formattata
    inner_value = ["0", str(pcf_hostname_id)]   # La lista invece della stringa
    return { pcf_port_id: inner_value }
'''
    {"bc4467dc-5e83-470e-8a19-ff05e85ee13f": ["0", "076a64a2-6e66-49d0-8624-19ff36a886c2"], 
 "a0072228-a8d7-4fb1-b873-f5266147f8a6": ["0"], 
 "1996cccf-cabd-454a-aba6-610a54446fd3": ["0", "076a64a2-6e66-49d0-8624-19ff36a886c2"], 
 "6e048d95-10ca-4050-b4a9-0c5bb6b26c1f": ["0", "761ea5ae-864a-4a4e-a425-79bdd2952164"], 
 "ccd8a8e2-1e3d-4636-b853-6cadedfeb1e6": ["0", "761ea5ae-864a-4a4e-a425-79bdd2952164"]}
{"8b088405-b5fb-44b2-8fea-f84c82585337": ["0", "5b0b7655-7f33-4f2e-a8bc-d672d570a8c6", "312e8275-53c2-4b15-825d-787b744ba67f", "4ae05a9f-ad8a-4744-9940-821c2a912d45"]}
per più hostnames
    '''
def update_services_dict(pcf_port_id, pcf_hostname_id, old_services):
    """Aggiorna i services esistenti mantenendo la struttura corretta"""
    # Converti old_services in dizionario se è una stringa JSON
    if isinstance(old_services, str):
        try:
            old_services = json.loads(old_services)
        except json.JSONDecodeError:
            old_services = {}

    # Converti pcf_port_id a stringa
    port_key = str(pcf_port_id)
    new_entry = ["0", str(pcf_hostname_id)]

    # Inizializza la struttura se non esiste
    if not isinstance(old_services, dict):
        old_services = {}

    # Crea la lista per la porta se non esiste
    if port_key not in old_services:
        print(f"Creazione nuova entry per porta {port_key}")
        old_services[port_key] = []

    # Aggiungi il nuovo hostname solo se non esiste già
    if new_entry not in old_services[port_key]:
        print(f"Aggiunta nuovo hostname {new_entry} alla porta {port_key}")
        old_services[port_key].append(new_entry)
    else:
        print(f"Hostname {new_entry} già presente per la porta {port_key}")

    return old_services
def get_poc_string(alert):
    """Crea una stringa formattata per il PoC"""
    instances = alert.find_all("instance")
    all_instances = []
    if instances:
        for instance in instances:
            uri = instance.find("uri").text.strip()
            method = instance.find("method").text.strip()
            evidence = instance.find("evidence").text.strip()
            param = instance.find("param").text.strip()
            attack = instance.find("attack").text.strip()
            all_instances.append(f"{method} {uri}")
            if param: all_instances.append(f"- param: {param}")
            if attack: all_instances.append(f"- attack: {attack}")
            if evidence: all_instances.append(f"- PoC: {evidence}")
            all_instances.append("-"*40)
    all_instances_str = "\n".join(all_instances) if all_instances else "Nessuna evidenza trovata"
    return all_instances_str

         
# Route name and tools description
route_name = "reducer"
tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "https://i.ibb.co/DVWwGcS/redcheck.png",#### cambiare
        "Official name": "Reducer",
        "Short name": "reducer",
        "Description": "Remove unnecessary warnings",
        "URL": "",
        "Plugin author": "@alexfr3"
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
    '''Posso rimuoverlo? Non lo metti a mano l'indirizzo ip
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
    '''
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
    
    xsd_file = os.path.join(os.getcwd(), Config.XSD_PATH)
    
    for bin_data in xml_files:
        try:
            if not bin_data:
                continue  # Evita file vuoti

            xml_data = bin_data.decode("utf-8")
            print("File XML ricevuto!")

            if not validate_xml(xml_data, xsd_file):
                return "XML validation failed!"
            
            soup, site, site_name, host, port, ssl = getDataSoup(xml_data)
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

            ip_obj = socket.gethostbyname(host)
            print(f"IP: {ip_obj}")
            
            try:
                print("--------------------------------------------------------")
                print(f"current_project:{current_project['id']}")
                
                current_host = db.select_project_host_by_ip(
                    project_id=current_project['id'],
                    ip=str(ip_obj)
                )
                
                if current_host:  
                    current_host = current_host[0]
                    host_id = current_host['id']
                else:  
                    host_id = db.insert_host(
                        project_id=current_project['id'], 
                        ip=str(ip_obj), 
                        user_id=current_user['id'],
                        comment=input_dict['hosts_description'],
                        threats=[],  
                        os=''        
                    )
                    print(f"Host: {host_id}")
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
            
            """
            Impostazione di default perchè con ZAP il protocollo è sempre tcp
            """
            is_tcp = True

            # Verifica se la porta esiste nel DB
            print("-" * 40)
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
                

            
            existing_port = db.select_host_port(host_id, port, is_tcp)
            print(f"Porta: {existing_port}")
            print("-" * 40)
            
            port_id = existing_port[0]['id']
            web_dict = {
                'pcf_port_id': port_id,
                'pcf_host_id': host_id,
                'pcf_hostname_id': pcf_hostname_id
            }
            '''
            print("*" * 40)
            print(f"PCF Port ID: {web_dict['pcf_port_id']}")
            print(f"PCF Host ID: {web_dict['pcf_host_id']}")
            print(f"PCF Hostname ID: {web_dict['pcf_hostname_id']}")
            print("*" * 40)
            '''
            '''-----------------------------------------------------------------'''
            """
             Estrai tutte le istanze della vulnerabilità
             Analizza gli alert di vulnerabilità
            """
            alert_items = soup.find_all("alertitem")
            if not alert_items:
                print("Nessun alert trovato.")
                continue
            # All'interno del ciclo per ogni alert
            for alert in alert_items:
                vulnerability_name = alert.find("name").text.strip()
                risk=int(alert.find("riskcode").text.strip())
                                
                '''-----------------------------------------------------------------'''
                '''Valori per il DB'''
                poc_string=get_poc_string(alert)
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
                '''-----------------------------------------------------------------'''
                #search_issues_port_ids,select_project_issues,join_duplicate_issues
                name= f"{vulnerability_name} - {filename} Imported"
                issue_names = {}
                for issue in db.select_project_issues(project_id):
                    # Aggiungi solo se il nome non è già presente
                    if issue['name'] not in issue_names:
                        issue_names[issue['name']] = issue  # Ora issue_names[name] conterrà un dizionario con tutti i dati
                # Nel blocco dove verifichi se l'issue esiste già
                # Nel blocco dove verifichi se l'issue esiste già
                if name in issue_names:
                    issue_id = issue_names[name]['id']
                    old_services = issue_names[name]['services']
                    print("Old services in if: "+str(old_services))
                    print(f"L'errore : {name} ; esiste già con ID: {issue_id}")
                    print("*" * 40)
                    # Converti manualmente se necessario
                    new_services = update_services_dict(
                        port_id, 
                        hostname_id,
                        old_services
                    )
                    print("New services creati: "+str(new_services))
                    # Aggiorna solo se ci sono modifiche
                    if new_services != old_services:
                        print("AGGIORNAMENTO SERVIZI")
                        print("Update services: "+str(new_services))
                        print("*" * 40)
                        #db.update_issue_services(issue_id, new_services)
                        print("FINE AGGIORNAMENTO SERVIZI")
                else:
                    services = create_services_dict(port_id, hostname_id)
                    #print(services)
                    issue_id = db.insert_new_issue_no_dublicate(
                        name,
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
                
                poc = str(poc_string)
                dati = poc.encode('utf-8')
                db.insert_new_poc(port_id, "Descrizione","txt", "poc.txt", issue_id, user_id, hostname_id, 
                                  poc_id='random', storage='database', data=dati)
                
                
        except Exception as e:
            logging.error(f"Errore durante l'importazione del file: {e}", exc_info=True)
            return "Uno dei file è corrotto!"
    return ""
''' Esempio di services
{"bc4467dc-5e83-470e-8a19-ff05e85ee13f": ["0", "076a64a2-6e66-49d0-8624-19ff36a886c2"], 
 "a0072228-a8d7-4fb1-b873-f5266147f8a6": ["0"], 
 "1996cccf-cabd-454a-aba6-610a54446fd3": ["0", "076a64a2-6e66-49d0-8624-19ff36a886c2"], 
 "6e048d95-10ca-4050-b4a9-0c5bb6b26c1f": ["0", "761ea5ae-864a-4a4e-a425-79bdd2952164"], 
 "ccd8a8e2-1e3d-4636-b853-6cadedfeb1e6": ["0", "761ea5ae-864a-4a4e-a425-79bdd2952164"]}





Old services: {"d1ee8e73-0dd0-4e23-9d52-ff0642c070ec": ["0", "5be74ba7-bc54-47bf-9f60-1e0815539b39"]}
web-1  | L'errore : Configurazione errata multi dominio - ZAP Imported ; esiste già con ID: 835b45be-c7ed-458c-947d-2e3dd4e7fe62
web-1  | old_services prima di creare new_services : {"d1ee8e73-0dd0-4e23-9d52-ff0642c070ec": ["0", "5be74ba7-bc54-47bf-9f60-1e0815539b39"]}
web-1  | extracted_services: 
['"d1ee8e73-0dd0-4e23-9d52-ff0642c070ec": ["0", "5be74ba7-bc54-47bf-9f60-1e0815539b39"]', 
['0', '5be74ba7-bc54-47bf-9f60-1e0815539b39']]
web-1  | New services creati: ['"d1ee8e73-0dd0-4e23-9d52-ff0642c070ec": ["0", "5be74ba7-bc54-47bf-9f60-1e0815539b39"]', ['0', '5be74ba7-bc54-47bf-9f60-1e0815539b39']]
web-1  | Update services: ['"d1ee8e73-0dd0-4e23-9d52-ff0642c070ec": ["0", "5be74ba7-bc54-47bf-9f60-1e0815539b39"]', ['0', '5be74ba7-bc54-47bf-9f60-
'''
