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

import socket
import json
import os
import base64

class Config:
    """Configurazione percorsi risorse plugin"""
    JSON_EVENTS = os.path.join(os.getcwd(), "routes/ui/tools_addons/import_plugins/spiderfootScan/event_type.json")
def split_ip_port(address: str):
    """
    Separa l'indirizzo IP dalla porta, se presente.
    Supporta:
      - IPv4 con formato "192.168.1.1:8080"
      - IPv6 con formato "[2001:db8::1]:8080"
      - IPv6 senza porta, esempio "2404:6800:4003:c00::1a"
    Se non è presente la porta, restituisce (indirizzo, None).
    """
    # Gestione degli indirizzi IPv6 con porta, nel formato [IPv6]:porta
    if address.startswith('['):
        closing_bracket = address.find(']')
        if closing_bracket != -1:
            ip = address[1:closing_bracket]
            # Controlla se c'è la porta dopo il bracket
            rest = address[closing_bracket+1:]
            if rest.startswith(':'):
                port = rest[1:]
            else:
                port = None
            return ip, port

    # Se l'intera stringa è un indirizzo valido (IPv4 o IPv6), restituiscilo senza porta
    try:
        import ipaddress
        ipaddress.ip_address(address)  # Se non solleva eccezione, l'indirizzo è valido
        return address, None
    except ValueError:
        pass  # L'indirizzo non è interamente valido, potrebbe contenere anche la porta

    # Per gli indirizzi IPv4 con porta (e casi non validi come IPv6 senza parentesi quadre)
    if ':' in address:
        parts = address.rsplit(':', 1)
        if len(parts) == 2 and parts[1].isdigit():
            ip, port = parts
            return ip, port

    # Nessuna porta specificata
    return address, None

def create_services_dict(port_id, hostname_id):
    """
    Crea un dizionario services nel formato:
    { idPort: [ "[\"0\",\"idHostname\"]" ] }

    Dove:
      - idService è il pcf_port_id
      - "0" indica che non c'è una porta associata (solo IP)
      - idHostname è il pcf_hostname_id
    """
    
    # Costruisce il dizionario invece di una stringa formattata
    inner_value = ["0", str(hostname_id)]   # La lista invece della stringa
    return { port_id: inner_value }

def update_services_dict(port_id, hostname_id, old_services):
    """
    Aggiorna la mappatura servizi mantenendo lo storico
    {idPort: [ "0", "idHostname1", "idHostname2", ... ]}
    
    Args:
        port_id (str): UUID della porta
        hostname_id (str): UUID dell'hostname
        old_services (dict/str): Servizi esistenti (dict o JSON string)
    
    Returns:
        dict: Dizionario aggiornato con la nuova relazione
    
    Note:
        - Aggiunge "0" come placeholder se non esiste la porta
        - Previene duplicati negli hostname
        
    Esempio di come possono essere aggiornati i services:
    {
        "bc4467dc-5e83-470e-8a19-ff05e85ee13f": ["0", "076a64a2-6e66-49d0-8624-19ff36a886c2"], 
        "a0072228-a8d7-4fb1-b873-f5266147f8a6": ["0"], 
        "8b088405-b5fb-44b2-8fea-f84c82585337": ["0", "5b0b7655-7f33-4f2e-a8bc-d672d570a8c6", "312e8275-53c2-4b15-825d-787b744ba67f", "4ae05a9f-ad8a-4744-9940-821c2a912d45"]
    }
    """
    # Conversione a dizionario
    if isinstance(old_services, str):
        try:
            old_services = json.loads(old_services)
        except json.JSONDecodeError:
            old_services = {}

    port_key = str(port_id)
    host_id = str(hostname_id)
    
    # Inizializzazione struttura
    if not isinstance(old_services, dict):
        old_services = {}

    # Crea entry per la porta se non esiste
    if port_key not in old_services:
        old_services[port_key] = ["0"]  # Inizializza con elemento "0"

    # Estrae gli UUID esistenti per la porta corrente (escludendo lo "0")
    existing_uuids = old_services[port_key][1:]

    # Controlla se l'hostname_id è già presente
    if host_id not in existing_uuids:
        old_services[port_key].append(host_id)
    return old_services
def split_data(data: str) -> list:
    """
    Suddivide la stringa WHOIS in righe pulite, rimuovendo spazi superflui
    e tutti i caratteri '%' da ogni riga.
    
    Args:
        data (str): Stringa grezza dal campo 'data'.
    
    Returns:
        list: Lista di stringhe formattate.
    """
    lines = data.strip().split('\r\n')

    cleaned_lines = []
    for line in lines:
        line = line.strip().replace('%', '')
        if line:  # Ignora righe vuote dopo la pulizia
            cleaned_lines.append(line)

    return cleaned_lines
def get_poc_string(entry):
    """
    Genera una stringa di Proof of Concept formattata con tutti i dettagli dell'entry
    
    Args:
        entry (dict): Dizionario contenente i dettagli della rilevazione
    
    Returns:
        str: Stringa formattata con tutti i campi dell'entry
    """
    data = entry['data']
    event_type = entry['event_type']
    module = entry['module']
    source_data = entry['source_data']
    false_positive = entry['false_positive']
    last_seen = entry['last_seen']
    scan_name = entry['scan_name']
    scan_target = entry['scan_target']
    
    poc_string= []
    if data: poc_string.append(f"Data: {data}")
    if event_type: poc_string.append(f"Event Type: {event_type}")
    if module: poc_string.append(f"Module: {module}")
    if source_data: poc_string.append(f"Source Data: {source_data}")
    if false_positive: poc_string.append(f"False Positive: {false_positive}")
    if last_seen: poc_string.append(f"Last Seen: {last_seen}")
    if scan_name: poc_string.append(f"Scan Name: {scan_name}")
    if scan_target: poc_string.append(f"Scan Target: {scan_target}")
    poc_string.append("-"*40)
    poc_string = "\n".join(poc_string)
    return poc_string
def is_event_in_subcategory(event: str, subcategory: str, categories: dict) -> bool:
    """
    Controlla se l'evento 'event' è presente nella sottocategoria 'subcategory'
    all'interno del dizionario 'categories'.
    
    Args:
        event (str): il nome dell'evento da cercare.
        subcategory (str): la chiave della sottocategoria da controllare (es. "dns", "domain", ecc.).
        categories (dict): dizionario con le sottocategorie ed i loro eventi.
        
    Returns:
        bool: True se l'evento è presente nella sottocategoria, False altrimenti.
    """
    # Recupera la lista degli eventi per la sottocategoria data
    events_list = categories.get(subcategory)
    
    # Se la sottocategoria esiste e l'evento è al suo interno, ritorna True
    return events_list is not None and event in events_list
def add_newline_for_capitalized(data):
    # Trova fino a 4 parole con la maiuscola iniziale seguite da ":"
    def add_newline(match):
        return '\n' + match.group(0)
    
    # Regex per cercare fino a 4 parole con la maiuscola iniziale seguite da ":"
    modified_data = re.sub(r'(\b[A-Z][a-zA-Z]*\b)(?:\s+\b[A-Z][a-zA-Z]*\b){0,3}:', add_newline, data)
    
    return modified_data
def clean_string(text):
    # Rimuovi parentesi quadre, virgolette, apici e altri caratteri inutili, va a capo con "IN MX", "IN NS", "IN TXT", "+" e stringhe tipo "Registrant Postal Code:"(fino a 4 parole, vedi add_newline_for_capitalized)
    cleaned = text.replace('[', '').replace(']', '').replace('"', '').replace("'", "").replace("\n", "").replace("\n", "").replace("\\n", "").replace("IN MX", " \n ").replace("IN NS", " \n ").replace("IN TXT", " \n ").replace("Data:","\nData:").replace("+","\n+")
    cleaned = add_newline_for_capitalized(cleaned)
    
    # Rimuove eventuali spazi extra alla fine della stringa
    #cleaned = cleaned.strip()
    return cleaned
def format_event_data(event_data):
    """
    Formatta i dati degli eventi in una stringa leggibile.
    """
    event_data = clean_string(event_data)
    if type(event_data) == list:
        event_data = ' '.join(event_data)  # Unisce gli elementi della lista in una stringa
    
    events = event_data.split("Event type:")
    
    formatted_data = ""
    
    for event in events:
        if event.strip():  # Se non è una stringa vuota
            event_lines = event.strip().split('\n')
            event_type = event_lines[0].strip()
            event_info = "\n".join([line.strip() for line in event_lines[1:] if line.strip()])
            formatted_data += f"Event Type: {event_type}\n"
            formatted_data += f"\n{clean_string(event_info)}\n\n"
            formatted_data += "-" * 40 + "\n\n"

    
    return formatted_data.strip()
def get_cvss_score_from_event(event_name: str) -> float:
    mapping = {
        "VULNERABILITY_CVE_CRITICAL": 10.0,
        "VULNERABILITY_CVE_HIGH": 8.0,
        "VULNERABILITY_CVE_MEDIUM": 5.5,
        "VULNERABILITY_CVE_LOW": 3.0,
        "VULNERABILITY_GENERAL": 0.0,
        "VULNERABILITY_CVE_THIRD_PARTY_DISCLOSURE": 0.0,
        "VULNERABILITY_DISCLOSURE": 0.0
    }

    return mapping.get(event_name, 0.0)

# Route name and tools description
route_name = "spiderfootScan"
tools_description = [
    {
        "Icon file": "icon.png",
        "Icon URL": "",#### cambiare
        "Official name": "SpiderfootScan",
        "Short name": "spiderfootScan",
        "Description": "Remove unnecessary warnings from json report of spiderfoot",
        "URL": "",
        "Plugin author": "@alexfr3"
    }
]

####### Input arguments ########
# FlaskWTF forms
class ToolArguments(FlaskForm):
    json_files = MultipleFileField(
        label='json_files',
        description='.json reports',
        default=None,
        validators=[],
        _meta={"display_row": 1, "display_column": 1, "file_extensions": ".json"}
    )
    hosts_description = StringField(
            label='hosts_description',
            description='Host description',
            default='Added from SpiderfootScan',
            validators=[],
            _meta={"display_row": 1, "display_column": 2, "multiline": False}
        )
    
    hostnames_description = StringField(
        label='hostnames_description',
        description='Hostname description',
        default='Added from SpiderfootScan',
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

    json_files = input_dict['json_files']
    if not json_files:
        return "Nessun file JSON ricevuto!"
    
    for file_bin_content in input_dict['json_files']:
        file_content = file_bin_content.decode('charmap')
        try:
            json_content = json.loads(file_content)
            #creo un set di eventi dal json per controllare se gli eventi sono validi
            with open(Config.JSON_EVENTS, "r", encoding="utf-8") as f:
                event_structure = json.loads(f.read())
                flat_events = []
                for category in event_structure.values():
                    try:
                        for subcategory_events in category.values():
                            flat_events.extend(subcategory_events)
                    except AttributeError:
                        flat_events.extend(category)
                event_content_set = set(flat_events)
            vulnerability_events = event_structure.get("vulnerability", [])
            dns = []
            domain = []  
            ip = []  
            infrastructure = []  
            whois = []
            cloud = []
            provider = []
            accounts = []
            employees = []
            webEnum = []
            web = []
            certificates = []
            services = []
            vulnerability = []
            other = []
            domainOther = []
            blockchain = []
            name = ""

            for entry in json_content:
                event_type = entry['event_type']
                #controllo se l'evento è valido
                if event_type not in event_content_set:
                    logging.warning(f"Event type {event_type} not in event_content")
                    continue
                description = []
                host = entry['scan_target']
                ip_obj = None 
                port = None 
                note = [] 
                if name == "":
                    name = f"{event_type} "
                
                try:
                    if is_event_in_subcategory(event_type, "dns", event_structure):
                        if not dns:
                            dns.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        dns.append(f"{data}")
                    elif is_event_in_subcategory(event_type, "domain", event_structure):
                        if not domain:
                            domain.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        domain.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "ip", event_structure):
                        if not ip:
                            ip.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        ip.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "infrastructure", event_structure):
                        if not infrastructure:
                            infrastructure.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        infrastructure.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "whois", event_structure):
                        if not whois:
                            whois.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        whois.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "cloud", event_structure):
                        if not cloud:
                            cloud.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        cloud.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "provider", event_structure):
                        if not provider:
                            provider.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        provider.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "accounts", event_structure):
                        if not accounts:
                            accounts.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        accounts.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "employees", event_structure):
                        if not employees:
                            employees.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        employees.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "webEnum", event_structure):
                        if not webEnum:
                            webEnum.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        webEnum.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "web", event_structure):
                        if not web:
                            web.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        web.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "certificates", event_structure):
                        if not certificates:
                            certificates.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        certificates.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "services", event_structure):
                        if not services:
                            services.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        services.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "vulnerability", event_structure):
                        if not vulnerability:
                            vulnerability.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        vulnerability.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "other", event_structure):
                        if not other:
                            other.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        other.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "domainOther", event_structure):
                        if not domainOther:
                            domainOther.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        domainOther.append(f"{data}")

                    elif is_event_in_subcategory(event_type, "blockchain", event_structure):
                        if not blockchain:
                            blockchain.append(f"Event type: {event_type}")
                        data = split_data(entry['data'])
                        blockchain.append(f"{data}")

                        
                except Exception as e:
                    logging.error(f"Error: {str(e)}")
                    continue

                # Aggrega tutte le liste in una sola lista
                
                ip_obj = socket.gethostbyname(host)

                
                
                # Gestione porta - Se non fornita da spiderfoot  
                if port is None:
                    port = "0"
                '''-----------------------------------------------'''
                current_host = db.select_project_host_by_ip(
                        project_id=current_project['id'],
                        ip=str(ip_obj)
                )
                #gestione host e hostname
                
                try:
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
                except Exception as e:
                    logging.error(f"Errore nella selezione dell'host: {str(e)}")
                    return f"Errore nel recupero dell'host: {str(e)}"
                
                hostname_id = "0"
                if host:
                    current_hostname = db.select_ip_hostname(host_id, host)
                    if current_hostname:
                        hostname_id = current_hostname[0]['id']
                    else:   
                        hostname_id = db.insert_hostname(host_id, host,
                                                        input_dict['hosts_description'],
                                                        current_user['id'])
                '''--------------------------------------------------------'''
                is_tcp = True
                existing_port = db.select_host_port(host_id, port, is_tcp)
                if not existing_port:
                    db.insert_host_port(
                        host_id, 
                        port, 
                        is_tcp,
                        '', 
                        description=input_dict['hosts_description'], 
                        user_id=str(current_user['id']), 
                        project_id=str(current_project['id'])
                    )
                    

                
                existing_port = db.select_host_port(host_id, port, is_tcp)
               
                
                port_id = existing_port[0]['id']
                user_id = current_user['id']
                project_id = current_project['id']
                '''-----------------------------------------------------------------'''
                module = entry['module']
                source_data = entry['source_data']
                poc_string = get_poc_string(entry)
                if event_type in vulnerability_events:
                    issue_names = {}
                    for issue in db.select_project_issues(project_id):
                        # Aggiungo solo se il nome non è già presente
                        if issue['name'] not in issue_names:
                            issue_names[issue['name']] = issue  #issue_names[name] contiene un dizionario con tutti i dati
                    if name in issue_names:
                        issue_id = issue_names[name]['id']
                        old_services = issue_names[name]['services']

                        new_services = update_services_dict(
                            port_id, 
                            hostname_id,
                            old_services
                        )
                        # Aggiorna solo se ci sono modifiche
                        if new_services != old_services:
                            db.update_issue_services(issue_id, new_services)                        
                    else:
                        services = create_services_dict(port_id, hostname_id)
                        issue_id = db.insert_new_issue_no_dublicate(
                            name=name,
                            description="\n".join(description),
                            url_path="",
                            cvss=get_cvss_score_from_event(event_type),
                            user_id=user_id,
                            services=services,
                            status='Need to check',
                            project_id=project_id,
                            cwe=0,
                            issue_type='custom',
                            fix="",
                            technical="technical",
                            risks="",
                            references=source_data
                            )
                    
                    poc = str(poc_string)
                    dati = poc.encode('utf-8')
                    pocs=db.select_issue_pocs(issue_id)
                    
                    if pocs:
                        # Se esiste già un PoC per l'issue, aggiorna il PoC esistente
                        poc_dati = pocs[0]['base64']  # è una stringa base64
                        decoded_poc = base64.b64decode(poc_dati).decode("utf-8")
                        if decoded_poc != poc:
                            db.insert_new_poc(port_id, "Descrizione","txt", "poc.txt", issue_id, user_id, hostname_id, 
                                    poc_id='random', storage='database', data=dati)
                    else:
                        db.insert_new_poc(port_id, "Descrizione","txt", "poc.txt", issue_id, user_id, hostname_id, 
                                    poc_id='random', storage='database', data=dati)
                    
            all_events_str = (str(dns) + str(domain) + str(ip) + str(infrastructure) + str(whois) +
                    str(cloud) + str(provider) + str(accounts) + str(employees) + str(webEnum) + str(web) +
                    str(certificates) + str(services) + str(vulnerability) +
                    str(other) + str(domainOther) + str(blockchain)
                )
            if all_events_str:
                #aggregated_string = "\n".join(all_events_str)
                
                formatted_data = format_event_data(all_events_str)
                name += "- SpiderfootScan" 
                #aggiungere il controllo per vedere se esiste già la nota
                db.insert_new_note(
                    project_id=str(current_project['id']),
                    name=name,
                    user_id=str(current_user['id']),
                    text=formatted_data,
                    note_type='plaintext'
                )
        except Exception as e:
            logging.error(e)
            return 'One of files was corrupted!'
    
    
    return ""
