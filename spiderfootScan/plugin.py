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
class Config:
    """Configurazione percorsi risorse plugin"""
    JSON_EVENTS = os.path.join(os.getcwd(), "routes/ui/tools_addons/import_plugins/spiderfootScan/event_type.json")
def split_ip_port(address: str):
    """
    Separa l'indirizzo IP dalla porta, se presente.
    Supporta:
      - IPv4 con formato "192.168.1.1:8080"
      - IPv6 con formato "[2001:db8::1]:8080"
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

    # Per gli indirizzi IPv4 o IPv6 senza parentesi quadre
    # Se c'è almeno un ':' e l'ultima parte è numerica, supponiamo che sia la porta
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
        print(f"Creazione di nuova entry per la porta : {port_key}")
        old_services[port_key] = ["0"]  # Inizializza con elemento "0"

    # Estrae gli UUID esistenti per la porta corrente (escludendo lo "0")
    existing_uuids = old_services[port_key][1:]

    # Controlla se l'hostname_id è già presente
    if host_id not in existing_uuids:
        print(f"Aggiunta nuovo hostname {host_id} alla porta {port_key}")
        old_services[port_key].append(host_id)
    else:
        print(f"Hostname {host_id} già presente per la porta {port_key}")

    return old_services
def split_data(data: str) -> list:
    """
    Suddivide la stringa WHOIS in righe pulite, rimuovendo spazi superflui e separatori.
    
    Args:
        data (str): Stringa grezza dal campo 'data' (es. "Domain Name: 1E100.NET\r\nRegistry...")
    
    Returns:
        list: Lista di stringhe formattate (es. ["Domain Name: 1E100.NET", "Registry Domain ID: ..."])
    """
    # Split iniziale sulle nuove righe
    lines = data.strip().split('\r\n')
    
    # Pulizia: rimuove spazi iniziali/finali e filtra righe vuote
    cleaned_lines = [
        line.strip()
        for line in lines
        if line.strip()  # Ignora righe vuote dopo lo strip
    ]
    
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
    
    return (
        f"Module: {module}\n"
        f"Data: {data}\n"
        f"Event Type: {event_type}\n"
        f"Source Data: {source_data}\n"
        f"False Positive: {false_positive}\n"
        f"Last Seen: {last_seen}\n"
        f"Scan Name: {scan_name}\n"
        f"Scan Target: {scan_target}"
    )
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
            
            listOfIP=[]
            for entry in json_content:
                event_type = entry['event_type']
                #controllo se l'evento è valido
                if event_type not in event_content_set:
                    logging.warning(f"Event type {event_type} not in event_content")
                    continue
                description = []
                last_seen = entry['last_seen']
                print(f"Last seen: {last_seen}")
                description.append(f"Type of event: {event_type}\n" + f"Last_seen: {last_seen}\n" )
                host=None
                ip_obj = None 
                port = None 
                try:
                    if event_type == "IP_ADDRESS":
                        ip_obj,port = split_ip_port(entry['data'])
                        host=entry['source_data']
                    else:
                        ip_obj = socket.gethostbyname(entry['scan_target'])
                        port = None
                    if event_type == "AFFILIATE_DOMAIN_WHOIS":
                        data=split_data(entry['data'])
                        print("Data: "+str(data))
                        description.extend(data)
                except (ValueError, socket.gaierror) as e:
                    logging.error(f"IP error: {str(e)}")
                    continue

                if ip_obj not in listOfIP:
                    listOfIP.append(ip_obj)
                    print(f"IP: {ip_obj}")
                
                # Gestione porta - Se non fornita da spiderfoot  
                if port is None:
                    port = "0"
                print("-----------------------------------------------")
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
                        print(f"Host: {host_id}")
                except Exception as e:
                    logging.error(f"Errore nella selezione dell'host: {str(e)}")
                    return f"Errore nel recupero dell'host: {str(e)}"
                print(f"Host: {host_id}")
                
                hostname_id = "0"
                if host:
                    current_hostname = db.select_ip_hostname(host_id, host)
                    if current_hostname:
                        hostname_id = current_hostname[0]['id']
                    else:   
                        hostname_id = db.insert_hostname(host_id, host,
                                                        input_dict['hosts_description'],
                                                        current_user['id'])
                print("--------------------------------------------------------")
                is_tcp = True
                print("-" * 40)
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
                print(f"Porta: {existing_port}")
                print("-" * 40)
                
                port_id = existing_port[0]['id']
                user_id = current_user['id']
                project_id = current_project['id']
                '''-----------------------------------------------------------------'''
                module = entry['module']
                name = f"{module} - SpiderfootScan"
                source_data = entry['source_data']
                poc_string = get_poc_string(entry)
                
                issue_names = {}
                for issue in db.select_project_issues(project_id):
                    # Aggiungo solo se il nome non è già presente
                    if issue['name'] not in issue_names:
                        issue_names[issue['name']] = issue  #issue_names[name] contiene un dizionario con tutti i dati
                if name in issue_names:
                    issue_id = issue_names[name]['id']
                    old_services = issue_names[name]['services']
                    print("Old services in if: "+str(old_services))
                    print(f"L'errore : {name} ; esiste già con ID: {issue_id}")
                    print("*" * 40)

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
                        db.update_issue_services(issue_id, new_services)
                        print("FINE AGGIORNAMENTO SERVIZI")
                    print("*" * 40)
                    
                else:
                    services = create_services_dict(port_id, hostname_id)
                    #print(services)
                    issue_id = db.insert_new_issue_no_dublicate(
                        name=name,
                        description="\n".join(description),
                        url_path="",
                        cvss=0,
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
                db.insert_new_poc(port_id, "Descrizione","txt", "poc.txt", issue_id, user_id, hostname_id, 
                                  poc_id='random', storage='database', data=dati)
                
            print(listOfIP)
        except Exception as e:
            logging.error(e)
            return 'One of files was corrupted!'
    
    
    return ""
