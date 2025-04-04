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

    json_files = input_dict['json_files']
    if not json_files:
        return "Nessun file JSON ricevuto!"
    
    for file_bin_content in input_dict['json_files']:
        file_content = file_bin_content.decode('charmap')
        try:
            json_content = json.loads(file_content)
            with open(Config.JSON_EVENTS, "r", encoding="utf-8") as f:
                event_content = json.loads(f.read())
            for entry in json_content:
                host = entry['scan_target']
                event_type = entry['event_type']
                
                if event_type in event_content['Domain']:
                    print(f"Event type {event_type} is in event_content['Domain']: {event_content['Domain']}")
                else:
                    print(f"Event type {event_type} is NOT in event_content['Domain']: {event_content['Domain']}")
                    break

                module = entry['module']
                source_data = entry['source_data']
                false_positive = entry['false_positive']
                last_seen = entry['last_seen']
                scan_name = entry['scan_name']
                data = entry['data']
                ip_obj = None 
                port = None # la porta in questo caso non viene gestita
               
                if host:
                    try:
                        #Prende scan_target come host
                        ipaddress.ip_address(host)
                        ip_obj = socket.gethostbyname(host)
                        is_ip = True
                    except ValueError:
                        is_ip = False
                        
                #se l'ip non esiste salto al prossimo entry
                if is_ip == False:
                    continue    
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

        except Exception as e:
            logging.error(e)
            return 'One of files was corrupted!'
    
    
    return ""
