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
import dns.resolver

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
def confidence_toText(confidence):
    if confidence == "0":
        return "Info"
    elif confidence == "1":
        return "Low"
    elif confidence == "2":
        return "Medium"
    elif confidence == "3":
        return "High"
    else:
        return confidence
    """Genera una descrizione tecnica basata su vari parametri"""
    technical_parts = []
    if site_name: technical_parts.append(f"Site: {site_name}")
    if host: technical_parts.append(f"Host: {host}")
    if port: technical_parts.append(f"Port: {port}")
    if ssl: technical_parts.append(f"SSL: {ssl}")
    if language: technical_parts.append(f"Language: {language}")
    if otherInfo: technical_parts.append(f"OtherInfo: {otherInfo}")

    return "\n".join(technical_parts)
def resolve_dns(domain):
    # Se l'host è un oggetto IPv4Address, restituisci direttamente l'indirizzo
    if isinstance(domain, ipaddress.IPv4Address):
        return str(domain)
    
    try:
        result = dns.resolver.resolve(domain, 'A')  # 'A' per indirizzo IPv4
        for ipval in result:
            return ipval.to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        logging.error(f"Errore nella risoluzione del dominio {domain}: {e}")
        return None
def get_ip_address(host):
    if not host:
        logging.error("Host è None o vuoto.")
        return None
    
    # Controlla se l'host è "localhost"
    if host== "localhost":
        return ipaddress.ip_address("127.0.0.1")  # Restituisce l'IP per localhost

    ip = resolve_dns(host)
    if ip is None:
        logging.error(f"Impossibile risolvere l'IP per il dominio {host}")
        return None

    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        logging.error(f"IP non valido: {ip}")
        return None
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
def debugMsg(text):
    print("---------------------------------------")
    print("{text}")
    print("---------------------------------------")


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
    hostnames_file = StringField(
            label='hostnames_file',
            description='or take IPs from this field',
            default='127.0.0.1     vulnsite1.com,vulnsite2.com,subdomain.vulnsite2.com\n',
            validators=[],
            _meta={"display_row": 3, "display_column": 1, "multiline": True}
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

    xml_files = input_dict.get("xml_files", [])
    if not xml_files:
        return "Nessun file XML ricevuto!"
    
    xsd_file = os.path.join(os.getcwd(), "routes/ui/tools_addons/import_plugins/reducer/zap.xsd")
    for bin_data in xml_files:
        try:
            if not bin_data:
                continue  # Evita file vuoti

            # Decodifica con UTF-8
            xml_data = bin_data.decode("utf-8")
            print("📂 File XML ricevuto!")
            # Valida XML rispetto allo schema XSD (attivare se necessario)
            if not validate_xml(xml_data, xsd_file):
                return "XML validation failed!"

            # Analizza l'XML con BeautifulSoup
            soup = BeautifulSoup(xml_data, "xml")

            # Estrai dati del sito
            site = soup.find("site")
            if not site:
                print("Nessun <site> trovato nell'XML!")
                continue
            
            site_name = site.get("name", "Unknown")
            host = site.get("host", "Unknown")
            port = site.get("port", "Unknown")
            ssl = site.get("ssl", "Unknown")

            '''-----------------------------------------------------------------'''
            ip_obj = get_ip_address(host)
            print(f"📌 IP: {ip_obj}")
            try:
                print("--------------------------------------------------------")
                print(f"📌 current_project:{current_project['id']}")
                current_host = db.select_project_host_by_ip(current_project['id'], str(get_ip_address(ip_obj)))

                if current_host:  # Verifica che non sia una lista vuota
                    current_host = current_host[0]
                    host_id = current_host['id']
                    print(f"📌 Host trovato: {host_id}")
                else:
                    print("❌ Nessun host trovato, lo inserisco nel DB")
                    host_id = db.insert_host(current_project['id'], 
                                             str(get_ip_address(ip_obj)), 
                                             current_user['id'], 
                                             "Host aggiunto dall'analisi XML di ZAP")
                    
                    # Dopo l'inserimento, seleziona di nuovo l'host
                    current_host = db.select_host(host_id)
                    
                    if current_host:
                        print("✅ Host confermato nel DB")
                    else:
                        logging.error(f"❌ ERRORE: Host con ID {host_id} non trovato!")
                        return f"Errore: Host non trovato dopo l'inserimento."


            except Exception as e:
                logging.error(f"🚨 Errore nella selezione dell'host: {str(e)}")
                return f"Errore nel recupero dell'host: {str(e)}"
            '''-----------------------------------------------------------------''' 
            # gestione hostname
            hostname_id = db.select_ip_hostname(host_id, host)
            print("-" * 40)
            if not hostname_id:
                print("Hostname non trovato, lo inserisco nel DB......")
                # Usa get per evitare KeyError
                hosts_description = input_dict.get("hosts_description", "Added from Reducer")
                hostname_id = db.insert_hostname(host_id, host, hosts_description, current_user['id'])
            else:
                print(f"Hostname trovato: {hostname_id[0]['id']}")
                hostname_id = hostname_id[0]['id']

            # Gestione porta
            try:
                port = int(site.get("port", "0"))
            except ValueError:
                logging.error(f"Porta non valida: {site.get('port')}")
                return f"Porta non valida: {site.get('port')}"

            # Aggiungi logica per determinare TCP o UDP se applicabile
            is_tcp = True  # Impostazione di default
            if port != 0:
                is_tcp = True  # o verifica se è TCP/UDP se il dato è disponibile

            # Verifica se la porta esiste nel DB
            print("Verifica se la porta esiste nel DB")
            print("-----------------------------------------------------------------")
            print(f"current_host: {current_host} (type: {type(current_host)})")
            print("-----------------------------------------------------------------")
            if not db.select_host_port(str(ip_obj), port, 1 if is_tcp else 0):
                ######se porta non esiste, inseriscila
                print("Inserisco la porta, current_user['id']: " + str(current_user['id']))
                print("Inserisco la porta, port: " + str(port))
                print("Inserisco la porta, is_tcp: " + str(is_tcp))
                print("Inserisco la porta, "+ str(current_project['id']))
                print("Inserisco la porta, "+ str(ip_obj))
                db.insert_host_port(
                    str(ip_obj), 
                    port, 1, 
                    "input_dict[]", 
                    "Porta rilevata dall'analisi XML di ZAP", 
                    str(current_user['id']), 
                    str(current_project['id'])
                )
                print("Porta inserita con successo")
            ############################
            '''La porta non viene visualizzata in pcf, solo nel db'''
            ############################
            print("Porta non inserita, esiste già: " + str(db.select_host_port(str(ip_obj), port, 1 if is_tcp else 0)))
            print(db.check_port_in_project(current_project['id'], port))
            # Analizza gli alert di vulnerabilità
            alert_items = soup.find_all("alertitem")
            if not alert_items:
                print("Nessun alert trovato.")
                continue

            # All'interno del ciclo per ogni alert
            for alert in alert_items:
                vulnerability_name = alert.find("name").text.strip()
                cvss=int(alert.find("riskcode").text.strip())
                
                #print(f"Vulnerabilità: {vulnerability_name if vulnerability_name else 'N/A'} | CVSS: {cvss if cvss else 'N/A'} | Confidence: {confidence if confidence else 'N/A'}")
                #Validazione dell'IP
               

                # Estrai tutte le istanze della vulnerabilità
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
                
                otherInfo_items = alert.find_all("otherinfo")

                # Crea una lista di testi, aggiungendo il newline dopo ogni frase
                seen_phrases = set()
                # Crea una lista di testi, aggiungendo il newline dopo ogni frase, senza bisogno di controllare duplicati
                otherInfo_cleaned = [
                    split_sentences_safely(otherInfo.get_text(strip=True))
                    for otherInfo in otherInfo_items
                    if (otherInfo_text := otherInfo.get_text(strip=True)) and otherInfo_text not in seen_phrases and not seen_phrases.add(otherInfo_text)#utilizzando set per evitare duplicati
                ]
                # Unisci il testo dei <otherinfo> separato da \n
                otherInfo_complete = '\n'.join(otherInfo_cleaned)
                otherInfo = clean_html_entities(otherInfo_complete)

                technical=technical_description(site_name, host, port, ssl, language, otherInfo)
                
                '''-----------------------------------------------------------------'''
                # Verifica che current_user e current_project abbiano gli ID validi
                user_id = current_user.get('id')
                project_id = current_project.get('id')

                if not user_id or not project_id:
                    print("Errore: ID utente o progetto non valido!")
                    continue
                # Salvataggio issue nel db
                issue_id = db.insert_new_issue(
                    vulnerability_name,
                    f"{desc}\n"+ "",
                    filename,
                    cvss,
                    user_id,
                    {},
                    'need to check',
                    project_id,
                    cwe=cwe,
                    issue_type='custom',
                    fix=solution,
                    technical=technical,
                    risks=confidence_toText(confidence),
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
