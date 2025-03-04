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

def add_newlines_to_otherinfo(text):
    """Aggiunge newline tra le frasi di un testo, evitando duplicati"""
    # Split tra i punti che non sono parte di numeri o IP
    sentences = re.split(r'(?<!\d)\.(?!\d)', text)
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

    xml_files = input_dict.get("xml_files", [])
    if not xml_files:
        return "Nessun file XML ricevuto!"
    
    xsd_file = os.path.join(os.getcwd(), "routes/ui/tools_addons/import_plugins/reducer/new.xsd")
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

            #print(f"🌐 Sito: {site_name} | 🏠 Host: {host} | 🔌 Porta: {port} | 🔒 SSL: {ssl}")
            #print("-" * 40)
            '''-----------------------------------------------------------------'''

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
                language = report.get("language", "Unknown")
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
                    add_newlines_to_otherinfo(otherInfo.get_text(strip=True))
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
