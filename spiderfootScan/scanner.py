import os
import ast
import re

def extract_produced_events_function(file_path):
    """Legge un file Python e estrae il contenuto tra parentesi quadre della funzione producedEvents(self)."""
    with open(file_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=file_path)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "producedEvents":
            # Estrai il codice della funzione
            function_code = ast.get_source_segment(open(file_path, "r", encoding="utf-8").read(), node)
            if function_code:
                # Trova il contenuto tra parentesi quadre
                matches = re.findall(r"\[(.*?)\]", function_code, re.DOTALL)
                extracted_items = []
                for match in matches:
                    extracted_items.extend(item.strip() for item in match.split(","))  # Divide per virgola e rimuove spazi
                return extracted_items
    return None

def scan_directory(directory):
    """Scansiona tutti i file .py nella cartella e cerca la funzione producedEvents(self)."""
    extracted_data = {}
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                extracted_content = extract_produced_events_function(file_path)
                if extracted_content:
                    extracted_data[file_path] = extracted_content

    return extracted_data

# Imposta la directory di scansione (cambia con il tuo percorso)
directory_path = "."

# Scansiona la cartella e stampa i risultati con ogni evento su una riga separata
results = scan_directory(directory_path)
for file, events in results.items():
    for event in events:
        print(event)
