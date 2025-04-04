import json
import os

print(os.getcwd())

# Carica il file JSON e crea un set di eventi (tutti in UPPERCASE e puliti)
with open("/Users/alexfrisoni/Downloads/event_type.json", "r", encoding="utf-8") as json_file:
    json_data = json.load(json_file)

json_events = set()
for category in json_data.values():
    for event in category:
        json_events.add(event.strip().upper())

# Carica il CSV e rimuove le virgolette da ogni riga
with open("/Users/alexfrisoni/Downloads/AllEvents.csv", "r", encoding="utf-8") as file:
    events_to_check = set()
    for line in file:
        # Rimuove eventuali virgolette doppie o singole
        event = line.strip().replace('"', '').replace("'", "")
        if event:
            events_to_check.add(event.upper())

# Trova gli eventi che non sono presenti nel JSON
missing_events = events_to_check - json_events

# Stampa gli eventi mancanti
for event in missing_events:
    print(event)
