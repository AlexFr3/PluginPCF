## Panoramica
Questo plugin importa i risultati delle scansioni SpiderFoot (formato JSON), organizzando i dati in host,
servizi, vulnerabilità e note. Elabora automaticamente vari tipi di eventi come record DNS, informazioni IP, dati WHOIS e vulnerabilità.

## File per gestione eventi
1. scanner.py: da inserire nella repo di Spiderfoot nella cartella dei moduli -> `spiderfoot/modules`.
2. checkEvents.py: controlla se sono presenti tutti gli eventi in nel file `*.json` confrontadolo con un csv.
3.  TotalEvent.csv: file con tutti gli eventi non formattati per il codice.
4.  event_type.json: file con tutti gli eventi formattati per il codice(estratti con scanner.py) e categorizzati manualmente.
