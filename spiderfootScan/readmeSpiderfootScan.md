# Plugin SpiderFootScan per PCF

## Panoramica
Questo plugin importa i risultati delle scansioni SpiderFoot (formato JSON), organizzando i dati in host,
servizi, vulnerabilità e note. Elabora automaticamente vari tipi di eventi come record DNS, informazioni IP, dati WHOIS e vulnerabilità.

## File per gestione eventi
-scanner.py: da inserire nella repo di Spiderfoot nella cartella dei moduli -> spiderfoot/modules
-checkEvents.py: controlla se sono presenti tutti gli eventi in nel file *.json confrontadolo con un csv
