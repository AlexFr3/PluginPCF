# Plugin ZAP per PCF

## Panoramica
Questo plugin importa report di scansione XML generati da OWASP ZAP in PCF, organizzando i dati in:
- Host e servizi
- Vulnerabilità con evidenze dettagliate
- Note tecniche strutturate
- Relazioni tra componenti

## Funzionalità Principali
- **Validazione XML**: Controllo integrità report con schema XSD
- **Gestione Rete**
  - Rilevamento automatico IP/hostname
  - Deduplicazione intelligente
- **Elaborazione Vulnerabilità**
  - Generazione automatica PoC
  - Mappatura rischio/confidenza
- **Integrazione Database**
  - Creazione relazioni host-porta-servizio
  - Aggiornamento stato vulnerabilità

## Installazione
1. Installare dipendenze:
```bash
pip install os json base64
