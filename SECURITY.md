# Sikkerhet og personvern

## Lokal webserver

Serveren lytter bare på `127.0.0.1` og velger en ledig port ved oppstart. Alle API-kall krever en tilfeldig sesjonstoken i `X-Pant-Token`; CORS er ikke aktivert. Sikkerhetsheadere og streng innholds-policy reduserer risikoen fra andre nettsider.

## Enhetsidentitet

Appen avleder enhets-ID fra minst to uavhengige maskinvarekilder. Den foretrekker TPM/SMBIOS og fysisk systemdisk, avviser kjente OEM-plassholdere og hasher hver verdi med produktspesifikk domeneseparasjon. Rå UUID-er, serienumre og TPM-data lagres, logges eller sendes aldri. GitHub mottar ingen oppslag per enhet; alle klienter laster samme policy og sammenligner lokalt.

## Sperrepolicy

Produksjon bruker en Ed25519-signert policy med sekvensnummer, utløp, minimumsversjon, global nødstopp og lister over pseudonyme enhets-/ankertoken. En verifisert tillatelse kan caches i maksimalt 24 timer. Første oppstart uten nett er sperret. En eldre policy kan ikke rulle tilbake en nyere cache.

Den eksisterende `revoked.txt`-filen støttes som overgang, men bare ved et vellykket online-oppslag. `*` betyr global sperre.

## Realistisk grense

En lokal administrator kan i prinsippet patche en klientbinær eller kjøre en endret kildekodekopi. En ren klientbasert sperre kan derfor ikke være absolutt mot maskinens administrator. I produksjon bør ansatte være standardbrukere, EXE/installer Authenticode-signeres, installasjonen ligge i Program Files og virksomheten eventuelt bruke WDAC/App Control.

## Lokale personopplysninger

Regnr, navn og postnummer kan være personopplysninger. Appen sender dem bare til de valgte oppslagskildene, lagrer dem lokalt og tilbyr personvernvisning. Virksomheten er ansvarlig for tilgangsstyring, lagringstid og sletting av gamle CSV-/historikkdata.

