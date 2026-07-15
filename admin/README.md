# PantKontroll accessadministrasjon

Tilgangsstyringen er en **read-only gate** foran appfunksjonene. Den kan tillate eller avvise nye operasjoner, men den har ingen funksjon som sletter, flytter eller endrer brukerens CSV-filer eller andre arbeidsdata.

## Sikkerhetsmodell

- Hver PC får en avledet `dev1_…`-ID basert på SMBIOS System UUID og serienummeret til den fysiske systemdisken. Dersom TPM-informasjon er tilgjengelig uten administratorrettigheter, produseres også et separat TPM-token.
- Alle ankere eksponeres kun som enveisavledede `anc1_…`-token. Rå UUID, diskserienummer og TPM-data skal aldri legges i policy, logg, sak eller GitHub.
- `access/policy.json` er signert med Ed25519. Appen godtar ikke endret eller usignert innhold, og nekter sekvens-rollback.
- En verifisert policy kan brukes offline i maksimalt 24 timer. Første oppstart krever online policy eller den midlertidige online `revoked.txt`-fallbacken. Uten noen av delene feiler appen lukket.
- Root-filen `revoked.txt` finnes kun for kompatibilitet med eldre installasjoner og lagres aldri som offline tilgangsbevis. `access/revoked.txt` er et identisk speil for pakking og revisjon.

## Førstegangsoppsett av nøkkel

Privatnøkkelen skal **aldri** legges i repoet, en releasepakke eller applikasjonsloggen.

PantKontroll 10.0.0 i denne leveransen har allerede offentlig release-nøkkel
`yBn7di+vOqTLoNUTdbdMhs1ZERD9yaaTDEFYbqlCtpw=` bygget inn. Bruk den separate
private PEM-filen som fulgte administrasjonsleveransen som GitHub-secret
`PANT_POLICY_PRIVATE_KEY`. Ikke generer en ny nøkkel uten samtidig å bygge og
distribuere appen på nytt med den nye offentlige nøkkelen.

Følgende prosedyre brukes ved en planlagt nøkkelrotasjon:

1. Generer en Ed25519-nøkkel på en administrert maskin, utenfor repoet:

   ```powershell
   openssl genpkey -algorithm ED25519 -out C:\secure\pant-policy-private.pem
   ```

2. Oppdater og signer startpolicyen lokalt, og skriv ut den offentlige rånøkkelen i base64:

   ```powershell
   python admin/update_policy.py --action allow_all
   python admin/sign_policy.py --private-key-file C:\secure\pant-policy-private.pem --print-public-key
   ```

3. Sett den utskrevne offentlige base64-verdien i `EMBEDDED_PUBLIC_KEY_B64` i `pant_app/access.py` før release. Offentlig nøkkel er ikke hemmelig. Den pakkede klienten godtar bevisst ikke miljøvariabel-overstyring av trust root.
4. Opprett GitHub Actions-secret `PANT_POLICY_PRIVATE_KEY` med hele PEM-innholdet. Alternativt godtar signeringsverktøyet en base64-kodet 32-byte Ed25519 seed.
5. Commit kun den signerte policyen og offentlig nøkkel. Oppbevar privatnøkkelen i en hemmelighetstjeneste eller offline nøkkellager, og slett eventuelle arbeidskopier etter organisasjonens rutiner.

Den inncheckede startpolicyen er allerede signert med release-nøkkelen. Etter at
repoet er publisert, kan workflowen derfor oppdatere den uten et usignert
mellomstadium.

## GitHub workflow

Kjør **PantKontroll access policy** via *Actions → Run workflow*. Workflowen har en samtidighetslås, kun `contents: write`, validerer alle input, øker policysekvensen, oppdaterer kompatibilitetsfilen, signerer med GitHub-secret og committer resultatet på default branch.

Handlinger:

- `revoke`: Krever `kind=device` med `dev1_…`, eller `kind=anchor` med `anc1_…`.
- `restore`: Fjerner den oppgitte avledede ID-en fra sperrelisten.
- `deny_all`: Stanser alle nye appoperasjoner. Eksisterende data berøres ikke.
- `allow_all`: Opphever global stopp, men beholder individuelle sperringer.

Enhets-ID og ankertoken kan vises fra appens administrasjonsside/API som `AccessDecision.identity`. Objektet inneholder bare avledede verdier og kan kopieres direkte til workflow-input.

## Lokal nødrutine

De samme valideringene kan kjøres lokalt:

```powershell
python admin/update_policy.py --action revoke --kind device --identifier dev1_<64 små hex-tegn>
python admin/sign_policy.py --private-key-file C:\secure\pant-policy-private.pem
```

Kontroller signaturen før commit ved å starte appens tester. Ikke håndrediger sekvensnummer nedover; klienten behandler det som rollback og bruker bare en nyere, fortsatt gyldig cache.
