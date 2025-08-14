# gpoParser

**gpoParser** is a tool designed to extract and analyze configurations applied through Group Policy Objects (GPOs) in an Active Directory environment.
Since enumerating these settings can be tedious and time-consuming, this tool provides a clearer understanding of applied policies and helps identify dangerous configurations that could enable lateral movement or privilege escalation.
It was presented at [leHack 2025](https://lehack.org/fr/2025/tracks/conferences/#gpoparser-automating-group-policies-extraction-to-reveal-security-gaps) and [DEFCON 33](https://defcon.org/html/defcon-33/dc-33-speakers.html#content_60387).

# Install

```
pipx install git+https://github.com/synacktiv/gpoParser
```

# Features

```
$ gpoParser -h
usage: gpoParser [-h] {local,remote,enrich,query} ...

GPO Analysis Tool

positional arguments:
  {local,remote,enrich,query}
                        Choose local, remote or enrich mode
    local               Parse GPOs locally
    remote              Parse GPOs via remote LDAP/SYSVOL
    enrich              Enrich BloodHound with new edges
    query               Query GPO parser results in order to display affected computers

options:
  -h, --help            show this help message and exit
```

## GPO retrieval in online or offline mode

**Online**: Connects to the LDAP directory to gather GPO-related information and their attributes (flags, gPLink, gPOptions, and more). It also connects to the SYSVOL share to collect the GPO configuration files.

```
$ gpoParser remote -h
usage: gpoParser remote [-h] [-s SERVER] [-d DOMAIN] [-u USER] [-p PASSWORD] [-H HASH] [-k] [-t TARGET] [-of {pretty}] [-o OUTPUT] [-c CACHE] [-dr]

options:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        LDAP server IP or FQDN
  -d DOMAIN, --domain DOMAIN
                        Domain name
  -u USER, --user USER  Username
  -p PASSWORD, --password PASSWORD
                        Password
  -H HASH, --hash HASH  NTLM authentication, format is [LM:]NT
  -k, --kerberos        Use Kerberos authentication
  -t TARGET, --target TARGET
                        Filter target computer or OU by name
  -of {pretty}, --output-format {pretty}
                        Output format
  -o OUTPUT, --output OUTPUT
                        Output filename and location (default ./gpoParser_<timestamp>.out)
  -c CACHE, --cache CACHE
                        Cache file location (default current folder)
  -dr, --dry-run        Ignore cache file
```

**Offline**: Requires a (partial) copy of the LDAP directory and the content of the Policies folder from the SYSVOL share. Currently, LDAP directory collection relies on the [ldeep](https://github.com/franc-pentest/ldeep) tool. Additional collectors will be added over time.
It is also possible to filter results to obtain only the GPOs applying to a specific machine.

```
$ gpoParser local -h
usage: gpoParser local [-h] [-f {ldeep,bloodhound-legacy,bloodhound}] [-of {pretty,json}] [-t TARGET] [-o OUTPUT] [-c CACHE] [-dr] [sysvol_folder] [ldap_folder]

positional arguments:
  sysvol_folder         SYSVOL folder containing the policies
  ldap_folder           Folder with LDAP dump in ldeep format

options:
  -h, --help            show this help message and exit
  -f {ldeep,bloodhound-legacy,bloodhound}, --format {ldeep,bloodhound-legacy,bloodhound}
                        JSON files input format (default ldeep)
  -of {pretty,json}, --output-format {pretty,json}
                        Output format
  -t TARGET, --target TARGET
                        Filter target computer by name
  -o OUTPUT, --output OUTPUT
                        Output filename and location (default ./gpoParser_<timestamp>.out)
  -c CACHE, --cache CACHE
                        Cache file location (default current folder)
  -dr, --dry-run        Ignore cache file
```

## BloodHound enrichment

Parses GPO information to create additional edges such as **AdminTo**, **CanRDP**, and **CanPSRemote**, identifying lateral movement opportunities that BloodHound may not detect natively. Edges are added by connecting directly to the Neo4j database.

```
$ gpoParser enrich -h
usage: gpoParser enrich [-h] [-u USER] [-p PASSWORD] [-s SERVER] [-c CACHE]

options:
  -h, --help            show this help message and exit
  -u USER, --user USER  Username for neo4j authentication (default: neo4j)
  -p PASSWORD, --password PASSWORD
                        Password for neo4j authentication (default: bloodhoundcommunityedition)
  -s SERVER, --server SERVER
                        Neo4j server URI (default: bolt://localhost:7687)
  -c CACHE, --cache CACHE
                        Cache file location (default current folder)
```

## Query mode

Enables identification of the machines where a given GPO applies. Filtering is also possible by GPO name or GUID.

```
$ gpoParser query -h
usage: gpoParser query [-h] [-n NAME] [-g GUID] [-c CACHE]

options:
  -h, --help            show this help message and exit
  -n NAME, --name NAME  GPO name to filter on
  -g GUID, --guid GUID  GPO GUID to filter on
  -c CACHE, --cache CACHE
                        Cache file location (default current folder)
```


## Limitations

Offline data ingestion introduces certain limitations: parameters such as inheritance status, user/computer configuration status, security filters, WMI filters, and item-level targeting may not always be collected or interpreted by existing tools (BloodHound, PowerView, GPOHound).
**gpoParser** will progressively take all these parameters into account as its development continues.
Additional data collectors will be introduced as the tooling evolves.

