# gpoParser

**gpoParser** is a tool designed to extract and analyze configurations applied through Group Policy Objects (GPOs) in an Active Directory environment.
Since enumerating these settings can be tedious and time-consuming, this tool provides a clearer understanding of applied policies and helps identify dangerous configurations that could enable lateral movement or privilege escalation.
It was presented at [leHack 2025](https://lehack.org/fr/2025/tracks/conferences/#gpoparser-automating-group-policies-extraction-to-reveal-security-gaps) and [DEFCON 33](https://defcon.org/html/defcon-33/dc-33-speakers.html#content_60387).

# Install

Note: dependency needed for `gssapi` package: `libkrb5-dev`, install via `sudo apt install libkrb5-dev` (or via your relevant package manager)

```
pipx install git+https://github.com/synacktiv/gpoParser
```

# Features

```
$ gpoParser -h
usage: gpoParser [-h] {local,remote,display,query,enrich} ...

GPO Analysis Tool

positional arguments:
  {local,remote,display,query,enrich}
                        Choose mode
    local               Parse GPOs locally
    remote              Parse GPOs via remote LDAP/SYSVOL
    display             Display parsed GPO contents
    query               Query GPO parser results in order to display affected computers
    enrich              Enrich BloodHound with new edges

options:
  -h, --help            show this help message and exit
```

## GPO retrieval in online or offline mode

**Online**: Connects to the LDAP directory to gather GPO-related information and their attributes (flags, gPLink, gPOptions, and more). It also connects to the SYSVOL share to collect the GPO configuration files.

```
$ gpoParser remote -h
usage: gpoParser remote [-h] [-s SERVER] [-d DOMAIN] [-u USER] [-p PASSWORD] [-H HASH] [-k] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -s, --server SERVER   LDAP server IP or FQDN (ex: ldap://192.168.57.5 or ldaps://dc.corp.local)
  -d, --domain DOMAIN   Domain name tied to the user
  -u, --user USER       Username
  -p, --password PASSWORD
                        Password
  -H, --hash HASH       NTLM authentication, format is [LM:]NT
  -k, --kerberos        Use Kerberos authentication
  -o, --output OUTPUT   Output filename and location (default ./cache_gpoParser_<timestamp>.json)

$ gpoParser remote -u bob -p password -d corp -s 192.168.57.5
Retrieving \CORP.LOCAL\Policies\{008B0634-C0B9-443A-A06A-E2BAD875E27F}\Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf
Retrieving \CORP.LOCAL\Policies\{008B0634-C0B9-443A-A06A-E2BAD875E27F}\Machine/Preferences/Groups/Groups.xml
Retrieving \CORP.LOCAL\Policies\{008B0634-C0B9-443A-A06A-E2BAD875E27F}\Machine/Preferences/Registry/Registry.xml
[...]
Information saved to cache, now use display / query features
```

**Offline**: Requires a (partial) copy of the LDAP directory and the content of the Policies folder from the SYSVOL share. Currently, LDAP directory collection relies on:

  - [ldeep](https://github.com/franc-pentest/ldeep)
  - [ADExplorerSnapshot](https://github.com/c3c/ADExplorerSnapshot) `Objects` output format (NDJSON)

```
$ gpoParser local -h
usage: gpoParser local [-h] [-f {ldeep,adexplorer}] [-o OUTPUT] sysvol_folder ldap_folder

positional arguments:
  sysvol_folder         SYSVOL folder containing the policies
  ldap_folder           Folder with LDAP dump in ldeep format

options:
  -h, --help            show this help message and exit
  -f {ldeep,adexplorer}, --format {ldeep,adexplorer}
                        JSON files input format (default ldeep)
  -o OUTPUT, --output OUTPUT
                        Output filename and location (default ./cache_gpoParser_<timestamp>.json)

$ mkdir sysvol && cd sysvol &&  echo -e 'prompt\nrecurse\nmget *' | smbclient -W CORP -U bob%password //192.168.57.5/SYSVOL

$ mkdir ldap && ldeep ldap -u bob -p password -d corp.local -s 192.168.57.5 all ldap/corp

$ gpoParser local sysvol/ ldap/
Information saved to cache, now use display / query features
```

## Display

This mode displays all configuration changes applied by GPOs, limited to supported formats and parsed data. You can filter the results by GPO name or GUID.

```
$ gpoParser display -h
usage: gpoParser display [-h] [-g GPO] [-c CACHE]

options:
  -h, --help            show this help message and exit
  -g GPO, --gpo GPO     Filter by GPO name or GUID
  -c CACHE, --cache CACHE
                        Cache file location (default: ./cache_gpoParser_<timestamp>.json)

$ gpoParser display
Cache file found, using it
{6F3821B3-89B2-496D-82A5-58092D3EA588}: AddAdmin
Computer configuration
   Groups
      The following principals are added to BUILTIN\Administrators
         CORP\admin
{ADC96BD4-86D3-4516-BCF2-F7BDD5A76366}: AddRDP
Computer configuration
   Groups
      The following principals are added to BUILTIN\Remote Desktop Users
         CORP\bob
[...]

$ gpoParser display -g work
Cache file found, using it
{474D47E2-2B77-4E37-9744-A3CF6AB04449}: Workstation admins
Computer configuration
   Groups
      The following principals are added to BUILTIN\Administrators
         CORP\Admin - All Workstations
```

## Query

This view shows the relationships between GPOs and computers. For example, you can see which computers a GPO applies to or what changes are applied to one or more computers.
```
$ gpoParser query -h
usage: gpoParser query [-h] [-g GPO] [-C COMPUTER] [-c CACHE]

options:
  -h, --help            show this help message and exit
  -g GPO, --gpo GPO     Filter by GPO name or GUID
  -C COMPUTER, --computer COMPUTER
                        Computer name or distinguishedName to filter on
  -c CACHE, --cache CACHE
                        Cache file location (default: ./cache_gpoParser_<timestamp>.json)

$ gpoParser query
Cache file found, using it
{6F3821B3-89B2-496D-82A5-58092D3EA588}: AddAdmin
This GPO affects the following computers:
CN=SRV55,OU=PROD,OU=Servers,DC=CORP,DC=LOCAL
CN=SRV54,OU=PROD,OU=Servers,DC=CORP,DC=LOCAL
CN=SRV53,OU=PROD,OU=Servers,DC=CORP,DC=LOCAL
CN=SRV52,OU=PROD,OU=Servers,DC=CORP,DC=LOCAL

{6AC1786C-016F-11D2-945F-00C04FB984F9}: Default Domain Controllers Policy
This GPO affects the following computers:
CN=DC01,OU=Domain Controllers,DC=CORP,DC=LOCAL

{31B2F340-016D-11D2-945F-00C04FB984F9}: Default Domain Policy
This GPO affects the following computers:
CN=SRV51,OU=SUBSUB,OU=SUB,DC=CORP,DC=LOCAL
CN=SRV49,OU=SUB,DC=CORP,DC=LOCAL
CN=SRV50,OU=SUB,DC=CORP,DC=LOCAL
CN=SRV55,OU=PROD,OU=Servers,DC=CORP,DC=LOCAL
[...]


$ gpoParser query -C wks
Cache file found, using it
CN=WKS01,OU=ADMIN,OU=WORKSTATIONS,DC=CORP,DC=LOCAL
{31B2F340-016D-11D2-945F-00C04FB984F9}: Default Domain Policy
Computer configuration
   Registry
      The following registry key changes have been made
      Action: Create
      Path: MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash
      Value: 4,1
      The following registry key changes have been made
      Action: Update
      Hive: HKEY_LOCAL_MACHINE
      Path: SYSTEM\CurrentControlSet\Services\Dnscache\Parameters
      Name: EnableMDNS
      Value: 00000000
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
                        Cache file location (default: ./cache_gpoParser_<timestamp>.json)
```

## Limitations

Offline data ingestion introduces certain limitations: parameters such as inheritance status, user/computer configuration status, security filters, WMI filters, and item-level targeting may not always be collected or interpreted by existing tools (BloodHound, PowerView, GPOHound).
**gpoParser** will progressively take all these parameters into account as its development continues.
Additional data collectors will be introduced as the tooling evolves.
