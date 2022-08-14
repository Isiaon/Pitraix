<img src="https://i.ibb.co/nM06FQM/pitraix.png"></img>
# Pitraix
Modern Cross-Platform P2P Botnet over TOR that cannot be traced
Design is based off intelligence agencies structures for reasoning behind this design check `spec.txt`

# Built-in Crypter and self-spreading
Pitraix has ability to self modify it's own code which results in a completely different executable in terms of hash on every Host infection.

it is done automatically and does not need operator intervention.

# Cross-platform with some sneaky 1-days
Pitraix works on windows 7 all way to windows 11 as well as linux
it has ability to automatically privilege escalate on linux and windows
on linux it does so by keylogging password when user runs "sudo" or "doas"
on windows it uses a modified version of UACME (work in progress)

- This release will only include windows version, next release will be linux as I iron out bugs from linux port

# Dynamic Behaviour
Pitraix automatically chooses different persistence locations on every host
Names of config files, pitraix it's self and more are all dynmically generated to confuse anti-viruses

# Anonymous and secure
- Hosts don't know each other, not even their their tor onion address
- Agents are hosts but have tor onion address of other hosts, agents relay instructions from operative to hosts. for reasoning behind this design check `spec.txt`
- Operatives are camaoflagued as agents to protect against advanced network timing and packets attacks over tor

# Features
- State-of-art encryption using AES-256 and public key crypto
- Peer-to-Peer over TOR
- Ability to keylog cross-platform even when run as user and not root
- Dynamic behaviour
- Built-in crypter
- Built-in ransomware that never stores keys on HOST
- Readiable code easy to modify, not alot of scattered files
- Events are anything interesting that happens on a host computer, currently it's tied only to keylogger
- Logs are mainly used for debugging behaviour and errors


# Help
- Type "help" in OPER for list of commands

# Future
- This is a oldi-sh version of Pitraix, more advanced options will be added soon as I work on ironing out bugs
- For example python and powershell Modules support will be added soon alongside alot of bug fixes 

# Techincal
- Please read `spec.txt` for more techincal information

# Terms
Operative/OPER means the botmaster

Agent/AGS means a host that can relay instructions

Host/HST means a host that does not relay instructions

Instructions mean commands

Host means a bot

Hostring/cell means botnet
