# Armsrace

Sibears training service 
Service file: verifier.py 
Checker file: checker.py 
Checker will dump and read its database to and from CWD.
Author: d86leader

## Tool stack

- python3=3.6.10
- mysql=15.1
- aiomysql=0.0.20
- openssl-python=17.5.0-lp151.4.6.1

Install those, set up your db, set db credentials in `verifier.py` and launch it.
Shabang line is set for freebsd, change it to `/usr/bin/env` for linux.

## Vulnerabilities

One single vulnerability. The checker reuses users and their keys for different
hosts, so you can setup your host to be an active attacker in the verification
protocol. The normal login conversation looks like this:
```
connect C S
C -> S: e1
S -> C: e2
C -> S: sign(client_key, e1*e2) = s
S -> C: ok if verify(client_cert, s)
```
Here is how we hijack it (with S1 being malicious):
```
connect C  S1
connect S1 S2
C  -> S1: e1
S1 -> S2: e1
S2 -> S1: e2
S1 -> C:  e2
C  -> S1: sign(client_key, e1*e1) = s
S1 -> S2: s
S2 -> S1: ok
S1 -> C: ok
```
et voila, S1 is now logged in via client_key they have no access to.
The malicious server (exploit) is in `sploited.py`

### Fix
This is a protocol vulnerability, so it is unfixable. That's why the service is called "armsrace": the first to discover this will get more points
