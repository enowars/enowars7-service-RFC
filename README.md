# enowars7-service-RFC
Service and checker repository for the upcoming enowars7 attack-defense CTF competition.

## RFC-technicalities in a nutshell
- Python based web service utilizing the flask framework
- Gunicorn WSGI server running behind a nginx reverse proxy
- Application data is stored in an SQLite database
- Two vulnerabilities with separate flag stores

## Deployment
- The service can be deployed from the /service directory via: `docker compose up --build -d`
- Checker deployment works analogously from the /checker directory
-
## Documentation
![Documentation](./documentation/README.md "Documentation")
