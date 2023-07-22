## RFC-technicalities in a nutshell
- RFC is a Python based web service that is utilizing the flask framework
- The service uses the Gunicorn WSGI server, which is running behind a nginx reverse proxy
- All necessary application data is stored in an SQLite database. The DB has three tables (users, posts, invitations) and makes use of indexes to speed up recurring queries.
- The service exposed two vulnerabilities with separate flag stores. The first flagstore is in the private post functionality, the second in the hidden post functionality. More on that in the respective document.
