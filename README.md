# enowars7-service-RFC
Service and checker repository for the upcoming enowars7 attack-defense CTF competition.

## RFC-technicalities in a nutshell
- Python based web service utilizing the flask framework
- Gunicorn WSGI server running behind a nginx reverse proxy
- Application data is stored in an SQLite database
- Two vulnerabilities with separate flag stores


## Service Features
- The service is a blogging platform
- Users can 
    - create accounts, 
- When restarting the service by running the above command again, the sqlite database is currently wiped and setup again, without any content. This will be fixed in a later release.
- Registering a new account and loging in with username and password
- Creating a blogpost with title and body and setting it to be private
- Viewing the blogposts of other users. The ones that are private can be accessed by other users with a Time-based One-time-Password.
- Public posts can be viewed by anyone

## Planned features - Service
- change the service from a BLOGGING platform to an EVENT  platform
- allow users to invite other users to events/blogposts (the terms are used interchangeably here)
- create hidden events that cannot be viewed by anyone except the owner

## Vulnerabilities and Flag Stores
- The current vulnerability is a weak key-derivation-function with publicly available information (post-id and title). In combination with the publicly available timestamp of the events, the attacker can compute the TOTP that is necessary to access private events he was not invited to.
- The current flag store is in the description of private events. 

## State of the Checker
- the checker can be deployed with docker-compose
- running `enocheker_test -a localhost -p 7999 -A $DOCKER_SERVICE test_function` results in errors. This needs fixing.
- It might be necessary to connect the networks of the service and checker docker containers using `docker network connect $CHECKER_NET $SERVICE_CONTAINER_ID`

## Deployment
- The service can be deployed from the /service directory via: `docker-compose up --build`
- Checker deployments works analogously from the /checker directory
