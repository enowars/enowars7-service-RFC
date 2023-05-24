# enowars7-service-RFC
Service and checker repository for the upcoming enowars7 attack-defense CTF competition

## Current features - Service
- The service can be deployed with `docker-compose up --build`
- When restarting the service by running the above command again, the sqlite database is currently wiped and setup again, without any content. This will be fixed in a later release.
- Registering a new account and loging in with username and password
- Creating a blogpost with title and body and setting it to be private
- Viewing the blogposts of other users. The ones that are private can be accessed by other users with a Time-based One-time-Password.
- Public posts can be viewed by anyone

## Planned features - Service
- change the service from a BLOGGING platform to an EVENT  platform
- allow users to invite other users to events/blogposts (the terms are used interchangeably here)
- create hidden events that cannot be viewed by anyone except the owner

## Current state - Vulnerabilities and Flag Stores
- The current vulnerability is a weak key-derivation-function with publicly available information (post-id and title). In combination with the publicly available timestamp of the events, the attacker can compute the TOTP that is necessary to access private events he was not invited to.
- The current flag store is in the description of private events. 

## Current state - Checker
- the checker can be deployed with docker-compose
- running `enocheker_test -a localhost -p 7999 -A $DOCKER_SERVICE test_function` results in errors. This needs fixing.
- It might be necessary to connect the networks of the service and checker docker containers using `docker network connect $CHECKER_NET $SERVICE_CONTAINER_ID`

## ToDo's
- change the key-derivation for TOTP
- think of a way to fix the vulnerability, without 'destroying' the service and checker
- Make database persistent between docker deployments
- Change the web server from development to production-grade server
