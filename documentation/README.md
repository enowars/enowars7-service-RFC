## RFC-technicalities in a nutshell
- RFC is a Python based web service that is utilizing the flask framework
- The service uses the Gunicorn WSGI server, which is running behind a nginx reverse proxy
- All necessary application data is stored in an SQLite database. The DB has three tables (users, posts, invitations) and makes use of indexes to speed up recurring queries.
- The service exposes two vulnerabilities with separate flag stores. The first flagstore is in the private post functionality, the second in the hidden post functionality. More on that in the respective document.

![Service Architecture](./pictures/architecture.png?raw=true "The application architecture")


## Service Features
- The RFC service is an event-blogging platform
- When accessing the service, users are presented with an index page, where all currently existing posts (public and private ones) are displayed


![Service Index](./pictures/Index.png?raw=true "The application index page")


- All other HTTP endpoint-views are protected and require a login 
- Users can register accounts with unique usernames at /auth/register and login afterwards /auth/login
- Each user can create five blogposts. Blogposts can be public, private or hidden. Users can invite fellow users to their events.
- Hidden posts are not displayed on the index. Instead they can be accessed via the /auth/accountInfo endpoint (by all users that are invited) or via the unique integer-based post identifier
- When accessing a private or hidden post, users have to enter a valid time-based one-time password
- Public posts can be viewed by anyone


![Service Index](./pictures/totp.png?raw=true "The application index page")


## Vulnerability One - Private Posts do not update Secret Key

### Description
When users create private posts, by ticking the appropriate button during the creation process, they need to specify a secret phrase. The default secret phrase, which is displayed, is "Correct horse battery staple!". Users **must** specify a different phrase.
The phrase a user chooses is however not updated in the database.
Recall that 

### Exploit


### Idea


### Automated Script


## Vulnerability Two - Hidden Posts


### Description


### Exploit


### Idea


### Automated Script



