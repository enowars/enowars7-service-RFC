## RFC-technicalities in a nutshell
- RFC is a Python based web service that is utilizing the flask framework
- The service uses the Gunicorn WSGI server, which is running behind a nginx reverse proxy
- All necessary application data is stored in an SQLite database. The DB has three tables (users, posts, invitations) and makes use of indexes to speed up recurring queries.
- The service exposes two vulnerabilities with separate flag stores. The first flagstore is in the private post functionality, the second in the hidden post functionality. More on that in the respective document.
- Computation of Time-based One-time Passwords is done in accordance to RFC 6238

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


## Vulnerability One - Default Key not updated in Private Posts
**Flagstore: Private Posts**  
When users create private posts, by ticking the appropriate button during the creation process, they need to specify a secret phrase. The default secret phrase, which is displayed, is "Correct horse battery staple!". Users **must** specify a different phrase.
The phrase a user chooses is however not updated in the database.
Recall that 



## Vulnerability Two - Unauthorized Invitations
**Flagstore: Hidden Posts**  
The following example illustrates the second vulnerability
- Imagine Alice is hosting a hidden event and neither Bob nor Chris are invited. They would however, like to participate in the event.
- Utilizing the attackinfo (here the post-identifier is published), Bob is able to enumerate the *title* of the event Alice is hosting. He does this by accessing the HTTP-endpoint */auth/accessblogpost/\<postid\>*. Although he is prompted with a TOTP-login form as can be seen further above, the eventname is also disclosed here.
- In a second step, Bob now creates an event with the exact same title and invites Chris to it.
Titles must be unique, which is why Bob is not successful in creating the event (an error is shown in the create mask). The invitation to the event is processed though, i.e. Chris received a valid invitation.
- Chris can now login and, when going to his */auth/accountInfo page, sees an accurate timestamp and the secret event key
- Chris can now use this information to calculate valid TOTPs



