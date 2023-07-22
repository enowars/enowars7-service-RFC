## Service Features
- The RFC service is an event-blogging platform
- When accessing the service, users are presented with an index page, where all currently existing posts (public and private ones) are displayed
- All other HTTP endpoint-views are protected and require a login 
- Users can register accounts with unique usernames at /auth/register and login afterwards /auth/login
- Each user can create five blogposts. Blogposts can be public, private or hidden. Users can invite fellow users to their events.
- Hidden posts are not displayed on the index. Instead they can be accessed via the /auth/accountInfo endpoint (by all users that are invited) or via the unique integer-based post identifier
- When accessing a private or hidden post, users have to enter a valid time-based one-time password
- Public posts can be viewed by anyone
