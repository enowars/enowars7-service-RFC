
CREATE TABLE IF NOT EXISTS user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  num_posts INTEGER DEFAULT 0,
  shared_secret TEXT NOT NULL DEFAULT "Hier könnte Ihr Geheimnis stehen!",
  init_time INTEGER
);

CREATE TABLE IF NOT EXISTS post (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  title TEXT UNIQUE NOT NULL,
  body TEXT NOT NULL,
  is_private INTEGER NOT NULL DEFAULT FALSE,
  is_hidden INTEGER NOT NULL DEFAULT FALSE,
  key TEXT DEFAULT "Correct horse battery staple!",
  FOREIGN KEY (author_id) REFERENCES user (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS invitation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  post_id INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS event (
  id integer PRIMARY KEY AUTOINCREMENT,
  created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  description TEXT NOT NULL DEFAULT "awesome event you should not miss",
  host_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  title TEXT NOT NULL,
  location TEXT NOT NULL,
  date_of TEXT NOT NULL,
  is_private NOT NULL DEFAULT FALSE,
  guestlist BLOB,
  event_photo BLOB,
  init_time INTEGER,
  event_key TEXT NOT NULL DEFAULT "one secret to rule them all",
  FOREIGN KEY (host_id) REFERENCES user (id) ON DELETE CASCADE
);
