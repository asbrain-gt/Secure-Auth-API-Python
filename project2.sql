PRAGMA foreign_keys = ON;

DROP TABLE IF EXISTS likes; 
DROP TABLE IF EXISTS tags; 
DROP TABLE IF EXISTS follows; 
DROP TABLE IF EXISTS posts; 
DROP TABLE IF EXISTS passwords;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT UNIQUE NOT NULL, 
    email_address TEXT UNIQUE NOT NULL, 
    first_name TEXT, 
    last_name TEXT, 
    salt TEXT NOT NULL, 
    moderator TEXT NOT NULL
);

CREATE TABLE passwords (
    password_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_id INTEGER NOT NULL, 
    password_hash TEXT NOT NULL, 
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
); 

CREATE TABLE posts ( 
    post_id INTEGER PRIMARY KEY, 
    owner_id INTEGER NOT NULL, 
    title TEXT NOT NULL, 
    body TEXT NOT NULL, 
    FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE tags (
    tag_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    post_id INTEGER NOT NULL, 
    tag TEXT NOT NULL, 
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE
);

CREATE TABLE likes (
    like_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_id INTEGER NOT NULL, 
    post_id INTEGER NOT NULL, 
    UNIQUE (user_id, post_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE, 
    FOREIGN KEY (post_id) REFERENCES posts(post_id) ON DELETE CASCADE
);

CREATE TABLE follows (
    follower_id INTEGER NOT NULL, 
    following_id INTEGER NOT NULL, 
    PRIMARY KEY (follower_id, following_id), 
    FOREIGN KEY (follower_id) REFERENCES users(user_id) ON DELETE CASCADE, 
    FOREIGN KEY (following_id) REFERENCES users(user_id) ON DELETE CASCADE
);
