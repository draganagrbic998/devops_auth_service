CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
	last_name VARCHAR(255) NOT NULL
);

insert into users (username, password, first_name, last_name)
values ('admin', '$2b$12$zyO4.0iFmM3Sh7ngnOncB.KgEcIjwVRLq6G/IIXzRglFYQR1gQ14G', 'admin', 'admin');
