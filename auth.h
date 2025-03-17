#ifndef AUTH_H
#define AUTH_H

int authenticate(const char *username, const char *password);

int check_auth(const char *auth_header);

#endif
