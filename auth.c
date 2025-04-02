#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include "httpd.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

static int conv_fn(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    struct pam_response *responses = malloc(num_msg * sizeof(struct pam_response));
    if (!responses) return PAM_CONV_ERR;

    for (int i = 0; i < num_msg; i++) {
        if (msg[i]->msg_style == PAM_PROMPT_ECHO_OFF) {  // Запрос пароля
            responses[i].resp = strdup((char *)appdata_ptr);  // Передаем пароль
            responses[i].resp_retcode = 0;
        } else {
            responses[i].resp = NULL;
            responses[i].resp_retcode = 0;
        }
    }

    *resp = responses;
    return PAM_SUCCESS;
}

// Функция для получения UID по имени пользователя
static uid_t userid_from_name(const char *username) {
    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        syslog(LOG_ERR, "User %s not found", username);
        return (uid_t)-1;
    }
    return pwd->pw_uid;
}

// Функция для получения GID по имени пользователя
static gid_t upgid_from_name(const char *username) {
    struct passwd *pwd = getpwnam(username);
    if (!pwd) {
        syslog(LOG_ERR, "User %s not found", username);
        return (gid_t)-1;
    }
    return pwd->pw_gid;
}

int authenticate(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    int retval;
    const char *service = "picofoxweb"; // Имя сервиса PAM
    uid_t uid;
    gid_t gid;

    struct pam_conv conv = {conv_fn, (void *)password};

    // Инициализация PAM
    retval = pam_start(service, username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "PAM start failed: %s\n", pam_strerror(pamh, retval));
        return 0;
    }

    // Проверка аутентификации
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "Authentication failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return 0;
    }

    // Проверка прав доступа
    retval = pam_acct_mgmt(pamh, 0);
    if (retval != PAM_SUCCESS) {
        syslog(LOG_ERR, "Account management failed: %s\n", pam_strerror(pamh, retval));
        pam_end(pamh, retval);
        return 0;
    }

    // Получаем username еще раз на случай, если PAM его изменил
    const char *authenticated_username = NULL;
    pam_get_item(pamh, PAM_USER, (const void **)&authenticated_username);
    if (!authenticated_username) {
	syslog(LOG_ERR, "Failed to get username with PAM");
        pam_end(pamh, retval);
        return 0;
    }

    // Получаем UID и GID
    uid = userid_from_name(authenticated_username);
    gid = upgid_from_name(authenticated_username);

    if (uid == (uid_t)-1 || gid == (gid_t)-1) {
        pam_end(pamh, retval);
	syslog(LOG_ERR, "Failed to get UID or GID with PAM");
        return 0;
    }

    // Меняем контекст безопасности
    if (setgid(gid) != 0) {
        syslog(LOG_ERR, "Failed to set GID to %d", gid);
        pam_end(pamh, retval);
        return 0;
    }

    if (setuid(uid) != 0) {
        syslog(LOG_ERR, "Failed to set UID to %d", uid);
        pam_end(pamh, retval);
        return 0;
    }

    // Проверяем, что смена контекста прошла успешно
    if (getuid() != uid || getgid() != gid) {
        syslog(LOG_ERR, "Security context change verification failed");
        pam_end(pamh, retval);
        return 0;
    }

    // Если все прошло успешно, возвращаем 1
    pam_end(pamh, retval);
    return 1;
}

char *base64_decode(const char *input) {
    BIO *bio, *b64;
    int decodeLen = strlen(input);
    char *output = malloc(decodeLen); // Выделяем память под результат

    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int len = BIO_read(bio, output, decodeLen);
    output[len] = '\0'; // Добавляем терминальный ноль
    BIO_free_all(bio);

    return output;
}

int check_auth(const char *auth_header) {
    if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0) {
	    return 0;  // Нет заголовка или он не Basic
    }

    // Декодируем Base64 (auth_header + 6, т.к. "Basic " занимает 6 символов)
    char *decoded_auth = base64_decode(auth_header + 6);
    if (!decoded_auth) {
        return 0;
    }

    // Разбираем "username:password"
    char *colon = strchr(decoded_auth, ':');
    if (!colon) {
        free(decoded_auth);
        return 0; // Неверный формат
    }

    *colon = '\0';  // Разделяем на username и password
    char *username = decoded_auth;
    char *password = colon + 1;
    int auth_result = authenticate(username, password);
    free(decoded_auth);
    return auth_result;
}
