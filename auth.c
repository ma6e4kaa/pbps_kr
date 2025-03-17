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

int authenticate(const char *username, const char *password) {
    pam_handle_t *pamh = NULL;
    int retval;
    const char *service = "picofoxweb"; // Имя сервиса PAM

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
