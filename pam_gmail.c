#include <sys/param.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif
#define DOMAIN_LENGTH 256

static char password_prompt[] = "gMail:";


size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
        return size;
}


int check_key(const char *user, const char *pass)
{
        const char *url = "https://www.google.com/accounts/ClientLogin";
        CURL *curl;
        CURLcode res;
        curl = curl_easy_init();
        struct curl_httppost* post = NULL;
        struct curl_httppost* last = NULL;

        if(curl) {
                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
                curl_formadd(&post, &last, CURLFORM_COPYNAME, "accountType",
                             CURLFORM_PTRCONTENTS, "HOSTED_OR_GOOGLE", CURLFORM_END);
                 curl_formadd(&post, &last, CURLFORM_COPYNAME, "Email",
                             CURLFORM_PTRCONTENTS, user, CURLFORM_END);
                curl_formadd(&post, &last, CURLFORM_COPYNAME, "Passwd",
                             CURLFORM_PTRCONTENTS, pass, CURLFORM_END);
                curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);

                res = curl_easy_perform(curl);

                long http_code = 0;
                curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (http_code == 200 && res != CURLE_ABORTED_BY_CALLBACK)
                {
                        /* always cleanup */
                        curl_easy_cleanup(curl);
                        return PAM_SUCCESS;
                        //Succeeded
                } else {
                        /* always cleanup */
			if(res == CURLE_COULDNT_RESOLVE_HOST || res == CURLE_OPERATION_TIMEDOUT
                           || res == CURLE_COULDNT_CONNECT) {
                                curl_easy_cleanup(curl);
				return PAM_AUTHINFO_UNAVAIL;
                        //Failed
                        }
                        curl_easy_cleanup(curl);
                        return PAM_AUTH_ERR;
                }
        }
        return PAM_SYSTEM_ERR;
}


/* pam arguments are normally of the form name=value.  This gets the
 * 'value' corresponding to the passed 'name' from the argument
 * list. */
static const char *getarg(const char *name, int argc, const char **argv) {
  int len = strlen(name);
  while (argc) {
    if (strlen(*argv) > len &&
        !strncmp(name, *argv, len) &&
        (*argv)[len] == '=') {
      return *argv + len + 1;  /* 1 for the = */
    }
    argc--;
    argv++;
  }
  return 0;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	const void *ptr;
	const struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
	const char *user;
	char *password;
	int pam_err, retry;
	int system_is_down = 0;
        const char *domain = getarg("domain", argc, argv);
	const char *system = getarg("system_is_down", argc, argv);
        const char *stacked = getarg("stacked_pass", argc, argv);
        char complete_user[DOMAIN_LENGTH] = {0};
	if( system && (!strcmp("allow",system))) {
		system_is_down = 1;
	}
        if(!domain)
                domain = "gmail.com";
	/* identify user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	/* get password */
	pam_err = pam_get_item(pamh, PAM_CONV, &ptr);
	if (pam_err != PAM_SUCCESS)
		return (PAM_SYSTEM_ERR);
	conv = ptr;
	msgp = &msg;
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = password_prompt;

	password = NULL;
	for (retry = 0; retry < 3; ++retry) {
		resp = NULL;
		pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
		if (resp != NULL) {
			if (pam_err == PAM_SUCCESS) {
				password = resp->resp;
                        } else {
				free(resp->resp);
                        }
			free(resp);
		}
		if (pam_err == PAM_SUCCESS)
			break;
	}
	if (pam_err == PAM_CONV_ERR)
		return (pam_err);
	if (pam_err != PAM_SUCCESS)
		return (PAM_AUTH_ERR);
        strncat(complete_user, user, DOMAIN_LENGTH);
        strncat(complete_user, "@", DOMAIN_LENGTH);
        strncat(complete_user, domain, DOMAIN_LENGTH);
        pam_err = check_key(complete_user, password);
        if (pam_err == PAM_AUTHINFO_UNAVAIL && system_is_down) {
                pam_err = PAM_SUCCESS;
        }
	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_pig");
#endif
