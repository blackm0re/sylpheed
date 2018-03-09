/*
 * LibSylph -- E-Mail client library
 * Copyright (C) 1999-2014 Hiroyuki Yamamoto
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#if USE_SSL

#include "defs.h"

#include <glib.h>
#include <glib/gi18n.h>

#include "utils.h"
#include "ssl.h"
#include "ssl_hostname_validation.h"

#define SALT_SIZE 16
#define CIPHER EVP_aes_256_cfb()
#define KEY_HASH EVP_sha256()
#define DIGEST_HASH EVP_sha256()
#define PBKDF2_DIGEST_SIZE 64
#define PBKDF2_ITERATIONS 100000

static SSL_CTX *ssl_ctx_SSLv23 = NULL;
static SSL_CTX *ssl_ctx_TLSv1 = NULL;

static GSList *trust_list = NULL;
static GSList *tmp_trust_list = NULL;
static GSList *reject_list = NULL;

static SSLVerifyFunc verify_ui_func = NULL;

static gchar *find_certs_file(const gchar *certs_dir)
{
	gchar *certs_file;

#define LOOK_FOR(crt)							   \
{									   \
	certs_file = g_strconcat(certs_dir, G_DIR_SEPARATOR_S, crt, NULL); \
	debug_print("looking for %s\n", certs_file);			   \
	if (is_file_exist(certs_file))					   \
		return certs_file;					   \
	g_free(certs_file);						   \
}

	if (certs_dir) {
		LOOK_FOR("ca-certificates.crt");
		LOOK_FOR("ca-bundle.crt");
		LOOK_FOR("ca-root.crt");
		LOOK_FOR("certs.crt");
		LOOK_FOR("cert.pem");
	}

#undef LOOK_FOR

	return NULL;
}

void ssl_init(void)
{
	gchar *certs_file, *certs_dir;
	FILE *fp;

	SSL_library_init();
	SSL_load_error_strings();

	certs_dir = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, "certs", NULL);
	if (!is_dir_exist(certs_dir)) {
		debug_print("ssl_init(): %s doesn't exist, or not a directory.\n",
			    certs_dir);
		g_free(certs_dir);
#ifdef G_OS_WIN32
		certs_dir = g_strconcat(get_startup_dir(), G_DIR_SEPARATOR_S
					"etc" G_DIR_SEPARATOR_S
					"ssl" G_DIR_SEPARATOR_S "certs", NULL);
#else
		certs_dir = g_strdup("/etc/ssl/certs");
#endif
		if (!is_dir_exist(certs_dir)) {
			debug_print("ssl_init(): %s doesn't exist, or not a directory.\n",
				    certs_dir);
			g_free(certs_dir);
			certs_dir = NULL;
		}
	}
	if (certs_dir)
		debug_print("ssl_init(): certs dir %s found.\n", certs_dir);

	certs_file = find_certs_file(get_rc_dir());

	if (certs_dir && !certs_file)
		certs_file = find_certs_file(certs_dir);

	if (!certs_file) {
#ifdef G_OS_WIN32
		certs_dir = g_strconcat(get_startup_dir(),
					G_DIR_SEPARATOR_S "etc"
					G_DIR_SEPARATOR_S "ssl", NULL);
		certs_file = find_certs_file(certs_dir);
		g_free(certs_dir);
		certs_dir = NULL;
		if (!certs_file) {
			certs_dir = g_strconcat(get_startup_dir(),
						G_DIR_SEPARATOR_S "etc", NULL);
			certs_file = find_certs_file(certs_dir);
			g_free(certs_dir);
			certs_dir = NULL;
		}
#else
		certs_file = find_certs_file("/etc/ssl");
		if (!certs_file)
			certs_file = find_certs_file("/etc");
#endif
	}

	if (certs_file)
		debug_print("ssl_init(): certs file %s found.\n", certs_file);

	ssl_ctx_SSLv23 = SSL_CTX_new(SSLv23_client_method());
	if (ssl_ctx_SSLv23 == NULL) {
		debug_print(_("SSLv23 not available\n"));
	} else {
		debug_print(_("SSLv23 available\n"));
		if ((certs_file || certs_dir) &&
		    !SSL_CTX_load_verify_locations(ssl_ctx_SSLv23, certs_file,
						   certs_dir))
			g_warning("SSLv23 SSL_CTX_load_verify_locations failed.\n");
	}

	/* ssl_ctx_TLSv1 = SSL_CTX_new(TLSv1_client_method()); */
	ssl_ctx_TLSv1 = SSL_CTX_new(SSLv23_client_method());
	if (ssl_ctx_TLSv1 == NULL) {
		debug_print(_("TLSv1 not available\n"));
	} else {
		debug_print(_("TLSv1 available\n"));
		/* disable SSLv2/SSLv3 */
		SSL_CTX_set_options(ssl_ctx_TLSv1,
				    SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
		if ((certs_file || certs_dir) &&
		    !SSL_CTX_load_verify_locations(ssl_ctx_TLSv1, certs_file,
						   certs_dir))
			g_warning("TLSv1 SSL_CTX_load_verify_locations failed.\n");
	}

	g_free(certs_dir);
	g_free(certs_file);

	certs_file = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S, "trust.crt",
				 NULL);
	if ((fp = g_fopen(certs_file, "rb")) != NULL) {
		X509 *cert;

		debug_print("ssl_init(): reading trust.crt\n");

		while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL)
			trust_list = g_slist_append(trust_list, cert);
		fclose(fp);
	}
	g_free(certs_file);
}

void ssl_done(void)
{
	gchar *trust_file;
	GSList *cur;
	FILE *fp;

	if (trust_list) {
		trust_file = g_strconcat(get_rc_dir(), G_DIR_SEPARATOR_S,
					 "trust.crt", NULL);
		if ((fp = g_fopen(trust_file, "wb")) == NULL) {
			FILE_OP_ERROR(trust_file, "fopen");
		}
		for (cur = trust_list; cur != NULL; cur = cur->next) {
			if (fp && !PEM_write_X509(fp, (X509 *)cur->data))
				g_warning("can't write X509 to PEM file: %s",
					  trust_file);
			X509_free((X509 *)cur->data);
		}
		if (fp)
			fclose(fp);
		g_free(trust_file);
		g_slist_free(trust_list);
		trust_list = NULL;
	}
	for (cur = tmp_trust_list; cur != NULL; cur = cur->next)
		X509_free((X509 *)cur->data);
	g_slist_free(tmp_trust_list);
	tmp_trust_list = NULL;
	for (cur = reject_list; cur != NULL; cur = cur->next)
		X509_free((X509 *)cur->data);
	g_slist_free(reject_list);
	reject_list = NULL;

	if (ssl_ctx_SSLv23) {
		SSL_CTX_free(ssl_ctx_SSLv23);
		ssl_ctx_SSLv23 = NULL;
	}

	if (ssl_ctx_TLSv1) {
		SSL_CTX_free(ssl_ctx_TLSv1);
		ssl_ctx_TLSv1 = NULL;
	}
}

gboolean ssl_init_socket(SockInfo *sockinfo)
{
	return ssl_init_socket_with_method(sockinfo, SSL_METHOD_SSLv23);
}

static gint x509_cmp_func(gconstpointer a, gconstpointer b)
{
	const X509 *xa = a;
	const X509 *xb = b;

	return X509_cmp(xa, xb);
}

gboolean ssl_init_socket_with_method(SockInfo *sockinfo, SSLMethod method)
{
	X509 *server_cert;
	gint err, ret;

	switch (method) {
	case SSL_METHOD_SSLv23:
		if (!ssl_ctx_SSLv23) {
			g_warning(_("SSL method not available\n"));
			return FALSE;
		}
		sockinfo->ssl = SSL_new(ssl_ctx_SSLv23);
		break;
	case SSL_METHOD_TLSv1:
		if (!ssl_ctx_TLSv1) {
			g_warning(_("SSL method not available\n"));
			return FALSE;
		}
		sockinfo->ssl = SSL_new(ssl_ctx_TLSv1);
		break;
	default:
		g_warning(_("Unknown SSL method *PROGRAM BUG*\n"));
		return FALSE;
		break;
	}

	if (sockinfo->ssl == NULL) {
		g_warning(_("Error creating ssl context\n"));
		return FALSE;
	}

	SSL_set_fd(sockinfo->ssl, sockinfo->sock);
	while ((ret = SSL_connect(sockinfo->ssl)) != 1) {
		err = SSL_get_error(sockinfo->ssl, ret);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			g_usleep(100000);
			g_warning("SSL_connect(): try again\n");
			continue;
		}
		g_warning("SSL_connect() failed with error %d, ret = %d (%s)\n",
			  err, ret, ERR_error_string(ERR_get_error(), NULL));
		return FALSE;
	}

	/* Get the cipher */

	debug_print(_("SSL connection using %s\n"),
		    SSL_get_cipher(sockinfo->ssl));
	debug_print("SSL protocol version: %s\n",
		    SSL_get_version(sockinfo->ssl));

	/* Get server's certificate (note: beware of dynamic allocation) */

	if ((server_cert = SSL_get_peer_certificate(sockinfo->ssl)) != NULL) {
		glong verify_result;
		gboolean expired = FALSE;

		if (get_debug_mode()) {
			gchar *str;
			guchar keyid[EVP_MAX_MD_SIZE];
			gchar keyidstr[EVP_MAX_MD_SIZE * 3 + 1] = "";
			guint keyidlen = 0;
			gint i;
	
			debug_print(_("Server certificate:\n"));

			if ((str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0)) != NULL) {
				debug_print(_("  Subject: %s\n"), str);
				OPENSSL_free(str);
			}

			if ((str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0)) != NULL) {
				debug_print(_("  Issuer: %s\n"), str);
				OPENSSL_free(str);
			}
			if (X509_digest(server_cert, EVP_sha1(), keyid, &keyidlen)) {
				for (i = 0; i < keyidlen; i++)
				g_snprintf(keyidstr + i * 3, 4, "%02x:", keyid[i]);
				keyidstr[keyidlen * 3 - 1] = '\0';
				debug_print("  SHA1 fingerprint: %s\n", keyidstr);
			}
			if (X509_digest(server_cert, EVP_md5(), keyid, &keyidlen)) {
				for (i = 0; i < keyidlen; i++)
				g_snprintf(keyidstr + i * 3, 4, "%02x:", keyid[i]);
				keyidstr[keyidlen * 3 - 1] = '\0';
				debug_print("  MD5 fingerprint: %s\n", keyidstr);
			}
		}

		verify_result = SSL_get_verify_result(sockinfo->ssl);
		if (verify_result == X509_V_OK) {
			debug_print("SSL certificate verify OK\n");
			if (ssl_validate_hostname(sockinfo->hostname, server_cert) == SSL_HOSTNAME_MATCH_FOUND) {
				debug_print("SSL certificate hostname validation OK\n");
				X509_free(server_cert);
				return TRUE;
			} else {
				verify_result = X509_V_ERR_APPLICATION_VERIFICATION;
			}
		}

		if (verify_result == X509_V_ERR_CERT_HAS_EXPIRED) {
			log_message("SSL certificate of %s has expired\n", sockinfo->hostname);
			expired = TRUE;
		} else if (g_slist_find_custom(trust_list, server_cert,
					       x509_cmp_func) ||
			   g_slist_find_custom(tmp_trust_list, server_cert,
					       x509_cmp_func)) {
			log_message("SSL certificate of %s previously accepted\n", sockinfo->hostname);
			X509_free(server_cert);
			return TRUE;
		} else if (g_slist_find_custom(reject_list, server_cert,
					       x509_cmp_func)) {
			log_message("SSL certificate of %s previously rejected\n", sockinfo->hostname);
			X509_free(server_cert);
			return FALSE;
		}

		if (verify_result == X509_V_ERR_APPLICATION_VERIFICATION) {
			g_warning("%s: SSL hostname validation failed\n",
				  sockinfo->hostname);
		} else {
			g_warning("%s: SSL certificate verify failed (%ld: %s)\n",
				  sockinfo->hostname, verify_result,
				  X509_verify_cert_error_string(verify_result));
		}

		if (verify_ui_func) {
			gint res;

			res = verify_ui_func(sockinfo, sockinfo->hostname,
					     server_cert, verify_result);
			/* 0: accept 1: temporarily accept -1: reject */
			if (res < 0) {
				debug_print("SSL certificate of %s rejected\n",
					    sockinfo->hostname);
#if 0
				reject_list = g_slist_prepend
					(reject_list, X509_dup(server_cert));
#endif
				X509_free(server_cert);
				return FALSE;
			} else if (res > 0) {
				debug_print("Temporarily accept SSL certificate of %s\n", sockinfo->hostname);
				if (!expired)
					tmp_trust_list = g_slist_prepend(tmp_trust_list, X509_dup(server_cert));
			} else {
				debug_print("Permanently accept SSL certificate of %s\n", sockinfo->hostname);
				if (!expired)
					trust_list = g_slist_prepend(trust_list, X509_dup(server_cert));
			}
		}

		X509_free(server_cert);
	} else {
		g_warning("%s: couldn't get SSL certificate\n",
			  sockinfo->hostname);
		return FALSE;
	}

	return TRUE;
}

void ssl_done_socket(SockInfo *sockinfo)
{
	if (sockinfo->ssl) {
		SSL_free(sockinfo->ssl);
	}
}

void ssl_set_verify_func(SSLVerifyFunc func)
{
	verify_ui_func = func;
}

/* master password related functions */
static gint secure_derive_key(guchar *key,
							  gint length_key,
							  const gchar *passphrase,
							  const guchar *salt) {

	guint length_buffer, length_hash;
	guchar *buffer, *ptr_hash;

	EVP_MD_CTX *mdctx;

	OPENSSL_cleanse(key, length_key);

	length_buffer = SALT_SIZE + strlen(passphrase);
	buffer = OPENSSL_malloc(length_buffer);
	OPENSSL_cleanse(buffer, length_buffer);

	memcpy(buffer, salt, SALT_SIZE);
	memcpy(buffer + SALT_SIZE, passphrase, strlen(passphrase));

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, KEY_HASH, NULL);
	EVP_DigestUpdate(mdctx, buffer, length_buffer);
	OPENSSL_cleanse(buffer, length_buffer);

	ptr_hash = OPENSSL_malloc(EVP_MD_size(KEY_HASH));
	EVP_DigestFinal_ex(mdctx, ptr_hash, &length_hash);

	memcpy(key,
		   ptr_hash,
		   (length_hash > length_key) ? length_key : length_hash);

	OPENSSL_cleanse(ptr_hash, length_hash);
	OPENSSL_free(ptr_hash);
	OPENSSL_free(buffer);
	EVP_MD_CTX_destroy(mdctx);

	return RC_OK;

}

gint encrypt_data(gchar **encrypted,
				  gint *length_encrypted,
				  const gchar *data,
				  const gchar *passphrase,
				  gint length_data,
				  guint min_data_length,
				  gboolean rnd_salt) {

	gint crypt_buffer_cnt, rc;
	guint key_size, length_hash;
	guint length_cleartext, length_ciphertext, length_total;
	guchar salt[SALT_SIZE];
	guchar *ciphertext_buffer, *total_buffer;
	/* sensitive buffers and counters */
	guint length_data_payload, length_padding;
	gchar str_data_size[3];
	guchar *data_payload_buffer, *hash_buffer, *padding_buffer, *key;
	guchar *cleartext_buffer;

	EVP_CIPHER_CTX *ctx;
	EVP_MD_CTX *mdctx;

	rc = RC_ERROR;

	if (length_data < 1) {
		return -1;
	}
	if (rnd_salt) {
		if (RAND_bytes(salt, SALT_SIZE) != 1) {
			debug_print("Random problems...\n");
			goto cleanup;
		}
	} else {
		strncpy((gchar *)salt, "FOR TESTING ONLY", SALT_SIZE);
	}

	key_size = EVP_CIPHER_key_length(CIPHER);
	key = OPENSSL_malloc(key_size);
	OPENSSL_cleanse(key, key_size);
	if (secure_derive_key(key,
					  key_size,
					  passphrase,
						  salt) != RC_OK) {
		OPENSSL_cleanse(key, key_size);
		debug_print("Could not generate secure key\n");
		goto cleanup;
	}

	/* prepare the data-buffer */
	length_padding = 0;
	if (length_data < min_data_length) {
		g_snprintf(str_data_size, 3, "%02d", length_data);
		length_padding = min_data_length - length_data;
		padding_buffer = OPENSSL_malloc(length_padding);
		OPENSSL_cleanse(padding_buffer, length_padding);
		if (RAND_bytes(padding_buffer, length_padding) != 1) {
			debug_print("Random problems...\n");
			goto cleanup;
		}
	} else {
		g_snprintf(str_data_size, 3, "-1");
	}

	length_data_payload = 2 + length_data + length_padding;
	data_payload_buffer = OPENSSL_malloc(length_data_payload);
	OPENSSL_cleanse(data_payload_buffer, length_data_payload);

	memcpy(data_payload_buffer, str_data_size, 2);
	memcpy(data_payload_buffer + 2, data, length_data);
	if (length_padding > 0) {
		memcpy(data_payload_buffer + (2 + length_data),
			   padding_buffer,
			   length_padding);
	}

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, DIGEST_HASH, NULL);
	EVP_DigestUpdate(mdctx, data_payload_buffer, length_data_payload);

	length_hash = EVP_MD_size(DIGEST_HASH);
	hash_buffer = OPENSSL_malloc(length_hash);
	OPENSSL_cleanse(hash_buffer, length_hash);
	EVP_DigestFinal_ex(mdctx, hash_buffer, NULL);

	length_cleartext = length_hash + length_data_payload;

	cleartext_buffer = OPENSSL_malloc(length_cleartext);
	OPENSSL_cleanse(cleartext_buffer, length_cleartext);

	/* assemble cleartext-buffer */
	memcpy(cleartext_buffer, hash_buffer, length_hash);
	memcpy(cleartext_buffer + length_hash,
		   data_payload_buffer,
		   length_data_payload);
	OPENSSL_cleanse(data_payload_buffer, length_data_payload); /* sensitive */

	/* encryption */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		debug_print("New ctx failed\n");
		goto cleanup;
	}

	length_ciphertext = 0;
	if (EVP_EncryptInit_ex(ctx, CIPHER, NULL, key, salt) != 1) {
		debug_print("EVP_EncryptInit_ex failed\n");
		goto cleanup;
	}

	ciphertext_buffer = OPENSSL_malloc(length_cleartext);

	crypt_buffer_cnt = 0;
	while(1) {
		if (EVP_EncryptUpdate(ctx,
							  ciphertext_buffer + length_ciphertext,
							  &crypt_buffer_cnt,
							  cleartext_buffer + length_ciphertext,
							  1) != 1) { /* one byte at a time */
			debug_print("EVP_EncryptUpdate failed\n");
			goto cleanup;
		}

		if (crypt_buffer_cnt != 1) { /* paranoia */
			debug_print("The sizes of enc and dec text do not correspond\n");
			goto cleanup;
		}

		++length_ciphertext;

		if (length_ciphertext >= length_cleartext) {
			break;
		}
	}
	/* No padding required for the CFB mode */

	OPENSSL_cleanse(cleartext_buffer, length_cleartext); /* sensitive */
	length_total = SALT_SIZE + length_ciphertext;
	total_buffer = OPENSSL_malloc(length_total);

	memcpy(total_buffer, salt, SALT_SIZE);
	memcpy(total_buffer + SALT_SIZE, ciphertext_buffer, length_ciphertext);

	*encrypted = g_base64_encode(total_buffer, length_total);
	*length_encrypted = strlen(*encrypted);

	rc = RC_OK;

cleanup:
	/* key */
	OPENSSL_cleanse(key, key_size);
	OPENSSL_free(key);
	/* cleartext buffer */
	OPENSSL_cleanse(cleartext_buffer, length_cleartext);
	OPENSSL_free(cleartext_buffer);
	/* payload buffer */
	OPENSSL_cleanse(data_payload_buffer, length_data_payload);
	OPENSSL_free(data_payload_buffer);
	/* hash */
	OPENSSL_cleanse(hash_buffer, length_hash);
	OPENSSL_free(hash_buffer);
	/* padding */
	if (length_padding > 0) {
		OPENSSL_cleanse(padding_buffer, length_padding);
		OPENSSL_free(padding_buffer);
	}

	OPENSSL_cleanse(str_data_size, 3); /* paranoia */

	/* ciphertext buffer */
	OPENSSL_free(ciphertext_buffer);

	/* total buffer */
	OPENSSL_free(total_buffer);

	length_data_payload = 0;
	length_padding = 0;

	EVP_CIPHER_CTX_free(ctx);
	EVP_MD_CTX_destroy(mdctx);

	return rc;

}

gint decrypt_data(gchar **decrypted,
				  const gchar *data,
				  const gchar *passphrase,
				  gint length_data) {

	gint rc; /* return code */
	gint decrypt_buffer_cnt, length_ciphertext, length_decrypted;
	guint key_size, length_hash, length_cleartext;
	gsize length_total;
	guchar salt[SALT_SIZE];
	guchar *ciphertext_buffer, *total_buffer;
	/* sensitive buffers and counters */
	gint data_size;
	guint length_data_payload;
	gchar str_data_size[3];
	guchar *data_payload_buffer, *hash_buffer, *key;
	guchar *cleartext_buffer;

	EVP_CIPHER_CTX *ctx;
	EVP_MD_CTX *mdctx;

	rc = -1;

	if (length_data < 1) {
		return -1;
	}

	total_buffer = g_base64_decode(data, &length_total);
	length_ciphertext = length_total - SALT_SIZE;
	ciphertext_buffer = OPENSSL_malloc(length_ciphertext);
	OPENSSL_cleanse(ciphertext_buffer, length_ciphertext);

	memcpy(salt, total_buffer, SALT_SIZE);
	memcpy(ciphertext_buffer, total_buffer + SALT_SIZE, length_ciphertext);

	key_size = EVP_CIPHER_key_length(CIPHER);

	/* decryption */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		debug_print("New ctx failed\n");
		goto cleanup;
	}

	key = OPENSSL_malloc(key_size);
	OPENSSL_cleanse(key, key_size);
	if (secure_derive_key(key,
						  key_size,
						  passphrase,
						  salt) != 0) {
		OPENSSL_cleanse(key, key_size);
		debug_print("Could not generate secure key\n");
		goto cleanup;
	}

	if (EVP_DecryptInit_ex(ctx, CIPHER, NULL, key, salt) != 1) {
		debug_print("EVP_DecryptInit_ex failed\n");
		goto cleanup;
	}
	OPENSSL_cleanse(key, key_size); /* highly sensitive */
	cleartext_buffer = OPENSSL_malloc(length_ciphertext);
	OPENSSL_cleanse(cleartext_buffer, length_ciphertext);

	length_cleartext = 0;
	decrypt_buffer_cnt = 0;

	while(1) {
		if (EVP_DecryptUpdate(ctx,
							  cleartext_buffer + length_cleartext,
							  &decrypt_buffer_cnt,
							  ciphertext_buffer + length_cleartext,
							  1) != 1) { /* one byte at a time */
			debug_print("EVP_EncryptUpdate failed\n");
			goto cleanup;
		}

		if (decrypt_buffer_cnt != 1) { /* paranoia */
			debug_print("The sizes of enc and dec text do not correspond");
			goto cleanup;
		}

		++length_cleartext;

		if (length_cleartext >= length_ciphertext) {
			break;
		}
	}


	length_hash = EVP_MD_size(DIGEST_HASH);
	hash_buffer = OPENSSL_malloc(length_hash);
	length_data_payload = length_cleartext - length_hash;
	data_payload_buffer = OPENSSL_malloc(length_data_payload);
	OPENSSL_cleanse(data_payload_buffer, length_data_payload);

	memcpy(data_payload_buffer,
		   cleartext_buffer + length_hash,
		   length_data_payload);

	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, DIGEST_HASH, NULL);
	EVP_DigestUpdate(mdctx, data_payload_buffer, length_data_payload);
	EVP_DigestFinal_ex(mdctx, hash_buffer, &length_hash);

	if (strncmp((const gchar*) hash_buffer,
				(const gchar*) cleartext_buffer,
				length_hash) != 0) {
		debug_print("Invalid hash\n");
		rc = RC_WRONG_HASH_OR_KEY;
		goto cleanup;
	}

	memcpy(str_data_size, cleartext_buffer + length_hash, 2);
	data_size = atoi(str_data_size);

	if (data_size < 0) {
		length_decrypted = length_data_payload - 2;
	} else {
		length_decrypted = data_size;
	}
	*decrypted = OPENSSL_malloc(length_decrypted);
	memcpy(*decrypted, data_payload_buffer + 2, length_decrypted);

	rc = RC_OK;

cleanup:

	/* key */
	OPENSSL_cleanse(key, key_size);
	OPENSSL_free(key);
	/* payload buffer */
	OPENSSL_cleanse(data_payload_buffer, length_data_payload);
	OPENSSL_free(data_payload_buffer);
	/* hash */
	OPENSSL_cleanse(hash_buffer, length_hash);
	OPENSSL_free(hash_buffer);
	/* ciphertext */
	OPENSSL_free(ciphertext_buffer);
	OPENSSL_free(total_buffer);

	EVP_CIPHER_CTX_free(ctx);
	EVP_MD_CTX_destroy(mdctx);

	return rc;

}

gint generate_password_hash(gchar **password_hash,
							const gchar *password,
							const guchar *salt) {
	/*
	 * Hashes 'password' using PKCS5_PBKDF2_HMAC with SHA512 and 'salt',
	 * and assigns a string to 'password_hash' with the following format:
	 * pbkdf2_sha512$iterations$base64(salt)$base64(password_hash)
	 */
	guchar lsalt[SALT_SIZE];
	gchar *PBKDF2_digest, *salt_b64, *digest_b64;

	if (salt == NULL) {
		if (RAND_bytes(lsalt, SALT_SIZE) != 1) {
			debug_print("Random problems...\n");
			return RC_ERROR;
		}
	} else {
		memcpy(lsalt, salt, SALT_SIZE);
	}

	PBKDF2_digest = OPENSSL_malloc(PBKDF2_DIGEST_SIZE);
	OPENSSL_cleanse(PBKDF2_digest, PBKDF2_DIGEST_SIZE);

	PKCS5_PBKDF2_HMAC(password,
					  strlen(password),
					  lsalt,
					  SALT_SIZE,
					  PBKDF2_ITERATIONS,
					  EVP_sha512(),
					  PBKDF2_DIGEST_SIZE,
					  (guchar *) PBKDF2_digest);
	digest_b64 = g_base64_encode((guchar *) PBKDF2_digest, PBKDF2_DIGEST_SIZE);
	OPENSSL_cleanse(PBKDF2_digest, PBKDF2_DIGEST_SIZE);
	OPENSSL_free(PBKDF2_digest);

	salt_b64 = g_base64_encode(lsalt, SALT_SIZE);

	*password_hash = g_strdup_printf("pbkdf2_sha512$%d$%s$%s",
									 PBKDF2_ITERATIONS,
									 salt_b64,
									 digest_b64);

	OPENSSL_cleanse(digest_b64, strlen(digest_b64));
	OPENSSL_free(digest_b64);

	OPENSSL_cleanse(salt_b64, strlen(salt_b64));
	OPENSSL_free(salt_b64);

	return RC_OK;

}

gint check_password(const gchar *password, const gchar *password_hash) {

	gint token_counter, rc;
	guchar *salt;
	gchar **tokens, *new_hash;
	gsize salt_length;

	rc = RC_ERROR;
	tokens = g_strsplit(password_hash,
						"$",
						-1);
	token_counter = 0;
	while (*(tokens + token_counter) != NULL) {
		++token_counter;
	}

	if (token_counter != 4) {
		debug_print("Invalid password hash...\n");
		goto cleanup;
	}

	salt = g_base64_decode(*(tokens + 2), &salt_length);
	if (salt_length != SALT_SIZE) {
		debug_print("Salt size does not match\n");
		goto cleanup;
	}

	if (generate_password_hash(&new_hash, password, salt) != RC_OK) {
		debug_print("Password hash generation failed\n");
		goto cleanup;
	}

	rc = g_strcmp0(password_hash, new_hash);

cleanup:
	g_free(salt);
	g_free(new_hash);
	g_strfreev(tokens);
	return rc;

}

#endif /* USE_SSL */
