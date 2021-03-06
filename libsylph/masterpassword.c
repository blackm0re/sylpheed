/*
 * LibSylph -- E-Mail client library
 * Copyright (C) 1999-2018 Hiroyuki Yamamoto
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib/gi18n.h>

#include "prefs_common.h"
#include "ssl.h"
#include "utils.h"
#include "masterpassword.h"


gchar *master_password;
gboolean master_password_enabled_on_init;

void set_master_password(const char *password) {
	master_password = password;
}

gchar *get_master_password(void) {
	return master_password;
}

void cleanse_buffer(void *buf, size_t len) {
#if USE_SSL
	OPENSSL_cleanse(buf, len);
#else
	memset(buf, 0, len); /* better than nothing */
#endif
}

void unload_master_password(void) {

	debug_print("Unloading master password\n");
	if (master_password == NULL) {
		/* not loaded / already unloaded */
		return;
	}
	cleanse_buffer(master_password, strlen(master_password));
	g_free(master_password);
	master_password = NULL;
	debug_print("Master password unloaded\n");

}

gint mpes_string_prefix(const gchar *str) {

	/* this function will be expanded in time as the format changes */
	if (g_str_has_prefix(str, "mpes1:"))
		return 6;
	return 0;

}

gboolean master_password_active(void) {

#if USE_SSL
	return ((master_password != NULL) &&
			prefs_common.use_master_password);
#else
	return FALSE;
#endif

}

gchar *decrypt_with_master_password(const gchar *str) {

#if USE_SSL
	gchar *new_str;
	gint str_prefix;

	if ((!str) || (!prefs_common.use_master_password))
		return g_strdup(str);

	if (master_password == NULL) {
		/* we have empty or auto unloaded master password */
		if ((!prefs_common.auto_unload_master_password) ||
			(check_master_password_interactively(3) != MP_RC_OK)) {
			return g_strdup(str);
		}
		debug_print("Reloaded master password\n");
	}

	str_prefix = mpes_string_prefix(str);
	if (!str_prefix)
		return g_strdup(str);

	if (decrypt_data(&new_str,
					 str + str_prefix,
					 master_password,
					 strlen(str) + 1 - str_prefix) != MP_RC_OK) {
		OPENSSL_cleanse(new_str, strlen(new_str));
		g_free(new_str);
		return g_strdup(str);
	}

	return new_str;
#else
	return g_strdup(str);
#endif

}

gchar *encrypt_with_master_password(const gchar *str) {

#if USE_SSL
	gchar *new_str, *mpes1_str;
	gint length_encrypted;

	if ((!str) || (!master_password_active()))
		return NULL;

	/*
	 * unlike the decrypt function, here it is up to the caller
	 * to make sure that auto unloaded master password is handled properly
	 */

	if (encrypt_data(&new_str,
					 &length_encrypted,
					 str,
					 master_password,
					 strlen(str) + 1,
					 prefs_common.encrypted_password_min_length,
					 TRUE) != MP_RC_OK) {
		g_free(new_str);
		return NULL;
	}

	mpes1_str = g_strdup_printf("mpes1:%s", new_str);
	g_free(new_str);

	return mpes1_str;
#else
	return NULL;
#endif

}

#if USE_SSL
gint set_master_password_interactively(guint max_attempts) {

	if (master_password == NULL)
		master_password = input_set_new_password(max_attempts);

	if (master_password == NULL)
		return 1;

	if (generate_password_hash(
			&prefs_common.master_password_hash,
			master_password,
			NULL) != MP_RC_OK) {
		/* should not really happen unless buggy code / library */
		g_free(prefs_common.master_password_hash);
		prefs_common.master_password_hash = NULL;
		debug_print(_("Could not generate master password hash"));
		return 1;
	}

	prefs_common_write_config();
	return 0;

}

gint check_master_password_interactively(guint max_attempts) {

	guint cnt;

	g_return_val_if_fail(max_attempts > 0, 1);
	g_return_val_if_fail(prefs_common.master_password_hash != NULL, 1);

	if (master_password != NULL) {
		/* password already cached */
		debug_print("Master password already cached\n");
		return check_password(master_password,
							  prefs_common.master_password_hash);
	}

	for (cnt = 0; cnt < max_attempts; ++cnt) {
		master_password = input_query_master_password();
		if (master_password == NULL) {
			/* input canceled or query_master_password_func not set */
			continue;
		}
		if (check_password(master_password,
						   prefs_common.master_password_hash) == MP_RC_OK) {
			return MP_RC_OK; /* match */
		}
		debug_print(_("Wrong master password entered (%d)\n"), cnt);
		OPENSSL_cleanse(master_password, strlen(master_password));
		g_free(master_password);
		master_password = NULL;
	}

	return 1; /* no match */

}
#endif /* USE_SSL */
