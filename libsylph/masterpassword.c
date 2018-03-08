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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "prefs_common.h"
#include "ssl.h"
#include "utils.h"


gchar *master_password;

void set_master_password(const char *password) {
    master_password = password;
}

gchar *get_master_password(void) {
    return master_password;
}

#if USE_SSL

gint set_master_password_interactively(guint max_attempts) {

    if (master_password != NULL)
        return 0; /* master_password already set */

    master_password = input_set_new_password(max_attempts);

    if (master_password == NULL)
        return 1;

    if (generate_password_hash(
            &prefs_common.master_password_hash,
            master_password,
            NULL) != RC_OK) {
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

    if (max_attempts < 1)
        return 1;

    if (prefs_common.master_password_hash != NULL) {
        return 1;
    }

    if (master_password != NULL) {
        /* password already cached */
        return check_password(master_password,
                              prefs_common.master_password_hash);
    }

    for (cnt = 0; cnt < max_attempts; ++cnt) {
        master_password = input_query_master_password();
        if (check_password(master_password,
                           prefs_common.master_password_hash) == RC_OK) {
            return RC_OK; /* match */
        }
        debug_print(_("Wrong master password entered (%d)\n"), cnt);
        /* TODO: clear before free? */
        g_free(master_password);
        master_password = NULL;
    }

    return 1; /* no match */

}

#endif /* USE_SSL */
