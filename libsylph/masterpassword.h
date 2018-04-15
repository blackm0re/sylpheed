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

#ifndef __MASTERPASSWORD_H__
#define __MASTERPASSWORD_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define MP_RC_OK 0
#define MP_RC_WRONG_HASH_OR_KEY 1
#define MP_RC_INVALID_FORMAT 2 /* invalid digest format */

extern gchar *master_password;
extern gboolean master_password_enabled_on_init; /* m.p. enabled on init? */
void set_master_password(const char *password);
gchar *get_master_password(void);
void cleanse_buffer(void *buf, size_t len);
void unload_master_password(void);
gint mpes_string_prefix(const gchar *str);
gboolean master_password_active(void);
gchar *decrypt_with_master_password(const gchar *str);
gchar *encrypt_with_master_password(const gchar *str);

#if USE_SSL
gint set_master_password_interactively(guint max_attempts);
gint check_master_password_interactively(guint max_attempts);
#endif /* USE_SSL */

#endif /* __MASTERPASSWORD_H__ */
