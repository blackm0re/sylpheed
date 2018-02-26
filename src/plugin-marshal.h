
#ifndef __syl_plugin_marshal_MARSHAL_H__
#define __syl_plugin_marshal_MARSHAL_H__

#include	<glib-object.h>

G_BEGIN_DECLS

/* VOID:POINTER (plugin-marshal.list:1) */
#define syl_plugin_marshal_VOID__POINTER	g_cclosure_marshal_VOID__POINTER

/* VOID:POINTER,POINTER (plugin-marshal.list:2) */
extern void syl_plugin_marshal_VOID__POINTER_POINTER (GClosure     *closure,
                                                      GValue       *return_value,
                                                      guint         n_param_values,
                                                      const GValue *param_values,
                                                      gpointer      invocation_hint,
                                                      gpointer      marshal_data);

/* VOID:POINTER,POINTER,STRING,STRING,POINTER (plugin-marshal.list:3) */
extern void syl_plugin_marshal_VOID__POINTER_POINTER_STRING_STRING_POINTER (GClosure     *closure,
                                                                            GValue       *return_value,
                                                                            guint         n_param_values,
                                                                            const GValue *param_values,
                                                                            gpointer      invocation_hint,
                                                                            gpointer      marshal_data);

/* BOOLEAN:POINTER,INT,INT,STRING,POINTER (plugin-marshal.list:4) */
extern void syl_plugin_marshal_BOOLEAN__POINTER_INT_INT_STRING_POINTER (GClosure     *closure,
                                                                        GValue       *return_value,
                                                                        guint         n_param_values,
                                                                        const GValue *param_values,
                                                                        gpointer      invocation_hint,
                                                                        gpointer      marshal_data);

/* VOID:POINTER,POINTER,BOOLEAN (plugin-marshal.list:5) */
extern void syl_plugin_marshal_VOID__POINTER_POINTER_BOOLEAN (GClosure     *closure,
                                                              GValue       *return_value,
                                                              guint         n_param_values,
                                                              const GValue *param_values,
                                                              gpointer      invocation_hint,
                                                              gpointer      marshal_data);

/* VOID:INT (plugin-marshal.list:6) */
#define syl_plugin_marshal_VOID__INT	g_cclosure_marshal_VOID__INT

/* VOID:POINTER,STRING,STRING,POINTER (plugin-marshal.list:7) */
extern void syl_plugin_marshal_VOID__POINTER_STRING_STRING_POINTER (GClosure     *closure,
                                                                    GValue       *return_value,
                                                                    guint         n_param_values,
                                                                    const GValue *param_values,
                                                                    gpointer      invocation_hint,
                                                                    gpointer      marshal_data);

G_END_DECLS

#endif /* __syl_plugin_marshal_MARSHAL_H__ */

