	Sylpheed - cliente de correo electr�nico ligero y amigable

   Copyright(C) 1999-2006 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>

   Este programa es software libre; puede redistribuirlo y/o modificarlo 
   bajo los t�rminos de la GNU General Public License publicada por la 
   Free Software Foundation; tanto la versi�n 2, como (opcionalmente) 
   cualquier versi�n posterior.

   Este programa se distribuye con la esperanza de que sea �til, pero 
   SIN NINGUNA GARANT�A; ni siquiera la garant�a impl�cita de 
   COMERCIALIDAD o ADECUACI�N PARA ALG�N PROP�SITO PARTICULAR. Vea la 
   GNU General Public License para m�s detalles.

   Usted deber�a haber recibido una copia de la GNU General Public License 
   junto con este programa; en caso contrario, escriba a la Free Software 
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
   
   Para m�s detalles vea el fichero COPYING.

Qu� es Sylpheed
===============

Sylpheed es un cliente de correo electr�nico basado en la librer�a gr�fica
GTK+. Corre bajo el X Window System y tambi�n en Microsoft Windows.

Sylpheed es un software libre distribuido bajo la GPL de GNU.

Sylpheed tiene las siguientes caracter�sticas:

    * Interfaz de usuario simple, elegante, y pulido
    * Manejo confortable construido al detalle
    * Disponibilidad inmediata con m�nima configuraci�n
    * Funcionamiento ligero
    * Alta fiabilidad
    * Soporte de internacionalizaci�n y m�ltiples idiomas
    * Alto nivel de procesamiento del Japon�s
    * Soporte de varios protocolos
    * Gran capacidad de filtrado y b�squedas 
    * Control del correo basura
    * Cooperaci�n flexible con programas externos

La apariencia e interfaz son similares a algunos clientes de correo populares
para Windows, como Outlook Express o Becky!. Muchas �rdenes son accesibles
con el teclado, como en los clientes Mew y Wanderlust basados en Emacs.
Por ello podr� ser capaz de migrar a Sylpheed con relativa comodidad en caso 
de que estuviera acostumbrado a otros clientes.

Los mensajes se gestionan en formato MH, y podr� usarlos junto con otros
clientes basados en el formato MH (tal como Mew). Tiene menos posibilidades
de perder correos ante falles ya que cada fichero se corresponde a un correo.
Puede importa o exportar mensajes en formato mbox. Tambi�n puede utilizar
fetchmail y/o procmail, y programas externos para recibir (como inc o imget).

Caracter�sticas principales implementadas actualmente
=====================================================

Protocolos soportados

	o POP3
	o IMAP4rev1
	o SMTP
	o NNTP
	o SSL/TLSv1 (POP3, SMTP, IMAP4rev1, NNTP)
	o IPv6

Caracter�sticas

	o m�ltiples cuentas
	o filtrado de gran capacidad
	o b�squedas (petici�n de b�squeda, b�squeda r�pida, carpeta de b�squeda)
	o control del correo no deseado (correo basura)
	o vista jer�rquica
	o presentaci�n y transferencia de adjuntos por MIME
	o vista de im�genes incrustadas
	o lector de noticias de internet (news)
	o soporte de SMTP AUTH (PLAIN / LOGIN / CRAM-MD5)
	o autentificaci�n CRAM-MD5 (SMTP AUTH / IMAP4rev1)
	o autentificaci�n APOP (POP3)
	o firmas y cifrado PGP (necesita GPGME)
	o comprobaci�n ortogr�fica (necesita GtkSpell)
	o vista de X-Face
	o cabeceras definidas por el usuario
	o etiquetas de marca y color
	o atajos de teclado compatibles con Mew/Wanderlust
	o soporte de m�ltiples carpetas MH
	o exportaci�n/importaci�n de mbox
	o acciones para trabajar con programas externos
	o editor externo
	o almacenamiento de mensajes en cola
	o comprobaci�n autom�tica de correo
	o borradores de mensaje
	o plantillas
	o recorte de l�neas
	o auto-guardado
	o URI en las que se puede hacer clic
	o libro de direcciones
	o gesti�n de mensajes nuevos y no le�dos
	o impresi�n
	o modo sin conexi�n
	o control remoto a trav�s de la l�nea de �rdenes
	o configuraci�n por cada carpeta
	o soporte de LDAP, vCard, y JPilot
	o arrastrar y soltar
	o soporte de autoconf y automake
	o internacionalizaci�n de mensajes con gettext
	o soporte de m17n (m�ltiples idiomas)

y m�s.

Instalaci�n
===========

Vea INSTALL para las instrucciones de instalaci�n.

Uso
===

Preparaci�n antes de la ejecuci�n
---------------------------------

Si esta usando una codificaci�n de caracteres distinta de UTF-8 para
los nombres de fichero, debe establecer la variable de entorno siguiente
(no funcionar� si no se especifica):

(usar la codificaci�n espec�fica de la localizaci�n)
% export G_FILENAME_ENCODING=@locale

o

(especificaci�n manual de la codificaci�n)
% export G_FILENAME_ENCODING=ISO-8859-1

Si quiere que se muestren los mensajes traducidos en su idioma,
debe especificar algunas variables de entorno relativas a la localizaci�n.
Por ejemplo:

% export LANG=de_DE

(sustituir de_DE con el nombre de la localizaci�n actual)

Si no quiere mensajes traducidos, establezca LC_MESSAGES a "C"
(y no establezca LC_ALL si esta especificada). 

C�mo ejecutar
-------------

Escriba �sylpheed� en la l�nea de �rdenes, o haga doble clic en el icono
en un gestor de ficheros para ejecutar.

Arranque inicial
----------------

Cuando se ejecuta Sylpheed por primera vez crea autom�ticamente los ficheros
de configuraci�n bajo ~/.sylpheed-2.0/, y le pregunta la ubicaci�n del buz�n.
Por omisi�n es ~/Mail. Si existe alg�n fichero en el directorio que no se
corresponda al formato MH tendr� que especificar otra ubicaci�n.

Si no existe ~/.sylpheed-2.0/ pero la configuraci�n de una versi�n anterior
existe en ~/.sylpheed/, se realizar� la migraci�n autom�ticamente despu�s de
la confirmaci�n.

Si la codificaci�n de la localizaci�n no es UTF-8 y la variable de entorno
G_FILENAME_ENCODING no est� establecida se mostrar� una ventana de aviso.

Configuraci�n necesaria
-----------------------

Inicialmente deber� crear al menos una cuenta para enviar o recibir mensajes
(puede leer los mensajes ya existentes sin crear ninguna cuenta). El di�logo
de configuraci�n se mostrar� al hacer clic en el men� �Configuraci�n -> Crear
nueva cuenta...� o �Cuenta� en la barra de herramientas. Despu�s se rellene
los valores necesarios.

Vea el manual proporcionado con este programa para el uso general.

Configuraciones ocultas
-----------------------

Se pueden configurar la mayor�a de las caracter�sticas de Sylpheed a trav�s
de la ventana de preferencias, pero hay algunos par�metros que carecen de
interfaz de usuario (no tiene que modificarlos para el uso normal). Debe
editar el fichero ~/.sylpheed-2.0/sylpheedrc con un editor de texto cuando
Sylpheed no se este ejecutando para cambiarlos.

allow_jisx0201_kana		permite JIS X 0201 Kana (kana de media anchura)
                                al enviar
                                0: desactivado 1: activado   [por omisi�n: 0]
translate_header		traducir cabeceras como �Desde:�, �Para:� y
                                �Asunto:�.
                                0: desactivado 1: activado   [por omisi�n: 1]
enable_rules_hint		habilita colores de fila alternativos en la
                                vista resumen
                                0: desactivado 1: activado   [por omisi�n: 1]
bold_unread			muestra en la vista resumen los mensajes no 
                                le�dos con una tipograf�a en negrita
                                0: desactivado 1: activado   [por omisi�n: 1]
textview_cursor_visible		mostrar el cursor en la vista de texto
                                0: desactivado 1: activado   [por omisi�n: 0]
logwindow_line_limit		especificar el n�mero de l�neas m�ximo en la
                                ventana de traza
				0: ilimitado  n (> 0): n l�neas 
				[por omisi�n: 1000]

Al contrario que la 1.0.x, esta versi�n no permite por omisi�n la modificaci�n
directa de los atajos de men�. Puede usar alguno de los m�todos siguientes
para ello:

1. Usando GNOME 2.8 o posterior
   Ejecute gconf-editor (�Aplicaciones - Herramientas del sistema - Editor de
   configuraci�n�.
   Seleccione �desktop - gnome - interface� y marque �can-change-accels� en �l.

2. Usando versiones anteriores a GNOME 2.8 u otros entornos
   A�ada (o cree una nueva) gtk-can-change-accels = 1 al fichero ~/.gtkrc-2.0

3. Cuando Sylpheed no este ejecut�ndose, edite directamente el fichero 
   ~/.sylpheed-2.0/menurc usando un editor de texto.

Informaci�n
===========

Puede comprobar la versi�n m�s reciente e informaci�n sobre Sylpheed en:

	http://sylpheed.sraoss.jp/

Existe tambi�n un manual de Sylpheed escrito por
Yoichi Imai <yoichi@silver-forest.com> en:

	http://y-imai.good-day.net/sylpheed/

Inf�rmenos
==========

Comentarios, ideas y (la mayor�a de) informes de errores (y especialmente 
parches) son muy bienvenidos.

Subversion
==========

Puede obtener el c�digo fuente m�s reciente del repositorio Subversion.

Vaya a un directorio apropiado y con el comando:

	svn checkout svn://sylpheed.sraoss.jp/sylpheed/trunk

se crear� el �rbol de las fuentes con nombre �sylpheed� bajo el directorio
actual.

El subdirectorio de sylpheed est� dividido como sigue:

    * trunk/     �rbol principal
    * branches/  Ramas experimentales varias
    * tags/      Ramas etiquetadas de las versiones liberadas

Para actualizarse a los cambios m�s recientes, ejecute la orden:

	svn update

en el directorio correspondiente.

-- 
Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
