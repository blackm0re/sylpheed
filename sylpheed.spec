%define ver 3.7.0
%define rel %(if [ "${SYLPHEED_REL_DIST}" == "" ] ; then echo "1"; else echo "${SYLPHEED_REL_DIST}"; fi)

Summary: a GTK+ based, lightweight, and fast e-mail client
Name: sylpheed
Version: %{ver}
Release: %{rel}%{?dist}
Source: http://sylpheed.sraoss.jp/sylpheed/%{name}-%{ver}.tar.gz
License: GPL
URL: http://sylpheed.sraoss.jp/
Requires: gtk2 >= 2.4.0
Group: Applications/Internet
Packager: Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
Buildroot: %{_tmppath}/%{name}-root

%changelog
* Thu Sep 26 2012 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- added sylpheed-plugins package.
- added dist to Release.
- fixed plugindir.

* Thu Sep 13 2012 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- fixed build on x86_64 platform.

* Tue Aug 4 2009 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- fixed %files section.

* Tue May 20 2008 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated %files section.

* Thu Feb 10 2006 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- changed Requires: package name from gtk+ to gtk2.

* Tue Jun 7 2005 Paul Dickson <paul@permanentmail.com>
- replaced "Copyright:" with "License:"
- if environmental variable SYLPHEED_REL_DIST is set, assign that to rel (1.FC4,2.FC4, etc)

* Thu Feb 3 2005 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- modified for the latest version

* Fri Aug 1 2003 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- omitted %changelog
- modified %description

* Thu Jul 31 2003 Andre Costa <acosta@ar.microlink.com.br>
- used more extensively RPM's builtin vars

* Tue Feb 4 2003 Andre Costa <acosta@ar.microlink.com.br>
- implemented SYLPHEED_CONFIGURE_FLAGS in %build phase
- BuildRoot: is now more portable
- included sylpheed's pixmaps into the package

* Tue Jan 9 2001 Yoichi Imai <yoichi@silver-forest.com>
- edited for spec.in

* Fri Dec 1 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.4.7, and updated %description

* Thu Sep 28 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.4.1, and modified %files

* Wed Sep 27 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.4.0, and modified %description

* Tue Sep 26 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.3.99, and modified %files

* Sat Aug 19 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.3.26, and modified URL

* Sun Jul 4 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.3.21, and modified Summary

* Sun Jun 11 2000 Hiroyuki Yamamoto <hiro-y@kcn.ne.jp>
- updated to 0.3.15 and modified description and doc

* Sun Jun 4 2000 Yoichi Imai <yoichi@silver-forest.com>
- some change

* Sat Apr 29 2000 Yoichi Imai <yoichi@silver-forest.com>
- gnome-menu and requires header change

* Wed Feb 5 2000 Yoichi Imai <yoichi@silver-forest.com>
- append "TODO.jp"

* Sat Jan 1 2000 Yoichi Imai <yoichi@silver-forest.com>
- first release for version 0.1.0

%description
Sylpheed is an e-mail client (and news reader) based on GTK+, running on
X Window System, and aiming for
 * Quick response
 * Simple, graceful, and well-polished interface
 * Easy configuration
 * Intuitive operation
 * Abundant features
The appearance and interface are similar to some popular e-mail clients for
Windows, such as Outlook Express, Becky!, and Datula. The interface is also
designed to emulate the mailers on Emacsen, and almost all commands are
accessible with the keyboard.

The messages are managed by MH format, and you'll be able to use it together
with another mailer based on MH format (like Mew). You can also utilize
fetchmail or/and procmail, and external programs on receiving (like inc or
imget).

%package plugins
Summary: standard plug-ins for Sylpheed
Group: Applications/Internet
Requires: %{name} = %{version}-%{release}

%description plugins
The %{name}-plugins package contains standard plug-ins for Sylpheed.

%prep
%setup -q

%build
export CFLAGS="$CFLAGS $RPM_OPT_FLAGS"
%{configure} --with-plugindir=%{_libdir}/sylpheed/plugins ${SYLPHEED_CONFIGURE_FLAGS}
%{__make}

%install
%makeinstall
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/pixmaps
install -m 644 *.png ${RPM_BUILD_ROOT}%{_datadir}/pixmaps

(cd plugin/attachment_tool && %{__make} prefix=${RPM_BUILD_ROOT}%{prefix} libdir=${RPM_BUILD_ROOT}%{_libdir}/sylpheed/plugins install-plugin)
cp plugin/attachment_tool/README README.attachment_tool

%clean
rm -rf ${RPM_BUILD_ROOT}

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%defattr(-,root,root)
%doc AUTHORS COPYING COPYING.LIB ChangeLog ChangeLog.ja ChangeLog-1.0 ChangeLog-1.0.ja README README.es README.ja INSTALL INSTALL.ja NEWS NEWS-1.0 NEWS-2.0 LICENSE TODO TODO.ja
%{_bindir}/%{name}
%{_includedir}/%{name}
%{_libdir}/*.la
%{_libdir}/*.so
%{_libdir}/*.so.*
%{_datadir}/locale/*/LC_MESSAGES/%{name}.mo
%{_datadir}/%{name}/faq/*/*
%{_datadir}/%{name}/manual/*/*
%{_datadir}/pixmaps/*.png
%{_datadir}/applications/sylpheed.desktop

%files plugins
%defattr(-,root,root)
%doc README.attachment_tool
%{_libdir}/sylpheed/plugins/*
