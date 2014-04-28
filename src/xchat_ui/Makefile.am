ALLNETUIJAR=AllNetUI.jar

clean-local:
	rm -f */*.class

all-local:
if ENABLE_GUI
	$(JAVAC) */*.java
	$(JAR) cfe $(ALLNET_BINDIR)/$(ALLNETUIJAR) allnetui.UI allnetui/*.class utils/*.class
endif

install-exec-local:
if ENABLE_GUI
	$(INSTALL_PROGRAM) $(ALLNET_BINDIR)/$(ALLNETUIJAR) $(DESTDIR)$(bindir)
endif

uninstall-local:
if ENABLE_GUI
	rm -f $(DESTDIR)$(bindir)/$(ALLNETUIJAR)
endif
