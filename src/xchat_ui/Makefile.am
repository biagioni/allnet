ALLNETUI_JAR=AllNetUI.jar
ALLNETUI_TARGET=$(ALLNET_BINDIR)/$(ALLNETUI_JAR)

all: $(ALLNETUI_TARGET)

$(ALLNETUI_TARGET):
if PRECOMP_GUI
	cp precompiled/$(ALLNETUI_JAR) $(ALLNETUI_TARGET)
endif
if ENABLE_GUI
	$(JAVAC) */*.java */*/*.java
	$(JAR) cfe $(ALLNETUI_TARGET) allnetui.UI allnetui/*.class utils/*.class utils/tabbedpane/*.class utils/tabbedpane/*.png
endif

clean-local:
	rm -f */*.class */*/*.class
	rm -f $(ALLNETUI_TARGET)

install-exec-local:
if PRECOMP_GUI
	$(INSTALL_PROGRAM) $(ALLNETUI_TARGET) $(DESTDIR)$(bindir)
endif
if ENABLE_GUI
	$(INSTALL_PROGRAM) $(ALLNETUI_TARGET) $(DESTDIR)$(bindir)
endif

uninstall-local:
if ENABLE_GUI
	rm -f $(DESTDIR)$(bindir)/$(ALLNETUIJAR)
endif
