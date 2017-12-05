ALLNETUI_JAR=AllNetUI.jar
ALLNETUI_TARGET=$(ALLNET_BINDIR)/$(ALLNETUI_JAR)

JAVASOURCELIST= \
    allnetui/Contact.java \
    allnetui/ContactComparator.java \
    allnetui/ContactConfigPanel.java \
    allnetui/ContactData.java \
    allnetui/ContactType.java \
    allnetui/ContactsPanel.java \
    allnetui/Conversation.java \
    allnetui/ConversationPanel.java \
    allnetui/CoreAPI.java \
    allnetui/CoreConnect.java \
    allnetui/KeyExchangePanel.java \
    allnetui/Message.java \
    allnetui/MorePanel.java \
    allnetui/NewContactPanel.java \
    allnetui/SocketUtils.java \
    allnetui/UIAPI.java \
    allnetui/UIController.java \
    allnetui/UI.java \
    allnetui/UITester.java \
    utils/ApplicationFrame.java \
    utils/BijectiveList.java \
    utils/CheckBoxPanel.java \
    utils/ComboBoxPanel.java \
    utils/ContactButtonPanel.java \
    utils/ControllerInterface.java \
    utils/HtmlLabel.java \
    utils/MessageBubble.java \
    utils/MyFrame.java \
    utils/RenamePanel.java \
    utils/RoundedBorder.java \
    utils/StatusPanel.java \
    utils/tabbedpane/MyTabbedPane.java \
    utils/tabbedpane/SimpleButton.java \
    utils/TextValidator.java \
    utils/WordWrapper.java

all: $(ALLNETUI_TARGET)

$(ALLNETUI_TARGET): $(JAVASOURCELIST)
if PRECOMP_GUI
	cp -a precompiled/$(ALLNETUI_JAR) $(ALLNETUI_TARGET)
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
