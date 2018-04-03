package allnetui;

import java.awt.Color;
import java.awt.Insets;
import java.lang.reflect.InvocationTargetException;
import javax.swing.JPanel;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import utils.ApplicationFrame;
import utils.ControllerInterface;
import utils.tabbedpane.MyTabbedPane;

/**
 *
 * @author Henry
 */
class UI extends ApplicationFrame {

    public static boolean debug = true;
    private static String[] debugContactNames
        = new String[]{"Alice", "Bob", "Charlie", "Dan", "Eve", "Frank"};
    private static final String myContactName = "self";
    // IDs for fixed panels
    public static final String CONTACTS_PANEL_ID = "CONTACTS_PANEL_ID";
    public static final String CONTACT_CONFIG_PANEL_ID
        = "CONTACT_CONFIG_PANEL_ID";
    public static final String NEW_CONTACT_PANEL_ID = "NEW_CONTACT_PANEL_ID";
    public static final String KEY_EXCHANGE_PANEL_ID = "KEY_EXCHANGE_PANEL_ID";
    public static final String MORE_PANEL_ID = "MORE_PANEL_ID";
    //
    // private static boolean debug = false;
    static final String TITLE = "xchat - AllNet Java UI";
    static final String VERSION = "0.01";
    //
    // init default colors
    private static Color bgndColor = new Color (224, 224, 224);
    private static Color otherColor = new Color(255, 215, 0);
    private static Color broadcastBackgroundColor = Color.PINK;
    private static Color broadcastContactColor = Color.BLUE;
    private static Color ackedBackgroundColor = Color.GREEN;
    // just to avoid a warning
    private static final long serialVersionUID = 1L;

    UI(String title, JPanel appPanel, ControllerInterface controller,
       boolean resizeOkay) {
        super(title, appPanel, controller, resizeOkay);
    }

    public static Color getBgndColor() {
        return bgndColor;
    }

    public static Color getAckedBgndColor() {
        return bgndColor;
    }

    public static Color getBroadcastBackgroundColor() {
        return broadcastBackgroundColor;
    }

    public static Color getBroadcastContactColor() {
        return ackedBackgroundColor;
    }

    public static Color getOtherColor() {
        return otherColor;
    }

    
    // application entry point, call with contact name if desired,
    public static void main(String... args) {
        if (args != null) {
            for (String arg : args) {
                if (arg.equalsIgnoreCase("debug")) {
                    debug = true;
                }
                else if (arg.equalsIgnoreCase("nodebug")) {
                    debug = false;
                }
            }
        }
        // use a default font
        System.setProperty("awt.useSystemAAFontSettings", "on");
        try {
            // NOTE: if we set a L&F, then we won't be able to
            // set button colors easily
            // UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
            // let individual panels determine border 
            UIManager.put("TabbedPane.contentBorderInsets",
                          new Insets(0, 0, 0, 0));
        }
        catch (ClassNotFoundException | InstantiationException
              | IllegalAccessException | UnsupportedLookAndFeelException ex) {
            System.out.println(ex);
        }
        try {
            // create the UI in the event-dispatching thread
            javax.swing.SwingUtilities.invokeAndWait(new Runnable() {

                @Override
                public void run() {
                    ContactData contactData = new ContactData();
                    UIController controller = new UIController(contactData);

                    ConversationPanel.setDefaultColors(bgndColor, otherColor,
                                                       broadcastBackgroundColor,
                                                       ackedBackgroundColor);
                    ContactsPanel contactsPanel =
                      new ContactsPanel("&nbsp;contacts panel <br>&nbsp;loading contacts...", bgndColor,
                                        otherColor, broadcastContactColor,
                                        contactData);
                    String p = " exchange a key with a new contact<br>&nbsp;";
                    NewContactPanel newContactPanel =
                        new NewContactPanel(p, bgndColor, otherColor);
                    MorePanel morePanel =
                        new MorePanel(bgndColor, otherColor);
                    ContactConfigPanel contactConfigPanel
                        = new ContactConfigPanel(contactData, controller);
                    //
                    MyTabbedPane uiTabs = new MyTabbedPane();
                    uiTabs.addTab(MORE_PANEL_ID, "More", morePanel);
                    uiTabs.addTab(CONTACT_CONFIG_PANEL_ID, "Edit Contact",
                                  contactConfigPanel);                    
                    uiTabs.addTab(NEW_CONTACT_PANEL_ID, "New Contact",
                                  newContactPanel);
                    uiTabs.addTab(CONTACTS_PANEL_ID, "Contacts", contactsPanel);
                    uiTabs.setSelected(contactsPanel);                    
                    //
                    // controller needs a references to the panels in the ui
                    // and also to register to listen for events from
                    // those panels
                    controller.setContactsPanel(contactsPanel);
                    controller.setContactConfigPanel(contactConfigPanel);
                    controller.setNewContactPanel(newContactPanel);
                    controller.setMorePanel(morePanel);
                    controller.setMyTabbedPane(uiTabs);
                    // update the contacts tab
                    // controller.updateContactsPanelStatus(); -- do it later
                    // tell controller when the selected tab changes
                    uiTabs.setListener(controller);

                    UI ui = new UI(TITLE, uiTabs, controller, true);
                    ui.setMyLocation("center");
                    ui.setVisible(true);

                    // make a tester frame to generate message
                    // for the UI to display
                    if (UI.debug) {
                        UITester test = new UITester(controller);
                        for (String contactName : debugContactNames) {
                            controller.contactCreated(contactName);
                        }
                        CoreAPI coreAPI = new CoreDebug ();
                        controller.setCore (coreAPI);
                    }
                    else {
                        CoreConnect coreAPI = new CoreConnect (controller);
                        controller.setCore (coreAPI);
                        coreAPI.start ();
                    }
                }
            }); // end of invokeAndWait
        }
        catch (InterruptedException ex) {
            // Logger.getLogger(AllnetUI.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println(ex + " in application entry point");
        }
        catch (InvocationTargetException ex) {
            System.out.println(ex + " with cause " + ex.getCause ());
        }
    }
}
