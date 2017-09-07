package allnetui;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.Border;
import utils.CheckBoxPanel;
import utils.ComboBoxPanel;
import utils.ContactButtonPanel;
import utils.HtmlLabel;
import utils.RenamePanel;

/**
 *
 * @author Henry
 */
public class ContactConfigPanel extends JPanel implements ActionListener {

    // just to avoid a warning
    private static final long serialVersionUID = 1L;
    //
    private ContactData contactData;
    private UIController controller;
    // define this panel's internal commands here
    private final String SAVE_CHANGES = "SAVE_CHANGES";
    private final String EXPORT_CONVERSATION = "EXPORT_CONVERSATION";
    private final String CLEAR_CONVERSATION = "CLEAR_CONVERSATION";
    private final String DELETE_CONTACT = "DELETE_CONTACT";
    private final String CONTACT_SELECT = "CONTACT_SELECT";
    private final String CANCEL_EDIT = "CANCEL_EDIT";

    // default colors to use
    // same as in UI.java, awkward should be in one place...
    private static Color bgndColor = new Color(224, 224, 224);
    private static Color otherColor = new Color(255, 215, 0);
    //
    private HtmlLabel topLabel;
    private ComboBoxPanel contactSelectPanel;
    private ComboBoxPanel groupsPanel;
    private CheckBoxPanel configPanel;
    private RenamePanel renamePanel;
    //
    private JButton saveButton;
    private JButton cancelButton;

    public ContactConfigPanel(ContactData contactData,
        UIController controller) {
        this.contactData = contactData;
        this.controller = controller;
        setBackground(bgndColor);
        // make the info label for the top of the panel
        topLabel = new HtmlLabel("Contact Configuration and Management" + "<br>&nbsp;");
        topLabel.setOpaque(true);
        topLabel.setBackground(otherColor);
        topLabel.setLineBorder(Color.BLACK, 1, false);
        //
        contactSelectPanel = new ComboBoxPanel("Contact:", CONTACT_SELECT);
        contactSelectPanel.setBackground(bgndColor);
        contactSelectPanel.setBorder(makeMarginBorder(5, "Select"));
        contactSelectPanel.getComboBoxes().get(0).addActionListener(this);
        //
        groupsPanel = new ComboBoxPanel("Add to Group:", "",
            "Remove from Group:", "");
        groupsPanel.setBackground(bgndColor);
        //
        configPanel = new CheckBoxPanel("Notify", "Save Messages", "Visible");
        configPanel.setBackground(bgndColor);
        //
        renamePanel = new RenamePanel();
        renamePanel.setBackground(bgndColor);
        //
        saveButton = new JButton("Save Changes");
        saveButton.setActionCommand(SAVE_CHANGES);
        cancelButton = new JButton("Cancel");
        cancelButton.setActionCommand(CANCEL_EDIT);
        saveButton.addActionListener(this);
        cancelButton.addActionListener(this);
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(1, 2, 5, 5));
        buttonPanel.add(cancelButton);
        buttonPanel.add(saveButton);
        buttonPanel.setBackground(bgndColor);
        //
        ContactButtonPanel cbPanel = new ContactButtonPanel();
        cbPanel.setBackground(bgndColor);
        cbPanel.setBorder(makeMarginBorder(5, "Manage"));
        cbPanel.addListener(this);
        //        
        JPanel lowerPanel = new JPanel();
        lowerPanel.setLayout(new BoxLayout(lowerPanel, BoxLayout.Y_AXIS));
        lowerPanel.add(configPanel);
        lowerPanel.add(Box.createVerticalStrut(10));
        lowerPanel.add(groupsPanel);
        lowerPanel.add(Box.createVerticalStrut(10));
        lowerPanel.add(renamePanel);
        lowerPanel.add(Box.createVerticalStrut(10));
        lowerPanel.add(buttonPanel);
        lowerPanel.setBackground(bgndColor);
        lowerPanel.setBorder(makeMarginBorder(5, "Configure"));
        //
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.PAGE_START;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        add(topLabel, gbc);
        // gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridy++;
        add(contactSelectPanel, gbc);
        //
        gbc.gridy++;
        add(lowerPanel, gbc);
        //
        gbc.gridy++;
        add(cbPanel, gbc);
        //
        gbc.gridy++;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        add(Box.createVerticalGlue(), gbc);
        //
        init();
    }

    public void update() {
        JComboBox<String> contactBox = contactSelectPanel.getComboBoxes().get(0);
        contactBox.removeAllItems();
        ArrayList<String> list = contactData.getContactsList();
        for (String contact : list) {
            contactBox.addItem(contact);
        }
        init();
    }

    public final void init() {
        JComboBox contactBox = contactSelectPanel.getComboBoxes().get(0);
        contactBox.setSelectedIndex(-1);
        ArrayList<JComboBox<String>> groupsBoxes = groupsPanel.getComboBoxes();
        groupsBoxes.get(0).removeAllItems();
        groupsBoxes.get(1).removeAllItems();
        groupsPanel.setEnabled(false, false);
        configPanel.init();
        renamePanel.init();
    }

    private void init(String contactName) {
        Contact contact = contactData.getContact(contactName);
        JCheckBox[] cbs = configPanel.getCheckBoxes();
        cbs[0].setSelected(contact.isNotify());
        cbs[1].setSelected(contact.isSaveMessages());
        cbs[2].setSelected(contact.isVisible());
        //
        ArrayList<JComboBox<String>> groupsBoxes = groupsPanel.getComboBoxes();
        groupsBoxes.get(0).removeAllItems();
        ArrayList<String> allGroups = contactData.getGroupsList();
        if (allGroups.isEmpty()) {
            groupsPanel.setEnabled(false, false);
        }
        else {
            groupsPanel.setEnabled(true, true);
            for (String gpName : allGroups) {
                if (!contact.getGroups().contains(gpName)) {
                    groupsBoxes.get(0).addItem(gpName);
                }
            }
            groupsBoxes.get(1).removeAllItems();
            for (String gpName : contact.getGroups()) {
                groupsBoxes.get(1).addItem(gpName);
            }
            if (contact.getGroups().isEmpty()) {
                groupsBoxes.get(1).setEnabled(false);
            }
        }
    }

    private Border makeMarginBorder(int margin, String title) {
        Border outer = BorderFactory.createLineBorder(Color.BLACK, 1);
        Border titled = BorderFactory.createTitledBorder(outer, title);
        Border inner = BorderFactory.createEmptyBorder(margin, margin,
            margin, margin);
        Border border = BorderFactory.createCompoundBorder(titled, inner);
        return (border);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String command = e.getActionCommand();
        // System.out.println(command);
        switch (command) {
            case CONTACT_SELECT:
                // fetch and display contact's config info
                processContactSelect();
                break;
            case CANCEL_EDIT:
                // clear contact selection and displayed config info
                init();
                break;
            case SAVE_CHANGES:
                // save info to contact, notify UIController
                saveChanges();
                break;
            case EXPORT_CONVERSATION:
                exportConversation();
                break;
            case CLEAR_CONVERSATION:
                clearConversation();
                break;
            case DELETE_CONTACT:
                deleteContact();
                break;

            default:
                throw new RuntimeException("bad command!?");

        }

    }

    private void processContactSelect() {
        JComboBox<String> contactBox = contactSelectPanel.getComboBoxes().get(0);
        if (contactBox.getSelectedIndex() == -1) {
            init();
        }
        else {
            String contact = (String) contactBox.getSelectedItem();
            init(contact);
        }
    }

    private void saveChanges() {
        // options are right to left, ie cancel will be on right
        Object[] options = {"Cancel", "Save Changes"};
        JComboBox<String> contactBox =
            contactSelectPanel.getComboBoxes().get(0);
        String contactName = (String) contactBox.getSelectedItem();
        int n = JOptionPane.showOptionDialog(this,
            "Saving changes for " + contactName + " cannot be undone.  ",
            "Confirm Save Changes",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
            null,
            options,
            options[0]);
        // NO_OPTION actually means the elft button, ie do it
        if (n != JOptionPane.NO_OPTION) {
            return;
        }
        // that's a go, so let's do it
        Contact contact = contactData.getContact(contactName);
        JCheckBox[] cbs = configPanel.getCheckBoxes();
        contact.setNotify(cbs[0].isSelected());
        contact.setSaveMessages(cbs[1].isSelected());
        contact.setVisible(cbs[2].isSelected());
        //
        ArrayList<JComboBox<String>> groupsBoxes = groupsPanel.getComboBoxes();
        String groupToAdd = (String) groupsBoxes.get(0).getSelectedItem();
        if (groupToAdd != null) {
            contact.getGroups().add(groupToAdd);
        }
        String groupToDelete = (String) groupsBoxes.get(1).getSelectedItem();
        if (groupToDelete != null) {
            contact.getGroups().remove(groupToDelete);
        }
        //
        controller.contactModified(contactName);
    }

    private void clearConversation() {
        // right to left
        Object[] options = {"Cancel", "Clear Conversation"};
        JComboBox contactBox = contactSelectPanel.getComboBoxes().get(0);
        String contact = (String) contactBox.getSelectedItem();
        int n = JOptionPane.showOptionDialog(this,
            "Clearing conversation for " + contact + " cannot be undone.  ",
            "Confirm Clear Conversation",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
            null, //do not use a custom Icon
            options, //the titles of buttons
            options[0]); //default button title
        // NO_OPTION means the left button
        if (n == JOptionPane.NO_OPTION) {
            // that's a go, so tell the UIController to do it
            controller.clearConversation(contact);
        }

    }

    private void exportConversation() {
        System.out.println("exportConversation not implemented yet");
    }

    private void deleteContact() {
        // cancel will be on right
        Object[] options = {"Cancel", "DELETE CONTACT"};
        JComboBox<String> contactBox
            = contactSelectPanel.getComboBoxes().get(0);
        String contact = (String) contactBox.getSelectedItem();
        int n = JOptionPane.showOptionDialog(this,
            "Deleting contact " + contact + " cannot be undone.  ",
            "Confirm Delete Contact",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE,
            null,
            options,
            options[0]);
        // NO_OPTION means the left button, so do it
        if (n == JOptionPane.NO_OPTION) {
            // that's a go, so tell the UIController to do it
            controller.contactDeleted(contact);
        }

    }

}
