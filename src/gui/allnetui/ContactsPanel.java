package allnetui;

import java.awt.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import javax.swing.*;
import javax.swing.border.LineBorder;
import utils.HtmlLabel;
import utils.ScrollPaneResizeAdapter;

/**
 * Keep 2 panels of buttons, keyed by name, and provide methods to add/delete
 * the buttons, to set their displayed text, and to move them between the 2
 * panels.
 *
 *
 * @author Henry
 */
class ContactsPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    // 2 panels for the buttons
    //private JPanel topPanel, bottomPanel;
    // one panel to combine them and allow scrolling
    // private JPanel bothPanel;
    private JPanel buttonsPanel;
    // list of which names' buttons are in which panel
    private ArrayList<String> topNames, bottomNames;
    // associate each name with a button
    private HashMap<String, JButton> map;
    private HtmlLabel topLabel;
    // action commands will look like this:  ContactsPanel:name 
    private String commandPrefix = "ContactsPanel";
    // save the action listener so we can set it for any new buttons created
    private ActionListener listener;
    private Color broadcastColor;
    private java.util.Comparator<String> comparator;
    private JScrollPane scrollPane;
    private ContactData contactData;

    ContactsPanel(String info, Color background, Color foreground,
        Color broadcastColor, ContactData contactData) {
        super();
        this.broadcastColor = broadcastColor;
        this.contactData = contactData;
        map = new HashMap<>();
        comparator = new ContactComparator(contactData);
        setBackground(background);
        // make the info label for the top of the panel
        topLabel = new HtmlLabel(info);
        topLabel.setOpaque(true);
        topLabel.setBackground(foreground);
        topLabel.setLineBorder(Color.BLACK, 1, false);
        // create the main content panel, scrollPane which holds bothPanel
        buildScrollPane(background);
        // put into the contacts panel: topPanel, space, scrollPane
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        add(topLabel, gbc);
        gbc.gridy++;
        add(Box.createRigidArea(new Dimension(0, 5)), gbc);
        gbc.gridy++;
        //
        gbc.anchor = GridBagConstraints.PAGE_START;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        add(scrollPane, gbc);
    }

    private void buildScrollPane(Color background) {
        topNames = new ArrayList<>();
        bottomNames = new ArrayList<>();
        // topPanel = makePanel(background);
        // bottomPanel = makePanel(background);
        // bothPanel = makePanel(background);
        buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.Y_AXIS));
        buttonsPanel.setBackground(background);
        scrollPane = makeScrollPane(buttonsPanel);
        scrollPane.getVerticalScrollBar().addComponentListener(
            new ScrollPaneResizeAdapter(scrollPane, false));
    }

    private JScrollPane makeScrollPane(JPanel panel) {
        JScrollPane scrP
            = new JScrollPane(
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                // ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        Dimension scrDim = new Dimension(1, 1);
        scrP.setMinimumSize(scrDim);
        scrP.setPreferredSize(scrDim);
        scrP.setMaximumSize(scrDim);
        scrP.setViewportView(panel);
        // don't want a border around it
        scrP.setBorder(BorderFactory.createEmptyBorder());
        return scrP;
    }

    private JPanel makePanel(Color background) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(background);
        panel.setBorder(new LineBorder(Color.BLACK, 1));
        return (panel);
    }

    // set the named button's text and place it in the top panel
    void placeInTop(String name, String text, boolean broadcast) {
        placeIt(name, text, topNames, bottomNames, broadcast);
    }

    void placeInBottom(String name, String text, boolean broadcast) {
        placeIt(name, text, bottomNames, topNames, broadcast);
    }

    private void placeIt(String name, String text,
        ArrayList<String> toNames, ArrayList<String> otherNames,
        boolean broadcast) {
        boolean changed = false;
        JButton button = map.get(name);
        if (button == null) {
            // doesn't exist yet
            button = makeButton(name, text, broadcast);
            map.put(name, button);
            toNames.add(name);
            changed = true;
        }
        else {
            button.setText(text);
            if (!toNames.contains(name)) {
                // we have to move it
                otherNames.remove(name);
                toNames.add(name);
                changed = true;
            }
        }
        // redo the layout only if changed something
        if (changed) {
            updateButtonsPanel();
        }
    }

    public void updateButtonsPanel() {
        buttonsPanel.removeAll();
        java.util.Collections.sort(topNames, comparator);
        for (String b : topNames) {
            if (contactData.isVisible(b)) {
                buttonsPanel.add(map.get(b));
            }
        }
        if (!topNames.isEmpty()) {
            buttonsPanel.add(Box.createRigidArea(new Dimension(0, 20)));
        }
        java.util.Collections.sort(bottomNames, comparator);
        for (String b : bottomNames) {
            if (contactData.isVisible(b)) {
                buttonsPanel.add(map.get(b));
            }
        }
        buttonsPanel.revalidate();
    }

    private JButton makeButton(String name, String text, boolean broadcast) {
        JButton button = new JButton(text);
        if (broadcast) {
            // use L&F default if not broadcast
            button.setForeground(broadcastColor);
        }
        // button.setBackground(Color.WHITE);
        // button.setRolloverEnabled(false); 
        button.setActionCommand(commandPrefix + ":" + name);
        button.setText(text);
        // put text at left of button
        button.setHorizontalAlignment(SwingConstants.LEFT);
        // where to send events
        if (listener != null) {
            button.addActionListener(listener);
        }
        // set for no max width
        Dimension d = button.getMaximumSize();
        d.width = Integer.MAX_VALUE;
        button.setMaximumSize(d);
        return (button);
    }

    void removeName(String name) {
        JButton button = map.get(name);
        if (button != null) {
            // delete it from everywhere
            map.remove(name);
            topNames.remove(name);
            bottomNames.remove(name);
            updateButtonsPanel();
        }
    }

    void setTopLabelText(String... lines) {
        topLabel.setText(lines);
    }

    // only need to call this once; it will add the listener to all extant 
    // buttons, and to any that are subsequently created
    void setActionListener(ActionListener listener) {
        this.listener = listener;
        Iterator<String> it = map.keySet().iterator();
        JButton button;
        while (it.hasNext()) {
            button = map.get(it.next());
            button.addActionListener(listener);
        }
    }

    String getCommandPrefix() {
        return commandPrefix;
    }

    // change the command prefix; must do before creating any buttons
    void setCommandPrefix(String commandPrefix) {
        if (!map.isEmpty()) {
            throw new RuntimeException("tried to change command prefix after buttons were created");
        }
        this.commandPrefix = commandPrefix;
    }
}
