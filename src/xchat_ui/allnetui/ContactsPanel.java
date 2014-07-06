package allnetui;

import java.awt.*;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import javax.swing.*;
import utils.HtmlLabel;

/**
 * Keep 2 panels of buttons, keyed by name, and provide methods to add/delete
 * the buttons, to set their displayed text, and to move them between the 2 panels.  
 * 
 * 
 * @author Henry
 */
class ContactsPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    // 2 panels for the buttons
    private JPanel topPanel, bottomPanel;
    // list of which names' buttons are in which panel
    private ArrayList<String> topNames, bottomNames;
    // associate each name with a button
    private HashMap<String, JButton> map;
    private HtmlLabel topLabel;
    // action commands will look like this:  ContactsPanel:name 
    private String commandPrefix = "ContactsPanel";
    // save the action listener so we can set it for any new buttons created
    private ActionListener listener;

    ContactsPanel(String info, Color background, Color foreground, Color bc) {
        super();
        map = new HashMap<>();
        topNames = new ArrayList<>();
        bottomNames = new ArrayList<>();
        topPanel = makePanel(background);
        bottomPanel = makePanel(background);
        setBackground(background);
        // make the info label for the top of the panel
        topLabel = new HtmlLabel(info);
        topLabel.setOpaque(true);
        topLabel.setBackground(foreground);
System.out.println("ContactsPanel.java todo: make broadcast messages a different color");
        topLabel.setLineBorder(Color.BLACK, 1, false);
        //
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        add(topLabel, gbc);
        gbc.gridy++;
        add(Box.createRigidArea(new Dimension(0, 10)), gbc);
        gbc.gridy++;
        add(topPanel, gbc);
        gbc.gridy++;
        add(Box.createRigidArea(new Dimension(0, 10)), gbc);
        gbc.gridy++;
        add(bottomPanel, gbc);
        gbc.gridy++;
        // expand bottom area vertically to fill extra space
        gbc.weighty = 1.0;
        add(Box.createRigidArea(new Dimension(0, 10)), gbc);
    }

    private JPanel makePanel(Color background) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(background);
        // panel.setBorder(new LineBorder(Color.BLACK, 1));
        return (panel);
    }

    // set the named button's text and place it in the top panel
    void placeInTop(String name, String text) {
        placeIt(name, text, topPanel, bottomPanel, topNames, bottomNames);
    }

    void placeInBottom(String name, String text) {
        placeIt(name, text, bottomPanel, topPanel, bottomNames, topNames);
    }

    private void placeIt(String name, String text, JPanel to, JPanel other, ArrayList<String> toNames, ArrayList<String> otherNames) {
        boolean changed = false;
        JButton button = map.get(name);
        if (button == null) {
            // doesn't exist yet
            button = makeButton(name, text);
            map.put(name, button);
            toNames.add(name);
            updatePanel(to, toNames);
            changed = true;
        }
        else {
            button.setText(text);
            if (!toNames.contains(name)) {
                // we have to move it
                other.remove(button);
                otherNames.remove(name);
                toNames.add(name);
                updatePanel(to, toNames);
                changed = true;
            }
        }
        // redo the layout only if changed something
        if (changed) {
            validate();
        }
    }

    private void updatePanel(JPanel to, ArrayList<String> toNames) {
        JButton b;
        Collections.sort(toNames);
        to.removeAll();
        for (String name : toNames) {
            b = map.get(name);
            to.add(b);
        }
    }

    private JButton makeButton(String name, String text) {
        JButton button = new JButton(text);
        button.setBackground(Color.WHITE);
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
            topPanel.remove(button);
            topNames.remove(name);
            bottomPanel.remove(button);
            bottomNames.remove(name);
            validate();
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
