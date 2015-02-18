package utils;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionListener;
import java.util.Arrays;
import javax.swing.*;

/**
 *
 * @author Henry
 */
public class StatusPanel extends JPanel {
    
    private static final long serialVersionUID = 1L;
    private String commandPrefix;
    private JButton[] buttons;
    private String [] buttonNames;
    private HtmlLabel[] labels;
    private int[] labelHeights;
    private Color[] labelColors;
    private boolean[] labelVisible;
    private Color background;

    // labelHeights is the number of lines for each label to hold
    // buttonsAndCommands[] format is button, command, button, command...
    public StatusPanel(int[] labelHeights, Color background, Color foreground,
            String commandPrefix, String... buttonsAndCommands) {
        this.labelHeights = labelHeights;
        this.background = background;
        this.commandPrefix = commandPrefix;
        labels = new HtmlLabel[labelHeights.length];
        labelColors = new Color[labels.length];
        Arrays.fill(labelColors, foreground);
        labelVisible = new boolean[labels.length];
        Arrays.fill(labelVisible, true);
        for (int i = 0; i < labels.length; i++) {
            labels[i] = new HtmlLabel(makeBlankLines(labelHeights[i]));
            labels[i].setOpaque(true);
            labels[i].setBackground(labelColors[i]);
            labels[i].setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
        }        
        setBackground(background);
        // make the buttons and panel to hold them
        JPanel buttonPanel = new JPanel();
        buttonPanel.setBackground(background);
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.X_AXIS));
        // space the buttons reasonably
        buttonPanel.add(Box.createHorizontalGlue());
        buttons = new JButton[buttonsAndCommands.length / 2];
        buttonNames = new String [buttons.length];
        for (int i = 0; i < buttons.length; i++) {
            buttons[i] = new JButton(buttonsAndCommands[2 * i]);
            buttonNames[i] = buttonsAndCommands[2 * i];
            buttons[i].setActionCommand(commandPrefix + ":" + buttonsAndCommands[2 * i + 1]);
            buttonPanel.add(buttons[i]);
            buttonPanel.add(Box.createHorizontalGlue());
        }
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 1;
        gbc.gridwidth = 1;
        for (HtmlLabel label : labels) {
            add(label, gbc);
            gbc.gridy++;
            add(Box.createVerticalGlue(), gbc);
            gbc.gridy++;
        }
        gbc.anchor = GridBagConstraints.SOUTH;
        add(buttonPanel, gbc);
    }

    // like the name says
    public void setTopLabelText(String... lines) {
        setText(0, lines);
    }

    // set where we will send events
    public void setListener(ActionListener listener) {
        for (JButton button : buttons) {
            button.addActionListener(listener);
        }
    }
    
    public String getCommandPrefix() {
        return commandPrefix;
    }
    
    public void setCommandPrefix(String commandPrefix) {
        this.commandPrefix = commandPrefix;
    }
    
    public void hideLabel(int idx) {
        clearText(idx);
        labels[idx].setOpaque(false);
        labels[idx].setBorder(BorderFactory.createLineBorder(background, 1));
    }

    public void unHideLabel(int idx) {
        labels[idx].setOpaque(true);
        labels[idx].setBorder(BorderFactory.createLineBorder(Color.BLACK, 1));
    }
    
    public void clearText(int idx) {
        setText(idx);
    }
    
    public void setText(int idx, String... input) {
        if (input == null) {
            input = new String []{};
        }
        String[] lines = new String[labelHeights[idx]];
        for (int i = 0; i < lines.length; i++) {
            if (i < input.length) {
                lines[i] = input[i];
            }
            else {
                lines[i] = " ";
            }
        }
        labels[idx].setText(lines);
    }
    
    public void setColor(int idx, Color color) {
        labels[idx].setBackground(color);
        labelColors[idx] = color;
    }
    
    public JButton getButton(String name) {
        for (int i=0; i<buttons.length; i++) {
            if (buttons[i].getText().equals(name)) {
                return(buttons[i]);
            }
        }
        return(null);
    }
        
    private String[] makeBlankLines(int n) {
        String[] lines = new String[n];
        Arrays.fill(lines, " ");
        return (lines);
    }
}
