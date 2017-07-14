package utils;

import java.awt.GridLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * ComboBoxes and labels in a grid layout
 * 
 * @author henry
 */
public class ComboBoxPanel extends JPanel {

    private JComboBox<String>[] comboBoxes;
    
    public ComboBoxPanel(String... labelAndCommandText) {
        super();
        JLabel [] labels = new JLabel [labelAndCommandText.length/2];
        comboBoxes = new JComboBox[labels.length];
        for (int i=0; i<comboBoxes.length; i++) {
            labels[i] = new JLabel(labelAndCommandText[2*i]);
            comboBoxes[i] = new JComboBox<String>();
            comboBoxes[i].setSelectedIndex(-1);
            comboBoxes[i].setActionCommand(labelAndCommandText[2*i+1]);
        }
        setLayout(new GridLayout(labelAndCommandText.length/2, 2, 5, 5));
        for (int i=0; i<labelAndCommandText.length/2; i++) {
            add(labels[i]);
            add(comboBoxes[i]);
        }
    }

    public JComboBox<String>[] getComboBoxes() {
        return comboBoxes;
    }
    
    public void setEnabled(boolean... enabled) {
        for (int i=0; i<Math.min(comboBoxes.length, enabled.length); i++){
            comboBoxes[i].setEnabled(enabled[i]);
        } 
    }
    
}
