package utils;

import java.awt.GridLayout;
import java.util.ArrayList;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * ComboBoxes and labels in a grid layout
 *
 * @author henry
 */
public class ComboBoxPanel extends JPanel {

    private ArrayList<JComboBox<String>> comboBoxes;

    public ComboBoxPanel(String... labelAndCommandText) {
        super();
        JLabel[] labels = new JLabel[labelAndCommandText.length / 2];
        comboBoxes = new ArrayList<>();
        JComboBox<String> comboBox;
        for (int i = 0; i < labels.length; i++) {
            labels[i] = new JLabel(labelAndCommandText[2 * i]);
            comboBox = new JComboBox<>();
            comboBox.setSelectedIndex(-1);
            comboBox.setActionCommand(labelAndCommandText[2 * i + 1]);
            comboBoxes.add(comboBox);
        }
        setLayout(new GridLayout(labelAndCommandText.length / 2, 2, 5, 5));
        for (int i = 0; i < labelAndCommandText.length / 2; i++) {
            add(labels[i]);
            add(comboBoxes.get(i));
        }
    }

    public ArrayList<JComboBox<String>> getComboBoxes() {
        return comboBoxes;
    }

    public void setEnabled(boolean... enabled) {
        for (int i = 0; i < Math.min(comboBoxes.size(), enabled.length); i++) {
            comboBoxes.get(i).setEnabled(enabled[i]);
        }
    }

}
