package utils;

import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;

/**
 * ComponentAdapter to scroll a JScrollPane to the top or bottom when resized.
 * 
 * @author Henry
 */
public class ScrollPaneResizeAdapter extends ComponentAdapter {

    private JScrollPane scrollPane;
    private boolean scrollToBottom;

    public ScrollPaneResizeAdapter(JScrollPane scrollPane, boolean scrollToBottom) {
        this.scrollPane = scrollPane;
        this.scrollToBottom = scrollToBottom;
    }

    @Override
    public void componentResized(ComponentEvent e) {
        JScrollBar bar = scrollPane.getVerticalScrollBar();
        if (bar != null) {
            if (scrollToBottom) {
                bar.setValue(bar.getMaximum());
            }
            else {
                bar.setValue(bar.getMinimum());
            }
        }
    }
}
