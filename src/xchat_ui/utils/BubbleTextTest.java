/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package utils;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.IOException;
import javax.imageio.ImageIO;
import javax.swing.*;

public class BubbleTextTest {

    public static void main(String[] args) {
        new BubbleTextTest();
    }

    public BubbleTextTest() {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | UnsupportedLookAndFeelException ex) {
                }

                JFrame frame = new JFrame("Testing");
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
                frame.setLayout(new BorderLayout());
                frame.add(new TestPane());
                frame.pack();
                frame.setLocationRelativeTo(null);
                frame.setVisible(true);
            }
        });
    }

    public class TestPane extends JPanel {

        private JLabel label;

        public TestPane() {

            String text = "<html>I am the very model of a modern Major-General,<br>";
            text += "I've information vegetable, animal, and mineral,<br>";
            text += "I know the kings of England, and I quote the fights historical<br>";
            text += "From Marathon to Waterloo, in order categorical;a<br>";
            text += "I'm very well acquainted, too, with matters mathematical,<br>";
            text += "I understand equations, both the simple and quadratical,<br>";
            text += "About binomial theorem I'm teeming with a lot o' news, (bothered for a rhyme)<br>";
            text += "With many cheerful facts about the square of the hypotenuse.<br>";

            label = new JLabel(text);

            setBackground(new Color(209, 209, 209));

            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            try {
                add(new JLabel(new ImageIcon(ImageIO.read(getClass().getResource("/TopLeft.png")))), gbc);
                gbc.gridx = 2;
                add(new JLabel(new ImageIcon(ImageIO.read(getClass().getResource("/TopRight.png")))), gbc);

                gbc.gridy = 2;
                gbc.gridx = 0;
                add(new JLabel(new ImageIcon(ImageIO.read(getClass().getResource("/BottomLeft.png")))), gbc);
                gbc.gridx = 2;
                add(new JLabel(new ImageIcon(ImageIO.read(getClass().getResource("/BottomRight.png")))), gbc);

                gbc.gridx = 1;
                gbc.gridy = 0;
                gbc.weightx = 1;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                add(new FillerPane(ImageIO.read(getClass().getResource("/Top.png")), FillDirection.HORIZONTAL), gbc);
                gbc.gridy = 2;
                add(new FillerPane(ImageIO.read(getClass().getResource("/Bottom.png")), FillDirection.HORIZONTAL), gbc);

                gbc.gridx = 0;
                gbc.gridy = 1;
                gbc.weighty = 1;
                gbc.weightx = 0;
                gbc.fill = GridBagConstraints.VERTICAL;
                add(new FillerPane(ImageIO.read(getClass().getResource("/Left.png")), FillDirection.VERTICAL), gbc);
                gbc.gridx = 2;
                add(new FillerPane(ImageIO.read(getClass().getResource("/Right.png")), FillDirection.VERTICAL), gbc);
            } catch (IOException ex) {
                ex.printStackTrace();
            }

            gbc.gridx = 1;
            gbc.gridy = 1;
            gbc.weightx = 1;
            gbc.weighty = 1;
            gbc.fill = GridBagConstraints.BOTH;
            add(label, gbc);
        }

    }

    public enum FillDirection {
        HORIZONTAL,
        VERTICAL
    }

    public class FillerPane extends JPanel {

        private BufferedImage img;
        private FillDirection fillDirection;

        public FillerPane(BufferedImage img, FillDirection fillDirection) {
            this.img = img;
            this.fillDirection = fillDirection;
        }

        @Override
        public Dimension getPreferredSize() {
            return img == null ? super.getPreferredSize() : new Dimension(img.getWidth(), img.getHeight());
        }

        @Override
        public Dimension getMinimumSize() {
            return getPreferredSize();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g); 
            if (img != null) {
                Graphics2D g2d = (Graphics2D) g.create();
                int x = 0;
                int y = 0;
                int xDelta = 0;
                int yDelta = 0;
                switch (fillDirection) {
                    case HORIZONTAL:
                        xDelta = img.getWidth();
                        break;
                    case VERTICAL:
                        yDelta = img.getHeight();
                        break;
                }
                while (x < getWidth() && y < getHeight()) {
                    g2d.drawImage(img, x, y, this);
                    x += xDelta;
                    y += yDelta;
                }
                g2d.dispose();
            }
        }

    }

}