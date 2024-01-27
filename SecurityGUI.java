import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
//adding 
import java.math.BigInteger;
//


public class SecurityGUI {
    private JTextArea plaintextArea;
    private JTextArea ciphertextArea;
    private JLabel algorithmDescriptionLabel;
    private JComboBox<String> algorithmComboBox;
    private JPanel keyPanel;
    private int keyFieldCount = 0;
    private static final int MAX_KEY_FIELDS = 2;
    private JButton openFileButton;
    private JButton saveFileButton;
    //
    private RSA rsa;
    //
    public SecurityGUI() {
        initLookAndFeel();
        initComponents();
        buildFrame();
        //
        rsa = new RSA(100);
        //
    }
// the same 
    private void initLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            showError("Failed to set Look and Feel. Defaulting to system default.");
        }
    }
// the same 
    private void initComponents() {
        plaintextArea = new JTextArea(10, 60);
        ciphertextArea = new JTextArea(10, 60);
        algorithmDescriptionLabel = new JLabel("Place your algorithm description and key requirement here.");
        algorithmComboBox = new JComboBox<>(new String[]{"Replace With Your Algorithm Title Name", "RSA"});
        algorithmComboBox.setSelectedIndex(1);
        keyPanel = new JPanel();
        openFileButton = new JButton("Open File");
        openFileButton.addActionListener(this::openFileAction);
        saveFileButton = new JButton("Save File");
        saveFileButton.addActionListener(this::saveFileAction);
        keyPanel = new JPanel();
        keyPanel.setLayout(new BoxLayout(keyPanel, BoxLayout.Y_AXIS));
    }
// the same 
    private void buildFrame() {
        JFrame frame = new JFrame("CSC 429 - Computer Security Project");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BoxLayout(frame.getContentPane(), BoxLayout.Y_AXIS));
        frame.add(createInputPanel());
        frame.add(createAlgorithmPanel());
        frame.add(createActionPanel());
        frame.pack();
        frame.setMinimumSize(new Dimension(950, 600));
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }
// the same 
    private JPanel createInputPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        panel.add(new JLabel("Plaintext:"));
        panel.add(new JScrollPane(plaintextArea));
        panel.add(new JLabel("Ciphertext:"));
        panel.add(new JScrollPane(ciphertextArea));
        return panel;
    }
// the same 
    private JPanel createAlgorithmPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        JPanel upperPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        upperPanel.add(algorithmDescriptionLabel);
        upperPanel.add(algorithmComboBox);
        
        JButton addKeyButton = new JButton("+");
        addKeyButton.addActionListener(e -> addKeyField());
        upperPanel.add(addKeyButton);
        
        panel.add(upperPanel);
        panel.add(Box.createRigidArea(new Dimension(0, 5)));
        keyPanel.setLayout(new BoxLayout(keyPanel, BoxLayout.Y_AXIS));
        
        panel.add(keyPanel);
        panel.add(Box.createVerticalGlue());
        return panel;
    }

    private JPanel createActionPanel() {
        JPanel panel = new JPanel(new FlowLayout());
        JButton encryptButton = new JButton("Encrypt");
        //
        encryptButton.addActionListener(e -> encryptWithRSA());
        //
        JButton decryptButton = new JButton("Decrypt");
        //
        decryptButton.addActionListener(e -> decryptWithRSA());
        //
        JButton hashButton = new JButton("Hash");
        hashButton.addActionListener(e -> ciphertextArea.setText("Hashed text would be here."));
        JButton hmacButton = new JButton("HMAC");
        hmacButton.addActionListener(e -> ciphertextArea.setText("HMAC result would be here."));
        JButton signatureButton = new JButton("Digital Signature");
        signatureButton.addActionListener(e -> ciphertextArea.setText("Digital signature would be here."));
        //
        JButton keysButton = new JButton("Show Keys");
        keysButton.addActionListener(e -> showKeys());
        JButton modifyKeysButton = new JButton("Modify Keys");
        modifyKeysButton.addActionListener(e -> modifyKeys());
        //
        panel.add(encryptButton);
        panel.add(decryptButton);
        panel.add(hashButton);
        panel.add(hmacButton);
        panel.add(signatureButton);
        //
        panel.add(keysButton);
        //
        panel.add(openFileButton);
        panel.add(saveFileButton);
        //
        panel.add(modifyKeysButton);
        //
        return panel;
    }
// the same 
    private void addKeyField() {
        if (keyFieldCount < MAX_KEY_FIELDS) {
            JTextField newKeyField = new JTextField();
            newKeyField.setMaximumSize(new Dimension(Integer.MAX_VALUE, newKeyField.getPreferredSize().height));
            newKeyField.setAlignmentX(Component.CENTER_ALIGNMENT);
            keyPanel.add(newKeyField);
            keyPanel.revalidate();
            keyPanel.repaint();
            keyFieldCount++;
        } else {
            showError("Maximum number of key fields reached.");
        }
    }
// the same 
    private void openFileAction(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        int returnVal = fileChooser.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                String content = new String(Files.readAllBytes(Paths.get(file.getPath())));
                plaintextArea.setText(content);
            } catch (Exception ex) {
                showError("Error reading file: " + ex.getMessage());
            }
        }
    }
// the same 
    private void saveFileAction(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Specify a file to save");
        int userSelection = fileChooser.showSaveDialog(null);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            if (!fileToSave.getName().contains(".")) {
                fileToSave = new File(fileToSave.toString() + ".txt");
            }
            try (FileWriter fileWriter = new FileWriter(fileToSave)) {
                fileWriter.write(ciphertextArea.getText());
            } catch (IOException ex) {
                showError("Error saving file: " + ex.getMessage());
            }
        }
    }
//TODO: implement your algorithm function here:
    private void encryptWithRSA() {
        String plaintext = plaintextArea.getText();
        try {
            BigInteger encrypted = rsa.encrypt(plaintext);
            ciphertextArea.setText(encrypted.toString());
        } catch (IllegalArgumentException e) {
            showError(e.getMessage());
        }
    }

    private void decryptWithRSA() {
        String ciphertext = ciphertextArea.getText();
        try {
            BigInteger encrypted = new BigInteger(ciphertext);
            String decrypted = rsa.decrypt(encrypted);
            plaintextArea.setText(decrypted);
        } catch (NumberFormatException e) {
            showError("Invalid ciphertext format");
        }
    } 
    private void showKeys() {
        String publicKey = rsa.getPublicKey();
        String privateKey = rsa.getPrivateKey();
        String keysInfo = "Public Key: " + publicKey + "\nPrivate Key: " + privateKey;

        JOptionPane.showMessageDialog(null, keysInfo, "RSA Keys", JOptionPane.INFORMATION_MESSAGE);
    }

    private void modifyKeys() {
        String newPublicKey = JOptionPane.showInputDialog(null, "Enter new public key:");
        String newPrivateKey = JOptionPane.showInputDialog(null, "Enter new private key:");

        if (newPublicKey != null && newPrivateKey != null && !newPublicKey.isEmpty() && !newPrivateKey.isEmpty()) {
            rsa = new RSA(100);
            rsa.clearKeys();
            rsa.setKeys(newPublicKey, newPrivateKey);
            JOptionPane.showMessageDialog(null, "Keys updated successfully!", "Keys Updated", JOptionPane.INFORMATION_MESSAGE);
        } else {
            showError("Invalid keys. Please enter valid values for both public and private keys.");
        }
    }
// end my implement function
    
    
//the same 
    private void showError(String message) {
        JOptionPane.showMessageDialog(null, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(SecurityGUI::new);
    }
}
