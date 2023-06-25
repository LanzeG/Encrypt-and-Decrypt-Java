import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.security.MessageDigest;
import java.util.Arrays;

public class FileEncryptionExample {

    private static final String ALGORITHM = "AES";
    private JFrame frame;
    private JTextArea logTextArea;
    private JButton encryptButton;
    private JButton decryptButton;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new FileEncryptionExample().createAndShowGUI();
            }
        });
    }

    private void createAndShowGUI() {
        frame = new JFrame("File Encryption");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.setSize(400, 300);
        frame.setLocationRelativeTo(null); // Center the frame on the screen

        logTextArea = new JTextArea(10, 40);
        logTextArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logTextArea);
        frame.add(logScrollPane, BorderLayout.CENTER);

        encryptButton = new JButton("Encrypt");
        encryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                encryptFile();
            }
        });

        decryptButton = new JButton("Decrypt");
        decryptButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                decryptFile();
            }
        });

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        frame.add(buttonPanel, BorderLayout.SOUTH);

        frame.setVisible(true);
    }

    private void encryptFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select File to Encrypt");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text files", "txt");
        fileChooser.setFileFilter(filter);

        int result = fileChooser.showOpenDialog(frame);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String inputFile = selectedFile.getAbsolutePath();

            // Ask for password
            String password = JOptionPane.showInputDialog(frame, "Enter encryption password:", "Password", JOptionPane.PLAIN_MESSAGE);
            if (password != null) {
                String outputFile = inputFile + ".encrypted";

                try {
                    encryptFile(inputFile, outputFile, password);
                    logTextArea.append("Encryption completed. Encrypted file saved as: " + outputFile + "\n");

                    // Delete the original file
                    if (selectedFile.delete()) {
                        logTextArea.append("The file is encrypted: " + selectedFile.getName() + "\n");
                    } else {
                        logTextArea.append("Failed to delete the original file: " + selectedFile.getName() + "\n");
                    }
                } catch (Exception e) {
                    logTextArea.append("Error during encryption: " + e.getMessage() + "\n");
                }
            } else {
                logTextArea.append("Encryption canceled. No password entered.\n");
            }
        }
    }

    private void decryptFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select File to Decrypt");
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Encrypted files", "encrypted");
        fileChooser.setFileFilter(filter);

        int result = fileChooser.showOpenDialog(frame);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String inputFile = selectedFile.getAbsolutePath();

            // Ask for password
            String password = JOptionPane.showInputDialog(frame, "Enter decryption password:", "Password", JOptionPane.PLAIN_MESSAGE);
            if (password != null) {
                String outputFile = inputFile.replaceAll("\\.encrypted$", "");

                try {
                    decryptFile(inputFile, outputFile, password);
                    logTextArea.append("Decryption completed. Decrypted file saved as: " + outputFile + "\n");

                    // Delete the encrypted file
                    File encryptedFile = new File(inputFile);
                    if (encryptedFile.delete()) {
                        logTextArea.append("The file is Decrypted: " + encryptedFile.getName() + "\n");
                    } else {
                        logTextArea.append("Failed to delete the encrypted file: " + encryptedFile.getName() + "\n");
                    }

                    JOptionPane.showMessageDialog(frame, "File decrypted successfully!", "Decryption", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception e) {
                    logTextArea.append("Error during decryption: " + e.getMessage() + "\n");
                }
            } else {
                logTextArea.append("Decryption canceled. No password entered.\n");
            }
        }
    }

    private void encryptFile(String inputFile, String outputFile, String password) throws Exception {
        File inputFileObj = new File(inputFile);
        File outputFileObj = new File(outputFile);

        SecretKey secretKey = generateSecretKey(password);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFileObj);
        FileOutputStream outputStream = new FileOutputStream(outputFileObj);

        byte[] inputBytes = new byte[(int) inputFileObj.length()];
        inputStream.read(inputBytes);

        byte[] encryptedBytes = cipher.doFinal(inputBytes);
        outputStream.write(encryptedBytes);

        inputStream.close();
        outputStream.close();
    }

    private void decryptFile(String inputFile, String outputFile, String password) throws Exception {
        File inputFileObj = new File(inputFile);
        File outputFileObj = new File(outputFile);

        SecretKey secretKey = generateSecretKey(password);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFileObj);
        FileOutputStream outputStream = new FileOutputStream(outputFileObj);

        byte[] inputBytes = new byte[(int) inputFileObj.length()];
        inputStream.read(inputBytes);

        byte[] decryptedBytes = cipher.doFinal(inputBytes);
        outputStream.write(decryptedBytes);

        inputStream.close();
        outputStream.close();
    }

    private SecretKey generateSecretKey(String password) throws Exception {
        byte[] keyBytes = Arrays.copyOf(password.getBytes(), 16);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        keyBytes = sha.digest(keyBytes);

        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}
