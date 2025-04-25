import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.regex.*;

public class SensitiveDataScanner {
    private final Map<String, String> rules = new HashMap<>();

    public SensitiveDataScanner() {
        loadRules();
    }

    private void loadRules() {
        rules.put("SSN", "\\d{3}-\\d{2}-\\d{4}");
        rules.put("CreditCard", "\\b(?:\\d[ -]*?){13,16}\\b");
        rules.put("Email", "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b");
        rules.put("Phone", "\\b(?:\\+?(\\d{1,3}))?[-. (]*(\\d{3})[-. )]*(\\d{3})[-. ]*(\\d{4})\\b");
        rules.put("IPv4", "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        rules.put("IPv6", "\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b");
        rules.put("URL", "\\bhttps?://[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,6}\\b");
        rules.put("CreditCardExpiration", "\\b(0[1-9]|1[0-2])/[0-9]{2}\\b");
        rules.put("CreditCardCVV", "\\b\\d{3,4}\\b");
    }

    public boolean containsSensitiveData(File file) {
        try (Scanner scanner = new Scanner(file)) {
            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                for (String regex : rules.values()) {
                    if (Pattern.compile(regex).matcher(line).find()) return true;
                }
            }
        } catch (FileNotFoundException e) {
            DataLeakageDetectorGUI.logTextArea.append("File not found: " + file.getAbsolutePath() + "\n");
        }
        return false;
    }
}
