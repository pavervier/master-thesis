/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a SMTP dialogs signature parser. It aims at reading
 * signature definitions from a input file and build Signature instances
 * to be used within the SignatureMatcher.
 * The signatures are defined using a very simple language. Macros and variables
 * can also be defined to help designing powerfull and precise signatures.
 * There are 2 types of macros. *Global* macros are defined in the file
 * 'macro.def' and are meant to be used within every specified signature file.
 * *Local* macros are user defined macros provided in the specified signature
 * file. Local macros may override global macros by using the same identifier.
 * Macro identifiers can be used in the replacement value of other macros but
 * the former have to be defined before the later.
 * Variables can be considered as extended macros. They provide the same
 * replacement mechanism as macros but they also impose character strings
 * matching a particular variable to have the same value.
 * Macros are usefull for matching for instance a IMF date. Variables are
 * usefull for matching for instance the same IP address appearing several
 * times.
 * 
 */

package be.ulg.vervier.SmtpDump.BotsSignature;

import java.util.Collection;
import java.util.LinkedList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.FileHandler;
import java.io.IOException;
import be.ulg.vervier.SmtpDump.Utils.BufferedFileReader;

class SignatureParser {
    
    /** INSTANCE VARIABLES */
    
    /** The name of the file containing the bot signatures */
    private String sig_def_filename;
    /** The list of extracted bot signatures */
    private LinkedList<Signature> signatures;
    /** The buffering file input stream reader */
    private BufferedFileReader bfr;
    /** The macro parser regular expression */
    private static final String MACRO_REGEX =
        "\\G\\s*(var)?(\\$[\\w-_]+)[\\s&&[^\\r\\n]]+=[\\s&&[^\\r\\n]]+" +
        "\\\"(.+)\\\"\\s*";
    /** The signature parser regular expresion */
    private static final String SIG_REGEX =
        "\\s*sig\\s*\\\"([\\w-_]+)\\\"\\s*\\{\\s*(.+?;)\\s*\\}";
    /** The signature statement parser regular expression */
    private static final String STATEMENT_REGEX =
        "(tcp|smtp|imf)\\s*:\\s*(open|close|reset|\\\"(.*?)\\\")\\s*;" +
        "(\\^)?(=)?\\s*";
    /** The multiline signature statement parser regular expression */
    private static final String MULTILINE_STMT_REGEX = "\\\"\\s*\\+\\s*\\\"";
    /** The global macros replacement regular expression */
    private static String global_macro_rp_regex;
    /** The macro parser pattern object */
    private static Pattern macro_pattern;
    /** The signature parser pattern object */
    private static Pattern sig_pattern;
    /** The signature statement parser pattern object */
    private static Pattern statement_pattern;
    /** The multiline signature statement parser pattern object */
    private static Pattern multiline_stmt_pattern;
    /** The data structure mapping global macros identifier with their
     * associated replacement value */
    private static HashMap<String, String> global_macros;
    /** The data structure mapping local macros identifier with their
     * associated replacement value */
    private HashMap<String, String> local_macros;
    /** The data structure mapping variables with the index in an array of their
     * unique value */
    private HashMap<String, Integer> variables;
    /** Logger: log SMTPDUMP program error */
    private static final Logger LOGGER =
        Logger.getLogger(be.ulg.vervier.SmtpDump.SmtpDumpMain.class.getName());
    /** Logger: log signature parser information */
    private static final Logger LOGGER_PARSER =
        Logger.getLogger(SignatureParser.class.getName());
    /** The logging level: determine what information should be logged */
    private static final Level LOGGING_LEVEL = Level.FINE;
    
    private java.util.HashSet<Integer> temp2;
    
    /** Static block: loggers initialization */
    static {
        try {
            // log signature parser information
            FileHandler fh = new FileHandler("log_signature_parser.txt");
            fh.setLevel(LOGGING_LEVEL);
            fh.setFormatter
                (new be.ulg.vervier.SmtpDump.Utils.SimpleLogFormatter());
            LOGGER_PARSER.addHandler(fh);
        } catch (java.io.IOException ioe) {}
        // FINE level is appropriate for diagnostic
        LOGGER_PARSER.setLevel(LOGGING_LEVEL);
        // compile the parser regular expressions
        macro_pattern = Pattern.compile(MACRO_REGEX, Pattern.CASE_INSENSITIVE);
        sig_pattern = Pattern.compile(SIG_REGEX, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        statement_pattern =
            Pattern.compile(STATEMENT_REGEX,
                            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        multiline_stmt_pattern =
            Pattern.compile(MULTILINE_STMT_REGEX);
        // extract global macros from the "macro.def" file
        BufferedFileReader b = new BufferedFileReader("macro.def");
        String macro_def = null;
        try {
            b.openFile();
            macro_def = b.readFile();
            b.closeFile();
            if (macro_def != null && !macro_def.isEmpty()) {
                global_macros = new HashMap<String, String>();
                global_macro_rp_regex = parseMacros(macro_def, global_macros);
            }
        } catch (IOException ioe) {}
    }
    
    /** This class provides a way to manipulate an integer object
     * (i.e. increment/decrement) without the need to create a new object
     * each time it is modified. */
    class VariableIndex {
        
        /** INSTANCE VARIABLES */
        
        /** The integer value */
        private int value;
        
        /** CONSTRUCTORS */
        
        /** Default constructor. */
        VariableIndex() { this(0); }
        
        /** Create a new variable index instance initialized with the given
         * value. */
        VariableIndex(int value) {
            this.value = value;
        }
        
        /** METHODS */
        
        /** Retrieve the value of the variable index. */
        int value() { return value; }
        
        /** Set the value of the variable index. */
        void value(int value) { this.value = value; }
        
        /** Increment and retrieve the value of the variable index. */
        int inc() { return ++value; }
        
        /** Decrement and retrieve the value of the variable index. */
        int dec() { return --value; }
        
        /** Set the value of the variable index to 0 (reset). */
        void reset() { value = 0; }
        
        /** Return the String representation of the variable index integer
         * value. */
        public String toString() { return new Integer(value).toString(); }
        
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    SignatureParser() { this(null); }
    
    /** Create a new SignatureParser to parse bots signature from the given
     * input file. The main program logger is also given in order to log
     * important messages. */
    SignatureParser(String filename) {
        bfr = new BufferedFileReader(sig_def_filename = filename);
        signatures = new LinkedList<Signature>();
        if (LOGGER_PARSER == null)
            LOGGER.warning("Error initializing signature parser logger");
        if (global_macros == null) {
            LOGGER.warning
                ("Could not load macro definition file \"macro.def\"\n");
        } else {
            LOGGER.config("Macro definition file \"macro.def\" loaded\n");
        }
    }
    
    /** METHODS */
    
    /** Parse the input signature file and build signature instances for each
     * valid signature found. Macros/variables occurences in the signature
     * statements are also replaced with their associated replacement value. */
    void parse() throws SignatureParserException {
        String file_content = null;
        try { // read the input signature file
            bfr.openFile();
            file_content = bfr.readFile();
            bfr.closeFile();
        } catch (IOException ioe) {
            LOGGER.warning("No signature file found, running anyway\n");
            return;
        }
        if (file_content.isEmpty())
            return;
        LOGGER.config("Signature definition file \"" +
                            sig_def_filename + "\" loaded\n");
        local_macros = new HashMap<String, String>();
        variables = new HashMap<String, Integer>();
        //System.out.println(sb.toString());
        Matcher sig_matcher = null;
        Matcher statement_matcher = null;
        Matcher macro_matcher = null;
        Matcher replace_matcher = null;
        String protocol = null;
        String statement = null;
        boolean is_grouped = false;
        boolean same_transaction = false;
        Signature cur_sig = null;
        LinkedList<Link> statement_link = null;
        // merge GLOBAL and LOCAL macros
        // (local macros may override global macros)
        HashMap<String, String> macros = global_macros != null ?
            new HashMap<String, String>(global_macros) :
            new HashMap<String, String>();
        // extract the macros and variables from the specified input file
        String local_macro_rp_regex =
            parseMacrosAndVariables(file_content, macros, variables);
        global_macro_rp_regex =
            global_macro_rp_regex == null ? "" : global_macro_rp_regex;
        StringBuilder sb = new StringBuilder(global_macro_rp_regex.length() +
                                             local_macro_rp_regex.length() + 3);
        sb.append("(");
        if (!global_macro_rp_regex.isEmpty()) {
            sb.append(global_macro_rp_regex);
            sb.append("|");
        }
        sb.append(local_macro_rp_regex);
        sb.append(")");
        VariableIndex var_index = new VariableIndex();
        // PARSE SIGNATURE DEFINITIONS
        sig_matcher = sig_pattern.matcher(file_content);
        while (sig_matcher.find()) {  // extract each signature
            if (sig_matcher.group(1) != null)
                cur_sig = new Signature(sig_matcher.group(1));
            // each signature is made of "statements"
            statement_matcher = statement_pattern.matcher(sig_matcher.group(2));
            while (statement_matcher.find()) {  // extract each statement
                // each signature statement is made of:
                // a "statement" part
                protocol = statement_matcher.group(1);
                // a "protocol" part
                statement = statement_matcher.group(3) != null ?
                    statement_matcher.group(3) : statement_matcher.group(2);
                // an optional group directive: preceding stmt and current stmt
                // are grouped
                is_grouped = statement_matcher.group(4) != null;
                // an optional directive: preceding stmt and current stmt must
                // belong to the same SMTP transaction. Ignored if one stmt
                // doesn't belong to any transaction
                same_transaction = statement_matcher.group(5) != null;
                // statement may span multiple lines
                statement = statement.replaceAll(MULTILINE_STMT_REGEX, "");
                // replace macros/variables
                statement = replace(statement,
                                    Pattern.compile(sb.toString()),
                                    macros,
                                    variables,
                                    statement_link = new LinkedList<Link>(),
                                    var_index);
                if (protocol != null && statement != null) {
                    // special statement "tcp(open|close|reset)"
                    if (protocol.equalsIgnoreCase("tcp")) {
                        if (statement.equalsIgnoreCase("open"))
                            cur_sig.checkTcpSyn();
                        else if (statement.equalsIgnoreCase("close"))
                            cur_sig.checkTcpFin();
                        else if (statement.equalsIgnoreCase("reset"))
                            cur_sig.checkTcpRst();
                    }
                    else {
                        //System.out.println(statement);
                        cur_sig.addSignatureRegex
                            (statement, 
                             statement_link.size() > 0 ? statement_link : null,
                             is_grouped,
                             same_transaction);
                    }
                }
            }
            //System.out.println(variables);
            // remove all mapped variables and indices for the next signature
            if (variables != null) {
                //System.out.println(variables);
                for (String key: variables.keySet())
                    variables.put(key, null);
            }
            if (cur_sig != null && !cur_sig.isEmpty()) {
                signatures.add(cur_sig);
                LOGGER_PARSER.fine(new StringBuilder().
                                   append("(S) ").
                                   append(cur_sig.getIdentifier()).
                                   append(" [").
                                   append(cur_sig.size()).
                                   append(" statements]\n").toString());
            }
            cur_sig = null;
            var_index.reset();
        }
        LOGGER_PARSER.config(new StringBuilder().
                           append(signatures.size()).
                           append(" signatures extracted from file \"").
                           append(sig_def_filename).
                           append("\"\n").toString());
    }
    
    /** Replace the instances of macros and variables by the associated regex
     * pattern. Cross-references are also set between the instances of
     * variables. */
    private static String replace(String input,
                                  Pattern replace_pattern,
                                  HashMap<String, String> macros,
                                  HashMap<String, Integer> variables,
                                  LinkedList<Link> statement_link,
                                  VariableIndex variable_index) {
        if (input == null || (input != null && input.isEmpty()) ||
            replace_pattern == null || macros == null)
            return input;
        //System.out.println(variable_index);
        Matcher replace_matcher = replace_pattern.matcher(input);
        int group_number = -1;
        String macro = null;
        String replace = null;
        StringBuffer s = new StringBuffer();
        while (replace_matcher.find()) {   // replace macros within stmt
            macro = replace_matcher.group(1);
            macro = macro.substring(0, macro.length() - 1);
            replace = macros.get(macro);
            if (macro == null || replace == null)
                return input;
            if (variables != null && variables.containsKey(macro)
                && statement_link != null && variable_index != null) {
                replace_matcher.appendReplacement
                    (s, Matcher.quoteReplacement("(" + replace) + ")");
                input = s.toString();
                /* Each variable replacement value is prepended
                 * with '(' and appened with ')' to create a
                 * specific regex group to match that variable.
                 * This group only appears in the replacement
                 * value so the group number retrieved using
                 * the "getGroupNumber" method must be adjusted (+1).
                 */
                group_number = 1 + getGroupNumber
                    (input, input.length() - replace.length() - 2);
                // associate a variable with an index in an
                // array storing its unique value
                if (variables.get(macro) == null) {
                    variables.put(macro, variable_index.value());
                    variable_index.inc();
                }
                // record the regex group number with the value
                // index in the array
                statement_link.add
                    (new Link(group_number, variables.get(macro)));
            } else {
                replace_matcher.appendReplacement
                    (s, Matcher.quoteReplacement(replace));
            }
        }
        replace_matcher.appendTail(s);
        return s.toString();
    }
    
    /** Retrieve the collection of signatures extracted from the input file. */
    Collection<Signature> getSignatures() { return signatures; }
    
    /** Parse the input sequence of characters and extract macros from it.
     * Macros are then mapped with their associated replacement value. */
    protected static String parseMacros(String input,
                                      HashMap<String, String> identifier_map)
                                      throws SignatureParserException {
        return parseMacrosAndVariables(input, identifier_map, null);
    }
    
    /** Parse the input sequence of characters and extract macros and variables
     * from it. Macros and variables are then mapped with their associated
     * replacement value. Variables identifier are also stored in another map
     * used for managing links between variables occurence in the signature
     * statements. They are mapped with the index of the unique value associated
     * with the variable. */
    protected static String parseMacrosAndVariables(String input, 
            HashMap<String, String> identifier_map,
            HashMap<String, Integer> variables)
            throws SignatureParserException {
        if (identifier_map == null)
            identifier_map = new HashMap<String, String>();
        boolean is_var = false;
        String m_identifier = null;
        String m_value = null;
        Matcher macro_matcher = macro_pattern.matcher(input);
        StringBuilder m_rgxp_sb = new StringBuilder(150);
        for (String id: identifier_map.keySet()) {
            if (m_rgxp_sb.length() != 0)
                m_rgxp_sb.append("|");
            m_rgxp_sb.append(Pattern.quote(id + "$"));
        }
        while (macro_matcher.find()) {
            is_var = (variables != null && macro_matcher.group(1) != null);
            m_identifier = macro_matcher.group(2);
            m_value = macro_matcher.group(3);
            if (m_identifier != null && m_value != null) {
                // if the macro is a variable
                if (is_var)
                    variables.put(m_identifier, null);
                if (m_rgxp_sb.length() > 0) {
                    m_value = replace(m_value,
							Pattern.compile("(" + m_rgxp_sb.toString() + ")"),
							identifier_map, null, null, null);
                }
                identifier_map.put(m_identifier, m_value);
                // build the macro replacement regular expression
                if (m_rgxp_sb.length() != 0)
                    m_rgxp_sb.append("|");
                m_rgxp_sb.append(Pattern.quote(m_identifier + "$"));
            }
        }
        return m_rgxp_sb.toString();
    }
    
    /** Get the regular expression group number of the character located at the
     * specified position. Recall that a regular expression group begins with
     * '(' and ends with ')'. The character may be the first character of a
     * substring of the given character string. */
    protected static int getGroupNumber(String input, int position) {
        if (input == null ||
            (input != null && (position < 0 || position > input.length())))
            return -1;
        int group_number = 0;
        int group_count = 0;
        char cur_char;
        boolean found_escape_char = false;
        boolean found_char_class = false;
        for (int i = 0; i < position; i++) {
            cur_char = input.charAt(i);
            if (cur_char == '\\') { // '\' are used to escape '(' and ')'
                found_escape_char = true;
            } else if (cur_char == '[' && !found_escape_char) {
                found_char_class = true;
            } else if (cur_char == ']' && !found_escape_char) {
                found_char_class = false;
            } else {
                if (cur_char == '(' &&
					!found_escape_char &&
					!found_char_class) {
                    group_number = ++group_count;
                } else if (cur_char == ')' &&
						   !found_escape_char &&
						   !found_char_class) {
                    group_number = group_number > 0 ? group_number-- : 0;
                }
                found_escape_char = false;
            }
        }
        return group_number;
    }
    
}
