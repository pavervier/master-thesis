/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a parser for the Simple Mail Transfer Protocol. Given
 * an underlying TCP session, it extracts commands and responses issued by the
 * client and the server. In the SMTP protocol, each command issued by the
 * client is acknowledged by the server with specific response codes.
 * The java collections that can be retrieved after the parsing contain the
 * commands and responses in the order they were sent by the client or the
 * server.
 * 
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

import java.util.Collection;
import java.util.List;
import java.util.LinkedList;
import java.util.ArrayDeque;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.util.logging.FileHandler;
import java.nio.charset.Charset;
import be.ulg.vervier.SmtpDump.TCPSessionManagement.*;

public class SMTPParser {
    
    /** INSTANCE VARIABLES */
    
    /** The pattern objects */
    private static Pattern smtp_cmd_pattern, smtp_res_pattern,
        imf_header_pattern, imf_header_field_pattern, smtp_term_seq_pattern;
    /** The SMTP protocol command regular expression */
    private static final String SMTP_CMD_REGEX =
        "^(?:\\t| )*(((helo|ehlo)|(help)|(vrfy)|(expn)|(noop)|" +
        "(((mail(?:\\t| )+from)|(rcpt(?:\\t| )+to))(?:\\t| )*:))" +
        "((?:\\t| )*.*)|(quit)|(rset)|(data)(?:.*)|(starttls)|" +
        "(auth(?:\\t| )*login))(?:\\t| )*\\r\\n$";
    /** The SMTP protocol response regular expression */
    private static final String SMTP_RES_REGEX =
        "^(\\d{3})(\\t| |-)+(.*)\\r\\n$";
    /** The IMF e-mail header regular expression */
    private static final String IMF_HEADER_REGEX = 
        "(.*?\\r\\n)((\\r\\n)|(\\.\\r\\n))";
    /** The IMF e-mail body regular expression */
    private static final String IMF_HEADER_FIELD_REGEX =
        "[^\r\n]*(((return-path)|(received)|(resent-date)|(resent-from)|" +
        "(resent-sender)|(resent-to)|(resent-cc)|(resent-bcc)|" +
        "(resent-message-id)|(date)|(from)|(sender)|(reply-to)|(to)|(cc)|" +
        "(bcc)|(message-id)|(in-reply-to)|(references)|(subject)|(comments)|" +
        "(keywords)|(mime-version)|(content-type)|" +
        "(content-transfer-encoding)|(content-id)|(content-description)|" +
        "(x-[^\r\n:]+))\\s*:)+?";
    /** The SMTP termination sequence regular expression */
    private static final String SMTP_TERM_SEQ = "(\\r\\n\\.(\\r\\n)+)";
    /** The US-ASCII charset for the decoding of TCP payload */
    private static final Charset CHARSET_ASCII;
    /** Array mapping group number and SMTP command type */
    private static final SMTPCommandType[] SMTP_CMD_TYPE;
    /** Array mapping group number and IMF statement type */
    private static final IMFStatementType[] IMF_STMT_TYPE;
    /** The number of SMTP packets as extracted from the underlying TCP
     * connection so far. */
    private int smtp_packet_count;
    /** The number of SMTP sessions rebuilt so far */
    private int smtp_session_count;
    /** The number of TCP packets parsed so far */
    private int tcp_packet_count;
    /** The number of TCP sessions parsed so far */
    private int tcp_session_count;
    /** True if the IMF messages must be reassembled, false otherwise */
    private boolean imf_reassemble;
    /** Logger: log SMTPDUMP program error */
    private static final Logger LOGGER =
        Logger.getLogger(be.ulg.vervier.SmtpDump.SmtpDumpMain.class.getName());
    /** Logger: log SMTP parser information */
    private static final Logger LOGGER_PARSER =
        Logger.getLogger(SMTPParser.class.getName());
    /** The logging level: determine what information should be logged */
    private static final Level LOGGING_LEVEL = Level.FINE;
    
    static {
        try {
            // log signature parser information
            FileHandler fh = new FileHandler("log_smtp_session.txt");
            fh.setLevel(LOGGING_LEVEL);
            fh.setFormatter
                (new be.ulg.vervier.SmtpDump.Utils.SimpleLogFormatter());
            LOGGER_PARSER.addHandler(fh);
            // FINE level is appropriate for diagnostic
            LOGGER_PARSER.setLevel(LOGGING_LEVEL);
        } catch (java.io.IOException ioe) {}
        /* Compile the parser SMTP regular expression
         * (case insensitive matching). */
        smtp_cmd_pattern =
            Pattern.compile(SMTP_CMD_REGEX, Pattern.CASE_INSENSITIVE);
        /* Compile the parser SMTP response regular expression. */
        smtp_res_pattern = Pattern.compile(SMTP_RES_REGEX, Pattern.DOTALL);
        /* Compile the parser IMF header regular expression
         * (extract the whole IMF header). */
        imf_header_pattern = Pattern.compile(IMF_HEADER_REGEX, Pattern.DOTALL);
        /* Compile the parser IMF header regular expression
         * (extract IMF header fields, case insensitive matching). */
        imf_header_field_pattern =
			Pattern.compile(IMF_HEADER_FIELD_REGEX,
							Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        /* Compile the parser SMTP termination sequence regular expression
         * (termination sequence is <CRLF>.<CRLF>). */
        smtp_term_seq_pattern = Pattern.compile(SMTP_TERM_SEQ);
        /* The US-ASCII charset */
        CHARSET_ASCII = Charset.forName("US-ASCII");
        // fill in SMTP command types array
        SMTP_CMD_TYPE = new SMTPCommandType[15];
        SMTP_CMD_TYPE[0] = SMTPCommandType.HELO;
        SMTP_CMD_TYPE[1] = SMTPCommandType.HELP;
        SMTP_CMD_TYPE[2] = SMTPCommandType.VRFY;
        SMTP_CMD_TYPE[3] = SMTPCommandType.EXPN;
        SMTP_CMD_TYPE[4] = SMTPCommandType.NOOP;
        SMTP_CMD_TYPE[5] = null;
        SMTP_CMD_TYPE[6] = null;
        SMTP_CMD_TYPE[7] = SMTPCommandType.MAIL;
        SMTP_CMD_TYPE[8] = SMTPCommandType.RCPT;
        SMTP_CMD_TYPE[9] = null;
        SMTP_CMD_TYPE[10] = SMTPCommandType.QUIT;
        SMTP_CMD_TYPE[11] = SMTPCommandType.RSET;
        SMTP_CMD_TYPE[12] = SMTPCommandType.DATA;
        SMTP_CMD_TYPE[13] = SMTPCommandType.EXTN;
        SMTP_CMD_TYPE[14] = SMTPCommandType.EXTN;
        // fill in IMF statement types array
        IMF_STMT_TYPE = new IMFStatementType[28];
        IMF_STMT_TYPE[0] = IMFStatementType.RETURN_PATH;
        IMF_STMT_TYPE[1] = IMFStatementType.RECEIVED;
        IMF_STMT_TYPE[2] = IMFStatementType.RESENT_DATE;
        IMF_STMT_TYPE[3] = IMFStatementType.RESENT_FROM;
        IMF_STMT_TYPE[4] = IMFStatementType.RESENT_SENDER;
        IMF_STMT_TYPE[5] = IMFStatementType.RESENT_TO;
        IMF_STMT_TYPE[6] = IMFStatementType.RESENT_CC;
        IMF_STMT_TYPE[7] = IMFStatementType.RESENT_BCC;
        IMF_STMT_TYPE[8] = IMFStatementType.RESENT_MESSAGE_ID;
        IMF_STMT_TYPE[9] = IMFStatementType.DATE;
        IMF_STMT_TYPE[10] = IMFStatementType.FROM;
        IMF_STMT_TYPE[11] = IMFStatementType.SENDER;
        IMF_STMT_TYPE[12] = IMFStatementType.REPLY_TO;
        IMF_STMT_TYPE[13] = IMFStatementType.TO;
        IMF_STMT_TYPE[14] = IMFStatementType.CC;
        IMF_STMT_TYPE[15] = IMFStatementType.BCC;
        IMF_STMT_TYPE[16] = IMFStatementType.MESSAGE_ID;
        IMF_STMT_TYPE[17] = IMFStatementType.IN_REPLY_TO;
        IMF_STMT_TYPE[18] = IMFStatementType.REFERENCES;
        IMF_STMT_TYPE[19] = IMFStatementType.SUBJECT;
        IMF_STMT_TYPE[20] = IMFStatementType.COMMENTS;
        IMF_STMT_TYPE[21] = IMFStatementType.KEYWORDS;
        IMF_STMT_TYPE[22] = IMFStatementType.MIME_VERSION;
        IMF_STMT_TYPE[23] = IMFStatementType.CONTENT_TYPE;
        IMF_STMT_TYPE[24] = IMFStatementType.CONTENT_TRANSFER_ENCODING;
        IMF_STMT_TYPE[25] = IMFStatementType.CONTENT_ID;
        IMF_STMT_TYPE[26] = IMFStatementType.CONTENT_DESCRIPTION;
        IMF_STMT_TYPE[27] = IMFStatementType.X_FIELD;
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public SMTPParser() {
        this(true);
    }
    
    /** Create a new SMTP parser instance and enable/disbale IMF
     * reassembling. */
    public SMTPParser(boolean imf_reassemble) {
        smtp_packet_count = 0;
        smtp_session_count = 0;
        tcp_packet_count = 0;
        tcp_session_count = 0;
        this.imf_reassemble = imf_reassemble;
        if (LOGGER_PARSER == null)
            LOGGER.warning("Error initializing SMTP parser logger");
    }
    
    /** METHODS */
    
    /** Parse the given collection of TCP sessions and extract SMTP commands
     * from the client and responses from the server. */
    public Collection<SMTPSession> parse(Collection<TCPSession> tcp_sessions)
            throws SMTPParserException {
        Collection<SMTPSession> toReturn = new LinkedList<SMTPSession>();
        for (TCPSession tcp_s: tcp_sessions)
            toReturn.add(parse(tcp_s));
        return toReturn;
    }
    
    /** Parse the given TCP session and extract SMTP commands from the client
     * and responses from the server. */
    public SMTPSession parse(TCPSession tcp_session)
		throws SMTPParserException {
        if (tcp_session == null) return null;
        SMTPSession smtp_session = null;
        try {
            smtp_session = new SMTPSession(tcp_session);
        } catch (InvalidSMTPSessionIdentifierException issie) {
            throw new SMTPParserException("smtp-parser:" + issie.getMessage());
        }
        Matcher m = null;
        String payload = null;
        SMTPCommand command = null;
        IMFMessage message = null;
        List<IMFMessage> messages = null;
        SMTPResponse response = null;
        StringBuilder sb_message = null;
        SMTPCommandType last_cmd = null;
        String message_str = null;
        List<Integer> fragments = null;
        boolean is_response = false;
        boolean is_command = false;
        messages = new LinkedList<IMFMessage>();
        fragments = new LinkedList<Integer>();
        // extract the type and value of the SMTP statement
        for (jpcap.packet.TCPPacket p: tcp_session.getPackets()) {
            if ((payload = getPayload(p)).isEmpty())
                continue;
            try {
				// SMTP server response
                if ((m = smtp_res_pattern.matcher(payload)).find()) {
                    if (m.group(1) != null && m.group(3) != null)
                        response = new SMTPResponse
                           (Integer.valueOf(m.group(1)).intValue(), m.group(3));
                    else if (m.group(1) != null && m.group(3) == null)
                        response = new SMTPResponse
                           (Integer.valueOf(m.group(1)).intValue());
                    smtp_session.addResponse(response);
                    is_response = true;
                }
                // SMTP client command
                if ((m = smtp_cmd_pattern.matcher(payload)).find() &&
					!is_response) {
                    (command = new SMTPCommand(getSMTPCmdType(m)))
                        .command(payload);
                    smtp_session.addCommand(command);
                    last_cmd = command.cmdType();
                    is_command = true;
                }
                // IMF message from client
                // The message is always reassembled before extracting the
                // different header fields. If the message must be reassembled
                // for further processing in the system, the reassembled version
                // of the message is added to the current SMTP session. If the
                // message need not be reassembled, its fragmented version is
                // added to the SMTP session.
                if (!is_response &&
					!is_command && last_cmd == SMTPCommandType.DATA) {
                    if (sb_message == null)
                        sb_message = new StringBuilder();
                    if (message == null)
                        message = new IMFMessage(sb_message.length());
                    fragments.add(sb_message.length());
                    if (!imf_reassemble) {
                        message.message(payload);
                        messages.add(message);
                        smtp_session.addMessage(message);
                        message = null;
                    }
                    sb_message.append(payload);
                    // check for the TERMINATION-SEQUENCE to report the end of
                    // the message
                    if ((m = smtp_term_seq_pattern.matcher(payload)).find()) {
                        message_str = sb_message.toString();
                        if (imf_reassemble) {
                            message.message(message_str);
                            messages.add(message);
                            smtp_session.addMessage(message);
                        }
                        int header_end = 0;
                        int term_seq_start =
							message_str.length() - m.group(1).length();
                        String imf_header = null;
                        if ((m = imf_header_pattern.
							matcher(message_str)).find()) {
                            imf_header = m.group(1);
                            header_end = m.end(1) + 2;
                        }
                        // extract the different fields from the e-mail message
                        int start_field = 0;
                        int end_field = 0;
                        int next_i = 0;
                        Matcher last_match = null;
                        // extract header fields
                        while ((m = imf_header_field_pattern.
							matcher(imf_header)).find(next_i)) {
                            end_field = m.start(1);
                            if (end_field > 0)
                                getFragmentedMessages(messages,
													  fragments,
													  start_field).
									addStatement(getIMFStmtType(last_match),
												 start_field,
												 end_field);
                            start_field = m.start(1);
                            next_i = m.end(1);
                            last_match = m;
                        }
                        getFragmentedMessages(messages,
											  fragments,
											  start_field).
							addStatement(getIMFStmtType(last_match),
										 start_field,
										 imf_header.length());
						// extract the message body
                        getFragmentedMessages(messages,
											  fragments,
											  header_end).
							addStatement(IMFStatementType.BODY,
										 header_end,
										 term_seq_start);
						// extract the termination sequence
                        getFragmentedMessages(messages,
											  fragments,
											  term_seq_start).
							addStatement(IMFStatementType.TERM_SEQ,
										 term_seq_start,
										 message_str.length());
                        sb_message = null;
                        message = null;
                        messages.clear();
                        fragments.clear();
                    }
                } else {
                    sb_message = null;
                    message = null;
                    messages.clear();
                    fragments.clear();
                }
                message_str = null;
                is_response = false;
                is_command = false;
            } catch (InvalidSessionStatementException isse) {
                throw new SMTPParserException
                ("smtp-parser:" + isse.getMessage());
            }
            smtp_packet_count++;
        }
        
        tcp_packet_count += tcp_session.size();
        tcp_session_count++;
        // return the newly created SMTP session
        if (smtp_session != null && !smtp_session.isEmpty()) {
            smtp_session_count++;
            LOGGER_PARSER.fine(new StringBuilder(75).
                               append(smtp_session.toString()).
                               append("\n").toString());
            return smtp_session;
        }
        return null;
    }
    
    /** Retrieve the fragment, of a complete IMF message, that can hold the
     * statement located at the given index in the message. Disbaling
     * reassembling causes every message fragments to be stored in a different
     * IMF message object. On the contrary, enabling reassembling causes all
     * fragments to be stored in one IMF message object. The list of messages
     * contain the different fragment strings. The fragment list contain the
     * index in the complete message string of the boundary between each
     * fragment. */
    private IMFMessage getFragmentedMessages(List<IMFMessage> messages,
											 List<Integer> fragments,
											 int stmt_index) {
		// start from the end of the fragment list
        for (int i = fragments.size() - 1; i >= 0; i--) {
			// Check if the index in the complete message where the current
			// fragment begins is lower than the index where the statement
			// begins. If it so, the fragment can hold the statement.
            if (i < messages.size() && stmt_index >= fragments.get(i)) {
                if (!messages.get(i).getFragments().
					contains(messages.get(i).getStatementCount()))
                    messages.get(i).
						setFragment(i, messages.get(i).getStatementCount());
                return messages.get(i);
            }
        }
        return null;
    }
    
    /** Retrieve the SMTP command type mapping the given matched regex group
     * (from the SMTP_CMD_REGEX). */
    private SMTPCommandType getSMTPCmdType(Matcher m) {
        for (int i = 0; i < SMTP_CMD_TYPE.length; i++)
            if (SMTP_CMD_TYPE[i] != null && m.group(i + 3) != null)
                return SMTP_CMD_TYPE[i];
        return null;
    }
    
    /** Retrieve the IMF statement type mapping the given matched regex
     * group (from the IMF_HEADER_FIELD_REGEX). */
    private IMFStatementType getIMFStmtType(Matcher m) {
        if (m == null) return null;
        for (int i = 0; i < IMF_STMT_TYPE.length; i++)
            if (IMF_STMT_TYPE[i] != null && m.group(i + 3) != null)
                return IMF_STMT_TYPE[i];
        return null;
    }
    
    /** Retrieve the number of TCP packets which SMTP data has been extracted
     * from so far. */
    public int getTCPPacketCount() {
        return tcp_packet_count;
    }
    
    /** Retrieve the number of TCP sessions which SMTP sessions have been
     * extracted from so far. */
    public int getTCPSessionCount() {
        return tcp_session_count;
    }
    
    /** Retrieve the number of SMTP packets as extracted from the underlying TCP
     * connection so far. */
    public int getSMTPPacketCount() {
        return smtp_packet_count;
    }
    
    /** Retrieve the number of SMTP sessions rebuilt so far. */
    public int getSMTPSessionCount() {
        return smtp_session_count;
    }
    
    /** Extract the payload from a TCP packet.,*/
    private String getPayload(jpcap.packet.TCPPacket packet) {
        return new String(packet.data, CHARSET_ASCII);
    }
    
}
