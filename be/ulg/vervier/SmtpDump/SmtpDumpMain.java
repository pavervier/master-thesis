/**
 * 
 *    ****  *     * ******** *****    ****     **    **  *     *  *****
 *  **      **   **    **    **  **   **  **   **    **  **   **  **  **
 * **       *** ***    **    **   **  **   **  **    **  *** ***  **   **
 * **       ** * **    **    **  **   **   **  **    **  ** * **  **  **
 *  *****   **   **    **    *****    **   **  **    **  **   **  *****
 *      **  **   **    **    **       **   **  **    **  **   **  **
 *      **  **   **    **    **       **   **  **    **  **   **  **
 *     **   **   **    **    **       **  **   **    **  **   **  **
 * ****     **   **    **    **       ****      ******   **   **  **
 * 
 * Project work, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Main class for SmtpDump, a tool for the automated analysis and detection
 * of spamming botnets.
 * 
 */

package be.ulg.vervier.SmtpDump;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.logging.Logger;
import java.util.logging.Handler;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import be.ulg.vervier.SmtpDump.TCPSessionManagement.*;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.*;
import be.ulg.vervier.SmtpDump.BotsSignature.*;
import be.ulg.vervier.SmtpDump.BotsSignature.SignatureGeneration.*;
import be.ulg.vervier.SmtpDump.Result.*;

public class SmtpDumpMain {

    /** INSTANCE VARIABLES */
    
    /** The TCP session builder */
    private TCPSessionBuilder builder;
    /** The SMTP parser */
    private SMTPParser parser;
    /** The signature matcher */
    private SignatureMatcher sig_matcher;
    /** The database manager */
    private ResultGenerator result_generator;
    /** The signature generator */
    private SignatureGenerator sig_generator;
    /** The blocking queue storing SMTP sessions produced by the TCP session
     * builder and consumed by the SMTP parser */
    private final ArrayBlockingQueue<TCPSession> tcp_sessions;
    /** True if the TCP session builder has been initialized, false otherwise */
    private boolean tcp_builder_init;
    /** True if the SMTP matcher has been initialized, false otherwise */
    private boolean smtp_parser_init;
    /** True if the signature matcher has been initialied, false otherwise */
    private boolean sig_matcher_init;
    /** True if the result manager has been initialized, false otherwise */
    private boolean result_generator_init;
    /** True if the signature generator has been initialized, false
     * otherwise. */
    private boolean signature_generator_init;
    /** The list of network trace files to analyze */
    private LinkedList<String> input_files;
    /** Logger: log SMTPDUMP program error */
    private static final Logger LOGGER =
        Logger.getLogger(be.ulg.vervier.SmtpDump.SmtpDumpMain.class.getName());
    /** The logging level: determine what information should be logged */
    private static final Level LOGGING_LEVEL = Level.CONFIG;
    
    private int match_count;
    private int last_print_length;
    
    /** Static block: loggers initialization */
    static {
        Handler[] handlers = Logger.getLogger("").getHandlers();
        for (int i = 0; i < handlers.length; i++) {
            handlers[i].setLevel(LOGGING_LEVEL);
            if (handlers[i] instanceof java.util.logging.ConsoleHandler)
                handlers[i].setFormatter
                    (new be.ulg.vervier.SmtpDump.Utils.LogFormatter());
        }
        LOGGER.setLevel(LOGGING_LEVEL);
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public SmtpDumpMain() {
        tcp_builder_init = false;
        smtp_parser_init = false;
        sig_matcher_init = false;
        result_generator_init = false;
        signature_generator_init = false;
        tcp_sessions = new ArrayBlockingQueue<TCPSession>(5000);
        input_files = new LinkedList<String>();
        match_count = 0;
        last_print_length = 0;
    }
    
    /** METHODS */
    
    /** Initialize the TCP session builder. */
    public void initTCPBuilder() {
        builder = new TCPSessionBuilder(tcp_sessions);
        tcp_builder_init = true;
    }
    
    /** Initialize the SMTP parser. */
    public void initSMTPParser(boolean imf_reassemble) {
        parser = new SMTPParser(imf_reassemble);
        smtp_parser_init = true;
    }
    
    /** Initialize the signature matcher. */
    public void initSignatureMatcher(String sig_resource_id) {
        // parse the signature file and extract SMTP client signatures
        sig_matcher = new SignatureMatcher(sig_resource_id);
        try {
            sig_matcher.buildSignatures();
        } catch (SignatureParserException spe) {
            System.out.println("smtpdump:" + spe.getMessage());
            System.exit(1);
        }
        sig_matcher_init = true;
    }
    
    /** Initialize the result generator. */
    public void initResultGenerator(String db_name) {
        result_generator = new ResultGenerator();
        try {
            result_generator.openDataBase(db_name);
        } catch (ResultGeneratorException rge) {
            System.err.println(rge.getMessage());
            System.exit(1);
        }
        result_generator_init = true;
    }
    
    /** Terminate the result generator. */
    public void terminateResultGenerator() {
        try {
            result_generator.closeDataBase();
        } catch (ResultGeneratorException rge) {
            System.err.println(rge.getMessage());
            System.exit(1);
        }
    }
    
    /** Terminate the signature generator. */
    public void terminateSignatureGenerator() {
		sig_generator.closeSignatureFile();
	}
    
    /** Initialize the signature generation module. */
    public void initSignatureGenerator(String sig_gen_sample,
									   String sig_output_file) {
		if (!sig_matcher_init) return;
        try {
            sig_generator =
				new SignatureGenerator(sig_matcher,
									   sig_output_file,
									   true,
									   Integer.parseInt(sig_gen_sample));
        } catch (NumberFormatException nfe) {
            sig_generator =
				new SignatureGenerator(sig_matcher, sig_output_file, true, 0);
        }
        signature_generator_init = true;
    }

    /** Launch SMTP traffic analysis. */
    public void analyzeSMTPTraffic() {
        if (!(tcp_builder_init && smtp_parser_init && sig_matcher_init &&
            result_generator_init && signature_generator_init))
            return;
        printStatusHeader();
        // parse the specified network data resource
        builder.setResourceIdentifier(input_files.pollFirst());
        new Thread(builder).start();
        try {
            TCPSession tcp_session = null;
            SMTPSession smtp_session = null;
            MatchingSMTPSession m_session = null;
            while (true) {
                tcp_session = tcp_sessions.take();
                if (tcp_session != null && tcp_session.isEmpty()) {
                    if (input_files.peekFirst() == null) {
                        break;
                    } else {
                        builder.setResourceIdentifier(input_files.pollFirst());
                        new Thread(builder).start();
                        tcp_session = null;
                        smtp_session = null;
                        m_session = null;
                    }
                }
                // extract the SMTP session from the TCP connection
                if (tcp_session != null)
                    smtp_session = parser.parse(tcp_session);
                // test signatures against the SMTP sessions
                if (smtp_session != null)
                    m_session = sig_matcher.getMatchingSession(smtp_session);
                if (m_session != null) {	// match
                    match_count++;
                    // write information in the database
                    result_generator.addSession(m_session);
                } else {					// no match
                    if (smtp_session != null) {
						// use the SMTP session to generate new signatures
                        sig_generator.addSampleSession(smtp_session);
                        sig_generator.generateSignatures();
                    }
                }
                printStatusProgress();
            }
            // write a report about the execution of the system to the database
            SDReport report = new SDReport();
            report.tcpPackets(builder.getTCPPacketCount());
            report.tcpSessions(builder.getTCPSessionCount());
            report.smtpPackets(parser.getSMTPPacketCount());
            report.smtpSessions(parser.getSMTPSessionCount());
            result_generator.addReport(report);
        } catch (InterruptedException ie) {
            System.err.println("smtpdump:process interrupted");
        } catch (SMTPParserException spe) {
            System.err.println("smtpdump:" + spe.getMessage());
        } catch (ResultGeneratorException rge) {
            System.err.println("smtpdump:" + rge.getMessage());
        }
        terminateResultGenerator();
        terminateSignatureGenerator();
        printReport();
        System.out.println("\nGoodbye");
    }
    
    /** Add a network trace file to analyze. */
    private void addTraceFile(String file_name) {
        if (input_files != null)
            input_files.add(file_name);
    }
    
    /** Print SmtpDump analysis and detection status header on the command
     * line. */
    private void printStatusHeader() {
        System.out.println("\nProgress status");
        System.out.print("--------------");
        System.out.print("--------------");
        System.out.print("--------------");
        System.out.print("--------------");
        System.out.println("---------------");
        System.out.print("|     TCP     ");
        System.out.print("|     SMTP    ");
        System.out.print("|Spam sessions");
        System.out.print("|  Current SG ");
        System.out.print("|  Generated  ");
        System.out.println("|");
        System.out.print("|    flows    ");
        System.out.print("|   sessions  ");
        System.out.print("|   detected  ");
        System.out.print("|   clusters  ");
        System.out.println("|  signatures |");
        System.out.print("|-------------");
        System.out.print("|-------------");
        System.out.print("|-------------");
        System.out.print("|-------------");
        System.out.println("|-------------|");
    }
    
    /** Print SmtpDump analysis and detection status progress on the command
     * line. */
    private void printStatusProgress() {
        String str =
            String.format("| %1$-11d | %2$-11d | %3$-11d | %4$-11d | %5$-11d |",
                          builder.getTCPSessionCount(),
                          parser.getSMTPSessionCount(),
                          match_count,
                          sig_generator.getClusterCount(),
                          sig_generator.getGeneratedSigCount());
        System.out.print("\r");
		System.out.print(str);
	}
    
    /** Print SmtpDump report on the command line. */
    private void printReport() {
        System.out.print("\n--------------");
        System.out.print("--------------");
        System.out.print("--------------");
        System.out.print("--------------");
        System.out.println("---------------");
        System.out.format("\nSpam sessions detected written to database " +
                          "\"%1$s\".\n",
                          result_generator.getDBName());
        if (sig_generator.getSignatureFileName() != null &&
            !sig_generator.getSignatureFileName().isEmpty()) {
            System.out.format("Generated signatures written to file " +
                              "\"%1$s\".\n",
                              sig_generator.getSignatureFileName());
        }
    }
	
	/** Print a welcome message on the command line. */
	private void printWelcome() {
		System.out.print("SmtpDump - automated analysis and detection ");
		System.out.print("of spamming botnets\r\n");
	}

    /** SmtpDump main method (program start point). */
    public static void main(String[] arg) {
        SmtpDumpMain smtpdump = new SmtpDumpMain();
        smtpdump.printWelcome();
        // retrieve the pcap files list
        for (int i = 5; i < arg.length; i++)
            smtpdump.addTraceFile(arg[i]);
        // init modules
        smtpdump.initTCPBuilder();
        smtpdump.initSMTPParser
			(arg[0] != null && arg[0].equals("true") ? true : false);
        smtpdump.initSignatureMatcher
			(arg[1] != null && !arg[1].equals(".") ? arg[1] : null);
        smtpdump.initResultGenerator
			(arg[2] != null && !arg[2].equals(".") ? arg[2] : null);
        smtpdump.initSignatureGenerator
			(arg[3] != null && !arg[3].equals(".") ? arg[3] : null,
			 arg[4] != null && !arg[4].equals(".") ? arg[4] : null);
		// start the analysis and detection process
        smtpdump.analyzeSMTPTraffic();
    }
    
}
