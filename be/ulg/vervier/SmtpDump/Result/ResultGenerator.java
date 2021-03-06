/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a result processor. Given a set of SMTP sessions
 * matching SMTP signatures, it processes information extracted from these
 * sessions and exports results in a database.
 * 
 */

package be.ulg.vervier.SmtpDump.Result;

import java.util.Collection;
import java.util.concurrent.ArrayBlockingQueue;
import be.ulg.vervier.SmtpDump.TCPSessionManagement.TCPSession;
import be.ulg.vervier.SmtpDump.SMTPSessionManagement.SMTPSession;
import be.ulg.vervier.SmtpDump.BotsSignature.MatchingSMTPSession;
import be.ulg.vervier.SmtpDump.Result.DataBase.*;
import java.util.logging.Logger;

public class ResultGenerator {
    
    /** INSTANCE VARIABLES */
    
    /** The result exporter */
    private DataBaseManager db_manager;
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public ResultGenerator() {
        db_manager = new SQLiteDataBaseManager();
    }
    
    /** METHODS */
    
    /** Open the database storing results. */
    public void openDataBase(String db_name) throws ResultGeneratorException {
        try {
            db_manager.connect(db_name);
            db_manager.dropTables();
            db_manager.createTables();
        } catch (DataBaseManagerException dbme) {
            throw new ResultGeneratorException(dbme.getMessage());
        }
    }
    
    /** Store the mail session matching a signature in the database. */
    public void addSession(MatchingSMTPSession session)
            throws ResultGeneratorException {
        if (session == null || (session != null && session.isEmpty())) return;
        SMTPSession smtp_s = session.matchingSession();
        TCPSession tcp_s = smtp_s.getTCPSession();
        try {
            for (String client: session.matchedClientsID()) {
				// add the signature (a.k.a. client) that has matched the
				// session to the database
                if (!db_manager.hasClient(client))
                    db_manager.addClient(client);
                db_manager.updateClient(client,
                                             tcp_s.getSourcePacketCount(),
                                             1,
                                             smtp_s.getClientPacketCount(),
                                             1,
                                             tcp_s.getStartTime(),
                                             tcp_s.getStartTime() + 
                                             tcp_s.getDuration());
                // add the session to the database
                db_manager.addSession(smtp_s.getClientIP(),
                                      smtp_s.getServerIP(),
                                      smtp_s.getClientPort(),
                                      smtp_s.getServerPort(),
                                      tcp_s.getSourcePacketCount(),
                                      smtp_s.getClientPacketCount(),
                                      smtp_s.getTransactionCount(),
                                      tcp_s.getStartTime(),
                                      tcp_s.getDuration(),
                                      tcp_s.getSourceOptions().toString(),
                                      tcp_s.getDestinationOptions().toString(),
                                      tcp_s.getSourceStartSeq(),
                                      tcp_s.getDestinationStartSeq(),
                                      client);
                // update the traffic generated by this client with information
                // from the session
                db_manager.updateTimeEvolution((int)(tcp_s.getStartTime() / 86400000),
                                               tcp_s.getSourcePacketCount(),
                                               1,
                                               smtp_s.getClientPacketCount(),
                                               1,
                                               client);
            }
        } catch (DataBaseManagerException dbme) {
            throw new ResultGeneratorException(dbme.getMessage());
        }
    }
    
    /** Write a given report to the database. A report provides information
     * about the execution of the system. */
    public void addReport(SDReport report) throws ResultGeneratorException {
        if (report == null) return;
        try {
            db_manager.addReport(report);
        } catch (DataBaseManagerException dbme) {
            throw new ResultGeneratorException(dbme.getMessage());
        }
    }
    
    /** Close the database. */
    public void closeDataBase() throws ResultGeneratorException {
        try {
            db_manager.close();
        } catch (DataBaseManagerException dbme) {
            throw new ResultGeneratorException(dbme.getMessage());
        }
    }
    
    /** Retrieve the results output database name. */
    public String getDBName() {
        return db_manager == null ? "" : db_manager.getDBName();
    }
    
}
