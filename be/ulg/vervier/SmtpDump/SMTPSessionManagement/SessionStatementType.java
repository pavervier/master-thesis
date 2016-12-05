/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Enumerate SMTP session statement types. SMTP session statement types include:
 * - SMTP command;
 * - SMTP response;
 * - IMF message.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public enum SessionStatementType {
    COMMAND,
    RESPONSE,
    MESSAGE
}
