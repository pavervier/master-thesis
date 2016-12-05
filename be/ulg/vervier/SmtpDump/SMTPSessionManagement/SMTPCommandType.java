/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a SMTP command type. It enumerates each SMTP commands
 * supported. SMTP commands provided by an Extended SMTP compliant server are
 * labeled as EXTN (Extended) (e.g. starttls, auth). The Internet Message Format
 * data sent by a SMTP client is also stored in a SMTP command even if it is not
 * really a SMTP command. The command label IMF refers to that kind of message.
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public enum SMTPCommandType implements StatementType {
    HELO,
    MAIL,
    RCPT,
    DATA,
    IMF,
    QUIT,
    RSET,
    HELP,
    VRFY,
    EXPN,
    NOOP,
    EXTN;
    
    /** Compute the hashcode for the SMTP command. */
    public int hashcode() {
        switch(this) {
            case HELO: return 850;
            case MAIL: return 851;
            case RCPT: return 852;
            case DATA: return 853;
            case IMF: return 854;
            case QUIT: return 855;
            case RSET: return 856;
            case HELP: return 857;
            case VRFY: return 858;
            case EXPN: return 859;
            case NOOP: return 860;
            case EXTN: return 861;
            default: return 0;
        }
    }
}
