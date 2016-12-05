/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Enumerate all Internet Message Format (RFC 5322) statement types.
 * Statement type include:
 * - IMF header fields (RFC 5322, "X-" fields and MIME fields);
 * - IMF header-message seperator;
 * - IMF message;
 * - IMF termination sequence.
 * Extended fields beginning with "X-" are designated be the "X-FIELD" statement
 * type.
 * 
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public enum IMFStatementType implements StatementType {
    FROM,
    SENDER,
    TO,
    CC,
    BCC,
    COMMENTS,
    DATE,
    IN_REPLY_TO,
    KEYWORDS,
    MESSAGE_ID,
    RECEIVED,
    REPLY_TO,
    RESENT_DATE,
    RESENT_FROM,
    RESENT_SENDER,
    RESENT_TO,
    RESENT_CC,
    RESENT_BCC,
    RESENT_MESSAGE_ID,
    REFERENCES,
    RETURN_PATH,
    SUBJECT,
    MIME_VERSION,
    CONTENT_TYPE,
    CONTENT_TRANSFER_ENCODING,
    CONTENT_ID,
    CONTENT_DESCRIPTION,
    X_FIELD,
    BODY,
    TERM_SEQ;
    
    /** Compute the hashcode for a IMF statement. */
    public int hashcode() {
        switch(this) {
            case FROM: return 1880;
            case SENDER: return 1881;
            case TO: return 1882;
            case CC: return 1883;
            case BCC: return 1884;
            case COMMENTS: return 1885;
            case DATE: return 1886;
            case IN_REPLY_TO: return 1887;
            case KEYWORDS: return 1888;
            case MESSAGE_ID: return 1889;
            case RECEIVED: return 1890;
            case REPLY_TO: return 1891;
            case RESENT_DATE: return 1892;
            case RESENT_FROM: return 1893;
            case RESENT_SENDER: return 1894;
            case RESENT_TO: return 1895;
            case RESENT_CC: return 1896;
            case RESENT_BCC: return 1897;
            case RESENT_MESSAGE_ID: return 1898;
            case REFERENCES: return 1899;
            case RETURN_PATH: return 1900;
            case SUBJECT: return 1901;
            case MIME_VERSION: return 1902;
            case CONTENT_TYPE: return 1903;
            case CONTENT_TRANSFER_ENCODING: return 1904;
            case CONTENT_ID: return 1905;
            case CONTENT_DESCRIPTION: return 1906;
            case X_FIELD: return 1907;
            case BODY: return 1908;
            case TERM_SEQ: return 1909;
            default: return 0;
        }
    }
}
