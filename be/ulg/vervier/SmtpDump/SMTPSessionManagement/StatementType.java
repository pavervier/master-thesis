/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * Interface for a session statement type. A session statement type can either
 * be a SMTP command type or a IMF statement type. The only purpose of this
 * interface is to have group different session statement types in a unique
 * statement type. Session statement types include:
 * - SMTP command types (e.g. HELO, RSET, QUIT, etc);
 * - IMF statement types (e.g. SUBJECT, FROM, TO, etc).
 *
 */

package be.ulg.vervier.SmtpDump.SMTPSessionManagement;

public interface StatementType {}
