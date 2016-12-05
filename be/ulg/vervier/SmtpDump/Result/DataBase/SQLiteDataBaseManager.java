/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a database manager for a SQLite database. It extends
 * the DBMS-independent DataBaseManager class and provides the information
 * needed to use a SQLite database.
 * 
 */

package be.ulg.vervier.SmtpDump.Result.DataBase;

public class SQLiteDataBaseManager extends DataBaseManager {
    
    /** Default constructor, create a new SQLite database manager. */    
    public SQLiteDataBaseManager() {
        DRIVER = "org.sqlite.JDBC";
        URL = "jdbc:sqlite:";
        DEFAULT_DB_NAME = "smtpdump.db";
    }
    
}
