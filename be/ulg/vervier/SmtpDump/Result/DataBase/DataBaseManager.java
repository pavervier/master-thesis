/**
 * Final-year project, University of Liège
 * Automated analysis and detection of spamming botnets.
 * 
 * @author  Pierre-Antoine Vervier
 * @version May, 2010
 * 
 * This class implements a database manager for a database. This database
 * stores information about SMTP sessions matching a given set of SMTP
 * signatures. SMTP signatures are refered to as identified clients, or clients.
 * SMTP sessions are refered to as sessions.
 * 
 */

package be.ulg.vervier.SmtpDump.Result.DataBase;

import java.sql.*;
import java.net.InetAddress;
import be.ulg.vervier.SmtpDump.Result.SDReport;

public abstract class DataBaseManager {
    
    /** INSTANCE VARIABLES */
    
    /** The connection to the database */
    private Connection db_connection;
    /** The database file name */
    private String db_name;
    /** The database driver name */
    protected static String DRIVER;
    /** The database url */
    protected static String URL;
    /** The default database name */
    protected static String DEFAULT_DB_NAME;
    /** A String builder to build SQL statements efficiently */
    private StringBuilder sb;
    /** SQL statement: create table "sd_clients" */
    private static final String create_clients;
    /** SQL statement: create index on table "sd_clients" */
    private static final String create_index_clients;
    /** SQL statement: create table "sd_sessions" */
    private static final String create_sessions;
    /** SQL statement: create table "sd_reports" */
    private static final String create_reports;
    /** SQL statement: create table "sd_time_evolution" */
    private static final String create_time_evolution;
    /** SQL statement: drop table "sd_clients" */
    private static final String drop_clients;
    /** SQL statement: drop table "sd_sessions" */
    private static final String drop_sessions;
    /** SQL statement: drop table "sd_reports" */
    private static final String drop_reports;
    /** SQL statement: drop table "sd_time_evolution" */
    private static final String drop_time_evolution;
    /** A SQL statement */
    private Statement stmt;
    /** SQL prepared statement: add a client */
    private PreparedStatement add_client;
    /** SQL prepared statement: remove client */
    private PreparedStatement remove_client;
    /** SQL prepared statement: get the id from a client name */
    private PreparedStatement get_client_id;
    /** SQL prepared statement: get a client */
    private PreparedStatement get_client;
    /** SQL prepared statement: update a client */
    private PreparedStatement update_client;
    /** SQL prepared statement: add a session */
    private PreparedStatement add_session;
    /** SQL prepared statement: remove a session */
    private PreparedStatement remove_session;
    /** SQL prepared statement: add a report */
    private PreparedStatement add_report;
    /** SQL prepared statement: remove a report */
    private PreparedStatement remove_report;
    /** SQL prepared statement: add a time evolution/daystamp */
    private PreparedStatement add_time_evolution;
    /** SQL prepared statement: get a time evolution/daystamp */
    private PreparedStatement get_time_evolution;
    /** SQL prepared statement: update a time evolution/daystamp */
    private PreparedStatement update_time_evolution;
    /** The next available client identification number */
    private int client_id;
    /** The next available session identification number */
    private int sess_id;
    /** The next available report identification number */
    private int report_id;
    
    static {
        StringBuilder sbuilder = null;
        // SQL statement: create "sd_clients"
        sbuilder = new StringBuilder(100);
        sbuilder.append("CREATE TABLE IF NOT EXISTS sd_clients (");
        sbuilder.append("client_id INT NOT NULL, ");
        sbuilder.append("client_name VAR_CHAR(100) NOT NULL, ");
        sbuilder.append("tcp_packets INT DEFAULT 0, ");
        sbuilder.append("tcp_sessions INT DEFAULT 0, ");
        sbuilder.append("smtp_packets INT DEFAULT 0, ");
        sbuilder.append("smtp_sessions INT DEFAULT 0, ");
        sbuilder.append("start_activity TIMESTAMP DEFAULT 0, ");
        sbuilder.append("end_activity TIMESTAMP DEFAULT 0, ");
        sbuilder.append("CONSTRAINT pk_client ");
        sbuilder.append("PRIMARY KEY (client_id, client_name))");
        create_clients = sbuilder.toString();
        // SQL statement: create index on table "sd_clients"
        create_index_clients =
            "CREATE INDEX client_index ON sd_clients (client_id)";
        // SQL statement: create "sd_sessions"
        sbuilder = new StringBuilder(200);
        sbuilder.append("CREATE TABLE IF NOT EXISTS sd_sessions (");
        sbuilder.append("session_id INT NOT NULL, ");
        sbuilder.append("src_ip_byte_a TINYINT NOT NULL, ");
        sbuilder.append("src_ip_byte_b TINYINT NOT NULL, ");
        sbuilder.append("src_ip_byte_c TINYINT NOT NULL, ");
        sbuilder.append("src_ip_byte_d TINYINT NOT NULL, ");
        sbuilder.append("dst_ip_byte_a TINYINT NOT NULL, ");
        sbuilder.append("dst_ip_byte_b TINYINT NOT NULL, ");
        sbuilder.append("dst_ip_byte_c TINYINT NOT NULL, ");
        sbuilder.append("dst_ip_byte_d TINYINT NOT NULL, ");
        sbuilder.append("src_port_number INT NOT NULL, ");
        sbuilder.append("dst_port_number INT NOT NULL, ");
        sbuilder.append("tcp_packets INT DEFAULT 0, ");
        sbuilder.append("smtp_packets INT DEFAULT 0, ");
        sbuilder.append("smtp_transactions INT DEFAULT 0, ");
        sbuilder.append("start_time TIMESTAMP DEFAULT 0, ");
        sbuilder.append("duration BIGINT DEFAULT 0, ");
        sbuilder.append("src_tcp_options VAR_CHAR(100), ");
        sbuilder.append("dst_tcp_options VAR_CHAR(100), ");
        sbuilder.append("src_first_tcp_seq BIGINT, ");
        sbuilder.append("dst_first_tcp_seq BIGINT, ");
        sbuilder.append("client_id INT NOT NULL, ");
        sbuilder.append("client_name VAR_CHAR(100) NOT NULL, ");
        sbuilder.append("CONSTRAINT ");
        sbuilder.append("pk_session PRIMARY KEY (session_id), ");
        sbuilder.append("CONSTRAINT ");
        sbuilder.append("fk_client_id FOREIGN KEY (client_id) ");
        sbuilder.append("REFERENCES sd_clients_name(client_id))");
        create_sessions = sbuilder.toString();
        // SQL statement: create "sd_reports"
        sbuilder = new StringBuilder(100);
        sbuilder.append("CREATE TABLE IF NOT EXISTS sd_reports (");
        sbuilder.append("report_id INT NOT NULL, ");
        sbuilder.append("tcp_packets INT NOT NULL, ");
        sbuilder.append("tcp_sessions INT NOT NULL, ");
        sbuilder.append("smtp_packets INT DEFAULT 0, ");
        sbuilder.append("smtp_sessions INT DEFAULT 0, ");
        sbuilder.append("CONSTRAINT ");
        sbuilder.append("pk_report PRIMARY KEY (report_id))");
        create_reports = sbuilder.toString();
        // SQL statement: create "sd_time_evolution"
        sbuilder = new StringBuilder(100);
        sbuilder.append("CREATE TABLE IF NOT EXISTS sd_time_evolution (");
        sbuilder.append("daystamp INT NOT NULL, ");
        sbuilder.append("tcp_packets INT DEFAULT 0, ");
        sbuilder.append("tcp_sessions INT DEFAULT 0, ");
        sbuilder.append("smtp_packets INT DEFAULT 0, ");
        sbuilder.append("smtp_sessions INT DEFAULT 0, ");
        sbuilder.append("client_id INT NOT NULL, ");
        sbuilder.append("client_name VAR_CHAR(100) NOT NULL, ");
        sbuilder.append("CONSTRAINT ");
        sbuilder.append("pk_time_evolution PRIMARY KEY (daystamp, client_id))");
        create_time_evolution = sbuilder.toString();
        // SQL statement: drop table "sd_clients"
        drop_clients = "DROP TABLE IF EXISTS sd_clients";
        // SQL statement: drop table "sd_sessions"
        drop_sessions = "DROP TABLE IF EXISTS sd_sessions";
        // SQL statement: drop table "sd_reports"
        drop_reports = "DROP TABLE IF EXISTS sd_reports";
        // SQL statement: drop table "sd_time_evolution"
        drop_time_evolution = "DROP TABLE IF EXISTS sd_time_evolution";
    }
    
    /** CONSTRUCTORS */
    
    /** Default constructor. */
    public DataBaseManager() {
        client_id = 1;
        sess_id = 1;
        report_id = 1;
    }
    
    /** METHODS */
    
    /** Establish a connection to the given database. */
    public void connect(String db_name) throws DataBaseManagerException {
        connect(db_name, null, null);
    }
    
    /** Establish a connection to the given database using a 'login' and
     * 'password' to be granted access to the database. */
    public void connect(String db_name, String login, String pwd)
            throws DataBaseManagerException {
        if (db_name == null || (db_name != null && db_name.isEmpty()))
            db_name = DEFAULT_DB_NAME;
        this.db_name = db_name;
        try {
            Class.forName(DRIVER);
            db_connection = (login == null || pwd == null) ?
                DriverManager.getConnection(URL + db_name) :
                DriverManager.getConnection(URL + db_name, login, pwd);
            stmt = db_connection.createStatement();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        } catch (ClassNotFoundException cnfe) {
            throw new DataBaseManagerException
                ("database-manager:unbale to load SQLite DBMS driver");
        }
    }
    
    /** Close the connection to the database (if any). */
    public void close() throws DataBaseManagerException {
        try {
            if (db_connection != null)
                db_connection.close();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
        db_connection = null;
    }
    
    /** Retrieve the name of the database. */
    public String getDBName() { return db_name == null ? "" : db_name; }
    
    /** Creates the tables. */
    public void createTables() throws DataBaseManagerException {
        if (!isOpen()) return;
        try {
            stmt.executeUpdate(create_clients);
            stmt.executeUpdate(create_index_clients);
            stmt.executeUpdate(create_sessions);
            stmt.executeUpdate(create_reports);
            stmt.executeUpdate(create_time_evolution);
            prepareStatements();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Drop the tables. */
    public void dropTables() throws DataBaseManagerException {
        if (!isOpen()) return;
        try {
            stmt.executeUpdate(drop_clients);
            stmt.executeUpdate(drop_sessions);
            stmt.executeUpdate(drop_reports);
            stmt.executeUpdate(drop_time_evolution);
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Add a client (i.e. identified client, a signature) to the database. */
    public void addClient(String client_name) throws DataBaseManagerException {
        if (!isOpen() || (isOpen() && hasClient(client_name))) return;
        try {
            add_client.setInt(1, client_id++);
            add_client.setString(2, client_name);
            add_client.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Remove a client from the database. */
    public void removeClient(String client_name) throws DataBaseManagerException {
        if (!isOpen() || client_name == null) return;
        try {
            remove_client.setString(1, client_name);
            remove_client.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Update the information asscoiated with a client. */
    public void updateClient(String client_name,
                             int tcp_pkt_count,
                             int tcp_sess_count,
                             int smtp_pkt_count,
                             int smtp_sess_count,
                             long start_activity,
                             long end_activity)
                             throws DataBaseManagerException {
        if (!isOpen() || client_name == null) return;
        try {
            get_client.setString(1, client_name);
            ResultSet rs = get_client.executeQuery();
            if (rs != null) {
                while (rs.next()) {
                    if (tcp_pkt_count >= 0)
                        update_client.setInt(1, rs.getInt(1) + tcp_pkt_count);
                    else update_client.setInt(1, rs.getInt(1));
                    if (tcp_sess_count >= 0)
                        update_client.setInt(2, rs.getInt(2) + tcp_sess_count);
                    else update_client.setInt(2, rs.getInt(2));
                    if (smtp_pkt_count >= 0)
                        update_client.setInt(3, rs.getInt(3) + smtp_pkt_count);
                    else update_client.setInt(3, rs.getInt(3));
                    if (smtp_sess_count >= 0)
                        update_client.setInt(4, rs.getInt(4) + smtp_sess_count);
                    else update_client.setInt(4, rs.getInt(4));
                    if (start_activity >= 0 &&
                        (rs.getLong(5) == 0 || start_activity < rs.getLong(5)))
                        update_client.setLong(5, start_activity);
                    else update_client.setLong(5, rs.getLong(5));
                    if (end_activity >= 0 && end_activity > rs.getLong(6))
                        update_client.setLong(6, end_activity);
                    else update_client.setLong(6, rs.getLong(6));
                    update_client.setString(7, client_name);
                    update_client.executeUpdate();
                }
                rs.close();
            }
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Retrieve the identification number in the database of a client given its
     * name. */
    private int getClientId(String client_name)
            throws DataBaseManagerException {
        if (!isOpen() || client_name == null) return -1;
        int to_return = -1;
        try {
            get_client_id.setString(1, client_name);
            ResultSet rs = get_client_id.executeQuery();
            if (rs != null && rs.next()) {
                to_return = rs.getInt(1);
                rs.close();
            }
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
        return to_return;
    }
    
    /** Return true if the database already store information about the given
     * client. */
    public boolean hasClient(String client_name) throws DataBaseManagerException {
        return getClientId(client_name) > 0;
    }
    
    /** Add the given session information (i.e. the SMTP session that has been
     * matched by a signature) to the database. */
    public void addSession(InetAddress src_ip,
                           InetAddress dst_ip,
                           int src_port,
                           int dst_port,
                           int tcp_pkt_count,
                           int smtp_pkt_count,
                           int smtp_transaction_count,
                           long start_time,
                           long duration,
                           String src_tcp_options,
                           String dst_tcp_options,
                           long src_first_tcp_seq,
                           long dst_first_tcp_seq,
                           String client_name)
                           throws DataBaseManagerException {
        if (!isOpen() || src_ip == null || dst_ip == null || src_port < 1 ||
            dst_port < 1 || tcp_pkt_count < 0 || smtp_pkt_count < 0 ||
            smtp_transaction_count < 0 || start_time < 0 || duration < 0 ||
            src_tcp_options == null || dst_tcp_options == null ||
            src_first_tcp_seq < 0 || dst_first_tcp_seq < 0 ||
            client_name == null)
            return;
        try {
            int c_id = getClientId(client_name);
            if (c_id == -1)
                throw new DataBaseManagerException
                ("database-manager:session matching non existing client error");
            add_session.setInt(1, sess_id++);
            byte[] t_src_ip = src_ip.getAddress();
            byte[] t_dst_ip = dst_ip.getAddress();
            for (int i = 0; i < t_src_ip.length; i++) {
                add_session.setInt(i + 2, ((int)t_src_ip[i]) & 0xff);
                add_session.setInt(i + 6, ((int)t_dst_ip[i]) & 0xff);
            }
            add_session.setInt(10, src_port);
            add_session.setInt(11, dst_port);
            add_session.setInt(12, tcp_pkt_count);
            add_session.setInt(13, smtp_pkt_count);
            add_session.setInt(14, smtp_transaction_count);
            add_session.setLong(15, start_time);
            add_session.setLong(16, duration);
            add_session.setString(17, src_tcp_options);
            add_session.setString(18, dst_tcp_options);
            add_session.setLong(19, src_first_tcp_seq);
            add_session.setLong(20, dst_first_tcp_seq);
            add_session.setInt(21, c_id);
            add_session.setString(22, client_name);
            add_session.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Remove the session associated with the given session id in the
     * database. */
    public void removeSession(int session_id) throws DataBaseManagerException {
        if (!isOpen() || session_id < 0) return;
        try {
            remove_session.setInt(1, session_id);
            remove_session.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }        
    }
    
    /** Add the given report to the database. */
    public void addReport(SDReport report) throws DataBaseManagerException {
        if (!isOpen() || report == null) return;
        try {
            add_report.setInt(1, report_id++);
            add_report.setInt(2, report.tcpPackets());
            add_report.setInt(3, report.tcpSessions());
            add_report.setInt(4, report.smtpPackets());
            add_report.setInt(5, report.smtpSessions());
            add_report.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Remove the report associated with the given report id in the database.*/ 
    public void removeReport(int report_id)
            throws DataBaseManagerException {
        if (!isOpen() || report_id < 0) return;
        try {
            remove_report.setInt(1, report_id);
            remove_report.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Add a new entry in the database for the traffic generated by a client
     * during a given day. */
    public void addTimeEvolution(int daystamp,
                                 int tcp_packets,
                                 int tcp_sessions,
                                 int smtp_packets,
                                 int smtp_sessions,
                                 String client_name)
                                 throws DataBaseManagerException {
        if (!isOpen() || daystamp < 0 || tcp_packets < 0 ||
            tcp_sessions < 0 || smtp_packets < 0 || smtp_sessions < 0 ||
            client_name == null) return;
        try {
            int c_id = getClientId(client_name);
            if (c_id == -1)
                throw new DataBaseManagerException
                ("database-manager:" +
                 "time evolution matching non existing client error");
            add_time_evolution.setInt(1, daystamp);
            add_time_evolution.setInt(2, tcp_packets);
            add_time_evolution.setInt(3, tcp_sessions);
            add_time_evolution.setInt(4, smtp_packets);
            add_time_evolution.setInt(5, smtp_sessions);
            add_time_evolution.setInt(6, c_id);
            add_time_evolution.setString(7, client_name);
            add_time_evolution.executeUpdate();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Update the traffic generated during the given day by the given client.*/
    public void updateTimeEvolution(int daystamp,
                                    int tcp_packets,
                                    int tcp_sessions,
                                    int smtp_packets,
                                    int smtp_sessions,
                                    String client_name)
                                    throws DataBaseManagerException {
        if (!isOpen() || daystamp < 0 || tcp_packets < 0 ||
            tcp_sessions < 0 || smtp_packets < 0 || smtp_sessions < 0 ||
            client_name == null) return;
        try {
            int c_id = getClientId(client_name);
            get_time_evolution.setInt(1, daystamp);
            get_time_evolution.setInt(2, c_id);
            ResultSet rs = get_time_evolution.executeQuery();
            boolean is_update = false;
            if (rs != null) {
                while (rs.next()) {
                    is_update = true;
                    if (tcp_packets >= 0)
                        update_time_evolution.setInt
                            (1, rs.getInt(1) + tcp_packets);
                    else update_time_evolution.setInt(1, rs.getInt(1));
                    if (tcp_sessions >= 0)
                        update_time_evolution.setInt
                            (2, rs.getInt(2) + tcp_sessions);
                    else update_time_evolution.setInt(2, rs.getInt(2));
                    if (smtp_packets >= 0)
                        update_time_evolution.setInt
                            (3, rs.getInt(3) + smtp_packets);
                    else update_time_evolution.setInt(3, rs.getInt(3));
                    if (smtp_sessions >= 0)
                        update_time_evolution.setInt
                            (4, rs.getInt(4) + smtp_sessions);
                    else update_time_evolution.setInt(4, rs.getInt(4));
                    update_time_evolution.setInt(5, daystamp);
                    update_time_evolution.setInt(6, c_id);
                    update_time_evolution.executeUpdate();
                }
            }
            if (!is_update) {
                addTimeEvolution(daystamp,
                                 tcp_packets,
                                 tcp_sessions,
                                 smtp_packets,
                                 smtp_sessions,
                                 client_name);
            }
            rs.close();
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Return true if a connection to a database has been established and not
     * closed yet, false otherwise. */
    public boolean isOpen() {
        return db_connection != null;
    }
    
    /** Pre-compile different commonly used SQL statements to speed up the
     * their execution. */
    private void prepareStatements() throws DataBaseManagerException {
        if (!isOpen()) return;
        try {
            // clients management
            add_client = db_connection.prepareStatement
                ("INSERT INTO sd_clients VALUES " +
                 "(?, ?, NULL, NULL, NULL, NULL, NULL, NULL)");
            remove_client = db_connection.prepareStatement
                ("DELETE FROM sd_clients WHERE client_name = ?");
            get_client_id = db_connection.prepareStatement
                ("SELECT client_id FROM sd_clients WHERE client_name = ?");
            get_client = db_connection.prepareStatement
                ("SELECT tcp_packets, tcp_sessions, smtp_packets, " +
                 "smtp_sessions, start_activity, end_activity " +
                 "FROM sd_clients WHERE client_name = ?");
            update_client = db_connection.prepareStatement
                ("UPDATE sd_clients SET tcp_packets = ?, tcp_sessions = ?, " +
                 "smtp_packets = ?, smtp_sessions = ?, start_activity = ?, " +
                 "end_activity = ? WHERE client_name = ?");
            // sessions management
            add_session = db_connection.prepareStatement
                ("INSERT INTO sd_sessions VALUES (?, ?, " +
                 "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            remove_session = db_connection.prepareStatement
                ("DELETE FROM sd_sessions WHERE session_id = ?");
            // reports management
            add_report = db_connection.prepareStatement
                ("INSERT INTO sd_reports VALUES (?, ?, ?, ?, ?)");
            remove_report = db_connection.prepareStatement
                ("DELETE FROM sd_reports WHERE report_id = ?");
            // time evolution/daystamp management
            add_time_evolution = db_connection.prepareStatement
                ("INSERT INTO sd_time_evolution VALUES (?, ?, ?, ?, ?, ?, ?)");
            get_time_evolution = db_connection.prepareStatement
                ("SELECT tcp_packets, tcp_sessions, smtp_packets, " +
                 "smtp_sessions FROM sd_time_evolution " +
                 "WHERE daystamp = ? and client_id = ?");
            update_time_evolution = db_connection.prepareStatement
                ("UPDATE sd_time_evolution SET tcp_packets = ?, " +
                 "tcp_sessions = ?, smtp_packets = ?, smtp_sessions = ? " +
                 "WHERE daystamp = ? AND client_id = ?");
        } catch (SQLException sqle) {
            throw new DataBaseManagerException(getSQLExceptionReport(sqle));
        }
    }
    
    /** Catch the SQL exceptions that may be thrown by the execution of some
     * 'java.sql.*' methods. Detailed information is provided in order to better
     * identify the reason why exceptions were thrown. */
    private String getSQLExceptionReport(SQLException sqle) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("database-manager:SQL error in database \"");
        sb.append(db_name);
        sb.append("\" (details follow)");
        while (sqle != null) {
            sb.append("\nMessage:").append(sqle.getMessage());
            sb.append("\nSQLState:").append(sqle.getSQLState());
            sb.append("\nErrorCode:").append(sqle.getErrorCode());
            sqle = sqle.getNextException();
        }
        return sb.toString();
    }
    
}
