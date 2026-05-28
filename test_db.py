import mysql.connector

def test_database_connection():
    try:
        # 1. Establish the connection to your local LAMP stack
        # (Change 'root' and password '' if you set a password during XAMPP setup)
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="", 
            database="security_platform"
        )
        
        if connection.is_connected():
            print("Successfully connected to the LAMP database!")
            cursor = connection.cursor()
            
            # 2. Insert a dummy asset to prove it works
            target_ip = "127.0.0.1"
            target_host = "Localhost-Test"
            
            sql_query = "INSERT INTO assets (ip_address, hostname) VALUES (%s, %s)"
            record_to_insert = (target_ip, target_host)
            
            cursor.execute(sql_query, record_to_insert)
            
            # 3. Commit the changes to save them permanently
            connection.commit()
            print(f"Success: Inserted test asset {target_ip} into the database.")
            
    except mysql.connector.Error as error:
        print(f"Failed to connect or insert data: {error}")
        
    finally:
        # Always close the connection when done
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print("Database connection closed cleanly.")

# Run the function
if __name__ == "__main__":
    test_database_connection()