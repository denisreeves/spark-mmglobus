# database.py
import mysql.connector
from mysql.connector import Error
import pandas as pd
import numpy as np
from pathlib import Path
import os
from typing import Dict, Optional, Union, List, Tuple
import logging

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Database configuration from .env
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# Connect to MySQL
def connect_db():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        raise

# Example: Create users table if it doesn’t exist
def init_db():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS usersSpark (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()
    print("✅ MySQL Database initialized successfully!")

# Run the initialization
init_db()

class Database:
    def __init__(self):
        """Initialize database connection."""
        self.setup_logging()
        self.conn = connect_db()
        self.cursor = self.conn.cursor()
        self.table_created = False

    def setup_logging(self):
        """Set up logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename='resume_search.log'
        )
        self.logger = logging.getLogger(__name__)

    def create_table_from_df(self, df: pd.DataFrame) -> None:
        """Dynamically create table based on DataFrame columns."""
        try:
            columns = []
            for col in df.columns:
                if df[col].dtype in [np.float64, np.int64]:
                    col_type = "FLOAT"
                else:
                    col_type = "VARCHAR(255)"
                columns.append(f'`{col}` {col_type}')

            columns_sql = ", ".join(columns)

            self.cursor.execute("DROP TABLE IF EXISTS resumes")
            create_table_sql = f"CREATE TABLE resumes ({columns_sql})"
            self.cursor.execute(create_table_sql)

            # Create indexes for performance
            for col in df.columns:
                try:
                    self.cursor.execute(f'CREATE INDEX `idx_{col}` ON resumes(`{col}`)')
                except Error as e:
                    self.logger.warning(f"Failed to create index for {col}: {e}")

            self.conn.commit()
            self.table_created = True
        except Error as e:
            self.logger.error(f"Error creating table: {e}")
            raise

    def clean_numeric(self, value: Union[str, float, int]) -> float:
        """Clean and convert numeric values."""
        if pd.isna(value):
            return np.nan
        try:
            if isinstance(value, str):
                # Remove common suffixes and clean the string
                value = value.lower()
                for suffix in ['lpa', 'years', 'k', 'inr', '$']:
                    value = value.replace(suffix, '')
                value = value.strip()
            return float(value)
        except (ValueError, TypeError):
            return np.nan

    def clean_text(self, value: str) -> str:
        """Clean text values."""
        if pd.isna(value):
            return ""
        return str(value).strip()

    def process_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Process and clean dataframe before insertion."""
        processed = df.copy()
        
        # Clean numeric columns
        numeric_cols = processed.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            processed[col] = processed[col].apply(self.clean_numeric)
        
        # Clean text columns
        text_cols = processed.select_dtypes(include=['object']).columns
        for col in text_cols:
            processed[col] = processed[col].apply(self.clean_text)
        
        return processed

    def insert_data(self, file_path: str) -> Tuple[bool, str]:
        """Insert data from CSV/Excel file into the database."""
        try:
            # Read file based on extension
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
            elif file_path.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(file_path)
            else:
                raise ValueError("Unsupported file format")
            
            # Create table if not exists
            if not self.table_created:
                self.create_table_from_df(df)
            
            # Process dataframe
            df_cleaned = self.process_dataframe(df)
            
            # Insert into database
            with self.conn.cursor() as cursor:
                # Convert DataFrame to list of tuples for MySQL insertion
                data_tuples = [tuple(row) for row in df_cleaned.to_numpy()]
                columns = ', '.join([f'`{col}`' for col in df_cleaned.columns])
                placeholders = ', '.join(['%s'] * len(df_cleaned.columns))
                insert_query = f"INSERT INTO resumes ({columns}) VALUES ({placeholders})"
                cursor.executemany(insert_query, data_tuples)
                self.conn.commit()
            
            self.logger.info(f"Successfully inserted {len(df_cleaned)} records")
            return True, f"Successfully inserted {len(df_cleaned)} records"
        except Error as e:
            self.logger.error(f"Error inserting data: {e}")
            return False, f"Error inserting data: {str(e)}"

    def search_resumes(self, filters: Dict[str, Union[str, tuple, List[str]]]) -> pd.DataFrame:
        """Search resumes based on provided filters."""
        try:
            query = "SELECT * FROM resumes WHERE 1=1"
            params = []
            
            for column, value in filters.items():
                if value:
                    if isinstance(value, tuple):  # Range filter
                        query += f' AND `{column}` BETWEEN %s AND %s'
                        params.extend(value)
                    elif isinstance(value, list):  # Multi-select filter
                        placeholders = ','.join(['%s'] * len(value))
                        query += f' AND `{column}` IN ({placeholders})'
                        params.extend(value)
                    else:  # Text search
                        query += f' AND LOWER(`{column}`) LIKE LOWER(%s)'
                        params.append(f"%{value}%")
            
            with self.conn.cursor(dictionary=True) as cursor:
                cursor.execute(query, params)
                result = cursor.fetchall()
                df = pd.DataFrame(result)
            return df
        except Error as e:
            self.logger.error(f"Error searching resumes: {e}")
            return pd.DataFrame()

    def get_unique_values(self, column: str) -> List[str]:
        """Get unique values for a column."""
        try:
            with self.conn.cursor(dictionary=True) as cursor:
                query = f'SELECT DISTINCT `{column}` FROM resumes WHERE `{column}` IS NOT NULL'
                cursor.execute(query)
                result = cursor.fetchall()
                df = pd.DataFrame(result)
                return sorted(df[column].dropna().unique().tolist())
        except Error as e:
            self.logger.error(f"Error getting unique values for {column}: {e}")
            return []

    def get_column_stats(self, column: str) -> Dict[str, float]:
        """Get statistics for numeric columns."""
        try:
            with self.conn.cursor() as cursor:
                query = f'SELECT MIN(`{column}`), MAX(`{column}`), AVG(`{column}`) FROM resumes'
                cursor.execute(query)
                min_val, max_val, avg_val = cursor.fetchone()
                return {
                    "min": float(min_val or 0),
                    "max": float(max_val or 0),
                    "avg": float(avg_val or 0)
                }
        except Error as e:
            self.logger.error(f"Error getting column stats for {column}: {e}")
            return {"min": 0, "max": 0, "avg": 0}

    def __del__(self):
        """Close the database connection when the object is destroyed."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()