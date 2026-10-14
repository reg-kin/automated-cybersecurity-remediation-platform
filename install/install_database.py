#!/usr/bin/env python3
"""Command-line entry point for fresh database installation."""

import argparse
import os
import sys

from database import SQL_FILES, execute_migrations, validate_database_target


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(
        description="Install the Regis Security database into an empty database."
    )

    parser.add_argument(
        "--database",
        required=True,
        help="Name of the existing, empty target database.",
    )

    parser.add_argument(
        "--confirm-database",
        required=True,
        help="Repeat the exact target database name to authorise installation.",
    )

    args = parser.parse_args(argv)

    try:
        database_name = validate_database_target(args.database)
    except ValueError as error:
        parser.error(str(error))

    if args.confirm_database != database_name:
        parser.error(
            "--confirm-database must exactly match --database."
        )

    args.database = database_name
    return args



def connect_database(database_name):
    """Connect to the explicitly selected PostgreSQL database."""
    import psycopg2

    password = os.environ.get("PG_PASSWORD")
    if not password:
        raise RuntimeError("PG_PASSWORD environment variable is required.")

    connection = psycopg2.connect(
        host=os.environ.get("PG_HOST", "127.0.0.1"),
        port=os.environ.get("PG_PORT", "5432"),
        dbname=database_name,
        user=os.environ.get("PG_USER", ""),
        password=password,
        connect_timeout=10,
    )

    try:
        connection.autocommit = False

        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            actual_database = cursor.fetchone()[0]

        connection.rollback()

        if actual_database != database_name:
            raise RuntimeError(
                "Connected database does not match requested target."
            )

        return connection

    except Exception:
        connection.close()
        raise


def main():
    args = parse_arguments()
    connection = None

    try:
        connection = connect_database(args.database)

        applied = execute_migrations(connection)

        expected_count = len(SQL_FILES)
        if len(applied) != expected_count:
            raise RuntimeError(
                f"Expected {expected_count} migrations, "
                f"executed {len(applied)}."
            )

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT count(*)
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_type = 'BASE TABLE'
            """)
            table_count = cursor.fetchone()[0]

        if table_count == 0:
            raise RuntimeError(
                "Installation verification failed: no application tables."
            )

        connection.commit()

        print(f"PASS: {len(applied)} migrations committed.")
        print(f"PASS: {table_count} application tables installed.")
        print(f"PASS: Database installation completed: {args.database}")
        return 0

    except Exception as error:
        if connection is not None:
            connection.rollback()
        print(
            f"Database installation failed: {error}",
            file=sys.stderr,
        )
        return 1

    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    sys.exit(main())
