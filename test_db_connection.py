from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError

from app.utilities.config import settings


def redacted(settings):
    return f"{settings.database_username}:***@{settings.database_hostname}:{settings.database_port}/{settings.database_name}"


def try_connect(database_name=None):
    dbname = database_name or settings.database_name
    url = URL.create(
        drivername="postgresql+psycopg2",
        username=settings.database_username,
        password=settings.database_password,
        host=settings.database_hostname,
        port=int(settings.database_port),
        database=dbname,
    )
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, None
    except OperationalError as e:
        return False, e


def main():
    print("Using settings:")
    print("  host:", settings.database_hostname)
    print("  port:", settings.database_port)
    print("  user:", settings.database_username)
    print("  db (target):", settings.database_name)
    print("  redacted DSN:", redacted(settings))

    ok, err = try_connect()
    if ok:
        print('\nSUCCESS: Connected to target database.')
        return

    print('\nERROR connecting to target database:')
    print(err)

    # If database does not exist, attempt to connect to default 'postgres' to verify credentials/server reachability
    msg = str(err).lower()
    if 'does not exist' in msg or 'unknown database' in msg:
        print('\nIt looks like the target database does not exist.')
        print("Attempting to connect to the 'postgres' default database to verify credentials...")
        ok2, err2 = try_connect(database_name='postgres')
        if ok2:
            print('\nCREDENTIALS OK: Connected to default database. The target DB is missing.')
        else:
            print('\nFAILED to connect to the server with provided credentials:')
            print(err2)
    else:
        print('\nThe error indicates a connection/authentication problem. Trying default database to disambiguate...')
        ok2, err2 = try_connect(database_name='postgres')
        if ok2:
            print('\nConnected to default database; credentials are valid, target DB may be missing or you lack privileges.')
        else:
            print('\nUnable to connect to server using provided credentials. Error:')
            print(err2)


if __name__ == '__main__':
    main()
