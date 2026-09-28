"""Add lossless NVD match metadata. Run before deploying version-aware code."""
from sqlalchemy import text
from db.session import engine


def main():
    with engine.begin() as connection:
        connection.execute(text(
            'ALTER TABLE cpe_matches ADD COLUMN IF NOT EXISTS match_criteria JSON'
        ))


if __name__ == '__main__':
    main()
