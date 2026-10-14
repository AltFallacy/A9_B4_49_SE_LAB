#!/usr/bin/env python3
"""
init_db.py - Database Initialization and Administrator Seed Script
------------------------------------------------------------------
Run this script from the terminal to create database tables and seed
an initial administrator account for the Sports Management System (SPMS).

Usage:
    python3 init_db.py
    python3 init_db.py --username manager --password securepassword123
"""

import sys
import argparse
from database import init_db, create_user, get_db_connection, get_db_path


def seed_sample_equipment(db_path=None):
    """
    Seeds initial realistic sports equipment records for demonstration purposes.
    Skips if equipment table already has records.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS total FROM equipment")
        count = cursor.fetchone()["total"]
        if count > 0:
            return  # Already populated

        sample_items = [
            (
                "Basketball (Molten GG7X)",
                "Balls",
                15,
                "Good",
                "Official size 7 indoor/outdoor composite leather basketballs.",
            ),
            (
                "Football (Adidas FIFA Pro)",
                "Balls",
                12,
                "Good",
                "Regulation size 5 match footballs stored in Equipment Shed B.",
            ),
            (
                "Badminton Racket (Yonex Nanoray)",
                "Rackets",
                20,
                "Good",
                "Graphite frame badminton rackets for university team practice.",
            ),
            (
                "Badminton Shuttlecock Tube (Yonex Mavis 350)",
                "Shuttlecocks",
                30,
                "Good",
                "Nylon shuttlecock tubes (pack of 6 each).",
            ),
            (
                "Table Tennis Bat (Stiga Pro Carbon)",
                "Rackets",
                8,
                "Needs Repair",
                "Handle grip loose on 2 bats; rubbers need cleaning.",
            ),
            (
                "Cricket Bat (SS Ton English Willow)",
                "Cricket Gear",
                5,
                "Good",
                "Full-size senior English willow bats for inter-college tournaments.",
            ),
            (
                "Leather Cricket Balls (SG Tournament)",
                "Cricket Gear",
                24,
                "Good",
                "Four-piece red leather match cricket balls.",
            ),
            (
                "Agility Training Cones (Set of 20)",
                "Training",
                10,
                "Good",
                "Fluorescent orange saucer marker cones with metal carry strap.",
            ),
            (
                "Volleyball Net (Mikasa Tournament)",
                "Nets",
                2,
                "Damaged",
                "Torn steel top cable; replacement cable ordered.",
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO equipment (name, category, quantity, condition, description)
            VALUES (?, ?, ?, ?, ?)
            """,
            sample_items,
        )
        conn.commit()
        print(f"[*] Seeded {len(sample_items)} sample sports equipment items.")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Initialize SQLite database for Sports Management System (SPMS)."
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Administrator username (default: admin)",
    )
    parser.add_argument(
        "--password",
        default="admin123",
        help="Administrator password (default: admin123)",
    )
    parser.add_argument(
        "--no-samples",
        action="store_true",
        help="Do not seed sample equipment records",
    )
    args = parser.parse_args()

    db_path = get_db_path()
    print("=" * 60)
    print(" Sports Management System (SPMS) — Database Initialization")
    print("=" * 60)
    print(f"Target Database File: {db_path}")

    # Step 1: Initialize database schema
    print("[1/3] Creating tables (users, equipment)...")
    init_db(db_path)
    print("      Tables verified successfully.")

    # Step 2: Create initial administrator account
    print(f"[2/3] Checking administrator account: '{args.username}'...")
    success, message = create_user(args.username, args.password, db_path=db_path)
    if success:
        print(f"      [SUCCESS] Administrator account '{args.username}' created successfully!")
        print(f"      Credentials -> Username: {args.username} | Password: {args.password}")
    else:
        print(f"      [NOTE] {message}")

    # Step 3: Seed sample equipment (optional)
    if not args.no_samples:
        print("[3/3] Checking sample equipment inventory...")
        seed_sample_equipment(db_path)
    else:
        print("[3/3] Skipping sample equipment seeding (--no-samples specified).")

    print("=" * 60)
    print("Database initialization complete! You can now launch the application.")
    print("Run command: python3 app.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
