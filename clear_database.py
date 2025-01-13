from yourpackage import app, db  # Importuj obiekt app i db z twojej aplikacji

def clear_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Re-create all tables
        db.create_all()
        print("Database has been cleared and re-created.")

if __name__ == "__main__":
    clear_database()