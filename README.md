# ochronaProjekt

## Project Overview
This is a web application built with Python and the Flask framework. The project is designed to simulate messaging app.
The project uses a modular structure.

## Features
*   **Web Interface:** Built using Flask.
*   **Database Management:** Integrated SQLAlchemy for database operations.
*   **Security:** Environment variable support for sensitive data.
*   **Development Tools:** Utility scripts for resetting the database state.

## Prerequisites
*   Python 3.x
*   pip (Python package installer)
*   Virtual environment (recommended)

## Database Management
To initialize or completely reset the database (drop all tables and recreate them), run the utility script:
```bash
python clear_database.py
```
*Note: This will erase all existing data in the database.*

## Running the Application
To start the development server:
```bash
python app.py
```
The application will be available at `http://127.0.0.1:5000/`.

## Project Structure
*   `app.py`: The main entry point to run the application.
*   `clear_database.py`: A script to reset/initialize the database schema.
*   `yourpackage/`: (Directory) Contains the core application logic, models, and routes.

## License
MIT License
