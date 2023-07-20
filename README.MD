# Security Process - API Module

This module implements the API using Django REST Framework for the Security Process project.

## Requirements

- Python 3.x
- Virtual environment (virtualenv)
- Required packages (see `requirements.txt`)

## Installation

1. Clone the Security Process repository:

   ```shell
   git clone git@github.com:JR-Camacho/api_security_processes.git
   ```

2. Navigate to the API module directory:

   ```shell
   cd api_security_processes
   ```

3. Create a virtual environment:

   ```shell
   python3 -m venv venv
   source venv/bin/activate
   ```

4. Install the required packages:

   ```shell
   pip install -r requirements.txt
   ```

## Configuration

1. Set up the database:

   ```shell
   python manage.py migrate
   ```

2. Create a superuser account:

   ```shell
   python manage.py createsuperuser
   ```

   Follow the prompts to provide a username and password for the superuser account.

3. Run the development server:

   ```shell
   python manage.py runserver
   ```

   The API will be accessible at `http://localhost:8000/`.

## API Endpoints

The following endpoints are available:

- `POST /api/spam-detector`: With this enpoint you can make predictions. {email_text: ''} or {email_file: File}
- `POST /api/malicious-url-detector`: With this enpoint you can make predictions. {url: ''}


## Directory Structure

- `prediction_api_project/`: Directory containing the Django REST Framework API project.
- `predictor_app/views.py`: Views for the API endpoints.
- `predictor_app/urls.py`: URL routing for the API endpoints.

## Contact

If you have any questions or suggestions regarding the API module of Security Process, feel free to contact us:

- Name: [Jose Camacho]
- Email: [josecamachoc0303@gmail.com]