# TooDY, a new Tool for Detecting variabilitY
![](pagina1-welcome.png)\
![](pagina1-lista.png)


## Project Description
*TooDY* is a natural language processing tool designed to identify variability indicators in requirement documents. It leverages lexical and syntactic analysis and is built upon the *spaCy* library. This tool situates itself in the research line of specifying software product lines (*SPL*) from natural language requirement documents. Ambiguities in requirement documents often lead to inconsistencies between client expectations and the developed product, resulting in undesirable rework of artifacts. However, ambiguity can also be a means to defer decisions. Building on this concept, it has been shown that ambiguity detection can also serve as a way to capture hidden aspects of variability in requirements, utilizing specific variability indicators that differ from known ambiguity indicators.


## Dependencies and Local Deployment
In order to run the application locally, you'll need to install the required dependencies and libraries. Clone this repository first and navigate to the project directory:
```bash
git clone https://github.com/matteogiorgi/toody
cd toody
```

### Prerequisites
- *Python 3.x* language
- *spaCy* library for *NLP*
- *Flask* web framework

### Required Libraries
The application depends on several *Python* libraries, including:
- **_spaCy_**: for natural language processing.
- **_Flask_**: a lightweight WYSIWYG web application framework.
- **_Flask-Login_**: for managing user sessions.
- **_Flask-SQLAlchemy_**: an ORM for *Flask* applications.
- **_Werkzeug_**: for password hashing and authentication.
- **_APScheduler_**: for scheduling background jobs.
- **_python-slugify_**: for generating slugs from strings.
- **_Pytz_**: for timezone calculations.

### Installing Dependencies
To install the required *Python* libraries, run the following command:
```bash
pip install spacy flask flask_login flask_sqlalchemy werkzeug apscheduler python-slugify pytz
```

### Setting up spaCy
After installing *spaCy*, you'll need to download the language model:
```bash
python -m spacy download en_core_web_sm
```

### Running the Application Locally
To start the *Flask* server on your local machine, navigate to the project directory and run:
```bash
python app.py
```


## License
This project is licensed under the *GPL-3.0 license* - see the `LICENSE` file for details.
