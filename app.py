import spacy
from spacy.matcher import PhraseMatcher
from spacy.symbols import VERB
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    flash,
    abort,
    send_from_directory,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from slugify import slugify
import json
import random
import string
import os
import zipfile
import pytz
import re


app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
MIN_PASSWORD_LENGTH = 8
nlp = spacy.load("en_core_web_sm")
app.jinja_env.filters["slugify"] = slugify
local_tz = pytz.timezone("Europe/Rome")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    backup_code = db.Column(db.String(150), nullable=True)
    last_login_date = db.Column(db.DateTime, nullable=True)
    last_activity = db.Column(db.DateTime, nullable=True)
    requests = db.relationship(
        "Request", backref="author", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password = generate_password_hash(password, method="sha256")

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Request(db.Model):
    # Poiché `results` sarà una lista di dizionari,
    # sarà meglio archiviarla come testo JSON.
    id = db.Column(db.Integer, primary_key=True)
    content1 = db.Column(db.Text, nullable=False)
    content2 = db.Column(db.Text, nullable=False)
    lexical_total_matches = db.Column(db.Integer, nullable=True)
    passive_total_matches = db.Column(db.Integer, nullable=True)
    verb_conjunction_total_matches = db.Column(db.Integer, nullable=True)
    conjunction_sentence_total_matches = db.Column(db.Integer, nullable=True)
    results = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    request_name = db.Column(db.String(150), nullable=False, default="Unnamed Request")
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(local_tz))
    word_context = db.Column(db.Text, nullable=True)  # Aggiungi questa linea
    memory_data = db.Column(
        db.Text, nullable=True
    )  # Campo per archiviare il dizionario memory come testo JSON


@app.before_request
def update_last_activity_and_check_inactivity():
    # Escludi le route che non necessitano di autenticazione
    # aggiungi 'None' per gestire gli endpoint non definiti
    if request.endpoint in ["login", "register", "about", "heartbeat", None]:
        return

    if not current_user.is_authenticated:
        return

    now = datetime.utcnow()

    # Se last_activity è None, aggiorna semplicemente all'orario corrente
    if not current_user.last_activity:
        current_user.last_activity = now
        db.session.commit()
        return

    # Controlla l'inattività
    # faccio lo stesso il controllo anche se già ci pensa heartbeat
    # nel caso in cui l'utente abbia disattivato javascript sul browser
    if (now - current_user.last_activity) > timedelta(minutes=30):
        logout_user()
        flash("You have been logged out due to inactivity.", "warning")
        return redirect(url_for("login"))

    # Aggiorna l'ultima attività
    current_user.last_activity = now
    db.session.commit()


@app.route("/heartbeat")
@login_required
def heartbeat():
    now = datetime.utcnow()

    # Controlla l'inattività
    if (now - current_user.last_activity) > timedelta(minutes=30):
        logout_user()
        flash("You have been logged out due to inactivity.", "warning")
        return redirect(url_for("login"))

    return "", 204  # HTTP 204 No Content, indicando che tutto va bene


@app.route("/")
@app.route("/<string:order>")
def main(order=None):
    if current_user.is_authenticated:
        if order == "name_asc":
            user_requests = (
                Request.query.filter_by(user_id=current_user.id)
                .order_by(Request.request_name.asc())
                .all()
            )
        elif order == "name_desc":
            user_requests = (
                Request.query.filter_by(user_id=current_user.id)
                .order_by(Request.request_name.desc())
                .all()
            )
        elif order == "date_asc":
            user_requests = (
                Request.query.filter_by(user_id=current_user.id)
                .order_by(Request.timestamp.asc())
                .all()
            )
        elif order == "date_desc":
            user_requests = (
                Request.query.filter_by(user_id=current_user.id)
                .order_by(Request.timestamp.desc())
                .all()
            )
        else:
            user_requests = Request.query.filter_by(user_id=current_user.id).all()
        return render_template("main.html", user_requests=user_requests, order=order)
    else:
        return render_template("main.html")


@app.route("/about")
def about():
    return render_template("about.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def generate_random_string(length=8):
    return "".join(
        random.choice(string.ascii_letters + string.digits) for _ in range(length)
    )


@app.route("/new-backup-code", methods=["GET"])
@login_required
def new_backup_code():
    backup_code = generate_random_string(8)
    current_user.backup_code = backup_code
    db.session.commit()

    flash(
        f"Your new backup code is {backup_code}. " + "Keep it in a safe place!", "info"
    )
    # return redirect(request.referrer or url_for('main'))
    return redirect(url_for("main"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "warning")
            return redirect(url_for("register"))

        if len(password) < MIN_PASSWORD_LENGTH:
            flash(
                f"Password must be at least {MIN_PASSWORD_LENGTH} "
                + "characters long.",
                "danger",
            )
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash(
                f"User {username} already exists. " + "Choose a different username.",
                "danger",
            )
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password, method="sha256")
        backup_code = generate_random_string(8)
        new_user = User(
            username=username, password=hashed_password, backup_code=backup_code
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash(f"User {username} successfully created!", "success")
        flash(
            f"Your backup code is: {backup_code}. " + "Keep it in a safe place!", "info"
        )
        return redirect(url_for("main"))

    return render_template("register.html")


@app.route("/unregister", methods=["POST"])
@login_required
def unregister():
    password = request.form["password"]
    user = User.query.filter_by(id=current_user.id).first()
    if not check_password_hash(user.password, password):
        flash("Incorrect password. Please try again.", "danger")
        return redirect(url_for("main"))

    username = current_user.username
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash(f"User {username} has been deleted.", "info")
    return redirect(url_for("main"))


# @app.route("/download-request/<int:request_id>", methods=["GET"])
# @login_required
# def download_request(request_id):
#     req = Request.query.get_or_404(request_id)
#     if req.user_id != current_user.id:
#         abort(403)

#     # Pulire il nome della richiesta per usarlo come nome del file
#     safe_request_name = "".join(
#         [
#             c
#             for c in req.request_name
#             if c.isalpha() or c.isdigit() or c in [" ", "-", "_"]
#         ]
#     ).rstrip()

#     # Creare un file ZIP temporaneo
#     zip_filename = f"{safe_request_name}.zip"
#     zip_path = os.path.join("/tmp", zip_filename)

#     with zipfile.ZipFile(zip_path, "w") as zipf:
#         zipf.writestr("text.txt", req.content1)
#         zipf.writestr("dictionary.txt", req.content2)
#         zipf.writestr("results.txt", req.results)
#         # zipf.writestr("results.txt", json.dumps(json.loads(req.word_count), indent=4))
#         # zipf.writestr("context.txt", json.dumps(json.loads(req.word_context), indent=4))

#     # Nota: L'uso di /tmp come directory temporanea potrebbe
#     # non funzionare su tutti i sistemi. In produzione, potresti
#     # voler utilizzare una libreria come tempfile per gestire
#     # la creazione di file temporanei in modo sicuro e compatibile
#     # tra diverse piattaforme.
#     return send_from_directory("/tmp", zip_filename, as_attachment=True)


@app.route("/download-request/<int:request_id>", methods=["GET"])
@login_required
def download_request(request_id):
    req = Request.query.get_or_404(request_id)
    if req.user_id != current_user.id:
        abort(403)

    safe_request_name = "".join(
        [
            c
            for c in req.request_name
            if c.isalpha() or c.isdigit() or c in [" ", "-", "_"]
        ]
    ).rstrip()

    zip_filename = f"{safe_request_name}.zip"
    zip_path = os.path.join("/tmp", zip_filename)

    combined_results = json.loads(req.results)

    # Funzione per formattare i risultati in una forma testuale leggibile
    def format_results_for_text(results_dict, title):
        formatted_text = title.upper() + "\n" + "=" * len(title) + "\n\n"
        for key, value_list in results_dict.items():
            formatted_text += key + "\n" + "¯" * len(key) + "\n"
            for entry in value_list:
                sentence = (
                    entry["sentence"]
                    .replace('<span class="highlighted-word">', "*")
                    .replace("</span>", "*")
                )
                formatted_text += (
                    f"[Line {entry['line']}] ({entry['tag']})\n{sentence}\n\n"
                )
            formatted_text += "\n"
        return formatted_text

    def create_regex_from_sentence(sentence):
        # Spezza la frase in parole
        # Crea una regex per ogni parola
        # Combiniamo le regex di tutte le parole
        words = sentence.split()
        word_patterns = [f"(?:<[^>]*>)*{re.escape(word)}(?:<[^>]*>)*" for word in words]
        pattern = r"\s*".join(word_patterns)
        return pattern

    # Funzione per formattare i risultati in una forma HTML leggibile
    def generate_html_content(content, memory):
        # Normalizza le nuove righe nel contenuto
        content = content.replace("\r\n", "\n")

        for category, words in memory.items():
            for word, markers in words.items():
                for marker_type, sentences in markers.items():
                    for sentence in sentences:
                        # Qui rimuoviamo i tag HTML dalla sentence per creare un pattern regex
                        clean_sentence = sentence.replace(
                            '<span class="highlighted-word">', ""
                        ).replace("</span>", "")

                        # Normalizza le nuove righe nella sentence
                        clean_sentence = clean_sentence.replace("\r\n", "\n")

                        # Determina il colore in base al tipo di marker
                        if marker_type == "false_positive":
                            color = "red"
                        elif marker_type == "ambiguity":
                            color = "blue"
                        elif marker_type == "variability":
                            color = "yellow"
                        else:
                            color = "green"

                        # Creiamo un pattern regex per la frase
                        pattern = create_regex_from_sentence(clean_sentence)

                        # Trova la corrispondenza della frase nel contenuto
                        matched_sentence = re.search(
                            pattern, content, flags=re.IGNORECASE
                        )
                        if not matched_sentence:
                            continue

                        # Trova gli indici di inizio e fine della parola nella sentence (con tag HTML)
                        start_marker = '<span class="highlighted-word">'
                        start_idx = sentence.find(start_marker)  # + len(start_marker)
                        end_idx = start_idx + len(word)
                        print("Start index:", start_idx)
                        print("End index:", end_idx)

                        # Calcola gli indici corrispondenti nel matched_sentence considerando eventuali tag HTML
                        in_tag = False
                        actual_idx = 0
                        mapped_start_idx = 0
                        mapped_end_idx = 0
                        for idx, char in enumerate(matched_sentence.group(0)):
                            if char == "<":
                                in_tag = True
                            if not in_tag:
                                if actual_idx == start_idx:
                                    mapped_start_idx = idx
                                if actual_idx == end_idx - 1:
                                    mapped_end_idx = idx + 1
                                    break
                                actual_idx += 1
                            if char == ">":
                                in_tag = False

                        print("Mapped start index:", mapped_start_idx)
                        print("Mapped end index:", mapped_end_idx)

                        # Evidenzia la parola corretta nel matched_sentence
                        highlighted_sentence = (
                            matched_sentence.group(0)[:mapped_start_idx]
                            + f'<span style="background-color:{color}">{word}</span>'
                            + matched_sentence.group(0)[mapped_end_idx:]
                        )

                        print(matched_sentence.group(0)[:mapped_start_idx])
                        print(matched_sentence.group(0)[mapped_end_idx:])
                        print("Highlighted sentence:", highlighted_sentence)

                        # Sostituisci la corrispondenza originale nella content con la corrispondenza evidenziata
                        content = content.replace(
                            matched_sentence.group(0), highlighted_sentence, 1
                        )

        html_content = f"""
        <html>
        <head>
            <title>Highlighted Content</title>
        </head>
        <body>
            <pre>{content}</pre>
        </body>
        </html>
        """
        return html_content

    # Creare il contenuto testuale leggibile
    readable_results = ""
    readable_results += format_results_for_text(
        combined_results["lexical_results"], "Lexical Matches"
    )
    readable_results += format_results_for_text(
        combined_results["passive_form_results"], "Passive Form Matches"
    )
    readable_results += format_results_for_text(
        combined_results["verb_conjunction_results"], "Verb Conjunction Matches"
    )
    readable_results += format_results_for_text(
        combined_results["conjunction_sentence_results"], "Conjunction Sentence Matches"
    )

    # Sostituire i caratteri speciali e creare il contenuto HTML
    readable_results = readable_results.replace("\r", "").replace("\n", os.linesep)
    html_content = generate_html_content(req.content1, json.loads(req.memory_data))

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.writestr("text.txt", req.content1)
        zipf.writestr("dictionary.txt", req.content2)
        zipf.writestr("results.txt", readable_results)
        zipf.writestr("highlighted.html", html_content)  # Aggiungi questa linea

    return send_from_directory("/tmp", zip_filename, as_attachment=True)


@app.route("/delete-request/<int:request_id>", methods=["POST"])
@login_required
def delete_request(request_id):
    req = Request.query.get_or_404(request_id)
    if req.user_id != current_user.id:
        abort(403)
    db.session.delete(req)
    db.session.commit()
    flash("Request successfully deleted!", "success")
    return redirect(url_for("main"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main"))

    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if user and user.backup_code == request.form["password"]:
            new_password = generate_random_string(8)
            user.set_password(new_password)
            user.last_login_date = datetime.utcnow()
            user.last_activity = datetime.utcnow()  # <-- Aggiungi questa linea
            db.session.commit()

            login_user(user)
            flash(
                f"Hi {user.username}, you've logged in with " + "the backup code!",
                "warning",
            )
            flash(
                f"Your new password is {new_password}. "
                + "Please change it as soon as possible!",
                "info",
            )
            return redirect(url_for("main"))

        elif user and user.check_password(request.form["password"]):
            login_user(user)
            user.last_login_date = datetime.utcnow()
            user.last_activity = datetime.utcnow()  # <-- Aggiungi questa linea
            db.session.commit()
            flash(f"Hi {user.username}, you've successfully logged in!", "success")
            return redirect(url_for("main"))
        else:
            flash("Login failed. Please check your username and password.", "danger")

    return render_template("login.html")


def remove_inactive_users():
    threshold_date = datetime.utcnow() - timedelta(days=15)
    inactive_users = User.query.filter(User.last_login_date <= threshold_date).all()

    for user in inactive_users:
        db.session.delete(user)
    db.session.commit()


def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(remove_inactive_users, "interval", days=1)
    scheduler.start()


@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash(f"User {username} disconnected.", "info")
    return redirect(url_for("main"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]

        if new_password != confirm_password:
            flash("New password and confirmation do not match!", "danger")
            return redirect(url_for("change_password"))

        if len(new_password) < MIN_PASSWORD_LENGTH:
            flash(
                "The new password must be at least "
                + f"{MIN_PASSWORD_LENGTH} characters long.",
                "danger",
            )
            return redirect(url_for("change_password"))

        current_user.set_password(new_password)
        db.session.commit()

        flash("Password changed successfully!", "success")
        return redirect(url_for("main"))

    return render_template("change_password.html")


# @app.route("/input-text", methods=["GET", "POST"])
# @login_required
# def input_text():
#     if request.method == "POST":
#         if "file1" in request.files and "file2" in request.files:
#             file1 = request.files["file1"]
#             file2 = request.files["file2"]

#             try:
#                 file1_content = file1.read().decode("utf-8")
#             except UnicodeDecodeError:
#                 file1_content = file1.read().decode("ISO-8859-1")

#             try:
#                 file2_content = file2.read().decode("utf-8")
#             except UnicodeDecodeError:
#                 file2_content = file2.read().decode("ISO-8859-1")

#             return render_template(
#                 "second_page.html", content1=file1_content, content2=file2_content
#             )

#     return render_template("index.html")


@app.route("/input-text", methods=["GET", "POST"])
@login_required
def input_text():
    return render_template("second_page.html")


@app.route("/view-request/<int:request_id>")
@login_required
def view_request(request_id):
    req = Request.query.get_or_404(request_id)
    if req.user_id != current_user.id:
        abort(403)
    combined_results = json.loads(req.results)

    # Estrazione di lexical_results (non è più necessario riorganizzarli)
    organized_lexical_results = combined_results["lexical_results"]

    # Estrazione di passive_form_results
    passive_results = combined_results["passive_form_results"]

    # Estrazione di verb_conjunction_results
    verb_conjunction_results = combined_results["verb_conjunction_results"]

    # Estrazione di conjunction_sentence_results
    conjunction_sentence_results = combined_results["conjunction_sentence_results"]

    memory_data = json.loads(req.memory_data) if req.memory_data else {}
    print("Memory data:", memory_data)

    return render_template(
        "second_page.html",
        content1=req.content1,
        content2=req.content2,
        request_name=req.request_name,
        lexical_output=organized_lexical_results,
        passive_output=passive_results,
        verb_conjunction_output=verb_conjunction_results,
        conjunction_sentence_output=conjunction_sentence_results,
        memory=memory_data,
    )


@app.route("/rename-request", methods=["POST"])
@login_required
def rename_request():
    request_id = request.form["request_id"]
    new_request_name = request.form["new_request_name"]

    # Trova la richiesta nel database
    req = Request.query.get_or_404(request_id)

    # Controlla che l'utente corrente sia l'autore della richiesta
    if req.user_id != current_user.id:
        abort(403)

    # Aggiorna il nome della richiesta e salva nel database
    req.request_name = new_request_name
    db.session.commit()

    flash("Request successfully renamed!", "success")
    return redirect(url_for("main"))


def highlight_specific_instance(sentence_text, match_text, start, end):
    # Estendi l'indice di inizio all'inizio della parola
    while start > 0 and sentence_text[start - 1].isalnum():
        start -= 1

    # Estendi l'indice di fine alla fine della parola
    while end < len(sentence_text) and sentence_text[end].isalnum():
        end += 1

    # Estrai la parola completa da evidenziare
    full_match_text = sentence_text[start:end]

    before_match = sentence_text[:start]
    after_match = sentence_text[end:]
    highlighted_match = f'<span class="highlighted-word">{full_match_text}</span>'

    return before_match + highlighted_match + after_match


def lexical_analyser(doc_requisiti, content1, content2, lexical_memory):
    print("Lexical memory:", lexical_memory)
    lexical_patterns = [
        nlp.make_doc(text.strip())
        for text in content2.splitlines()
        if not text.strip().startswith("#") and text.strip() != ""
    ]

    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    matcher.add("LEXICAL_PATTERNS", lexical_patterns)
    matches = matcher(doc_requisiti)

    results = {}
    for match_id, start, end in matches:
        span = doc_requisiti[start:end]
        line_number = content1.count("\n", 0, span.start_char) + 1

        # Evidenzia l'istanza specifica della parola nel contesto
        sentence_start = span.sent.start_char
        highlighted_sentence = highlight_specific_instance(
            span.sent.text,
            span.text,
            span.start_char - sentence_start,
            span.end_char - sentence_start,
        )

        # Rimuovi i caratteri di ritorno a capo
        highlighted_sentence = highlighted_sentence.replace("\r", "")

        # Verifica se la sentence è già presente in lexical_memory e, se lo è, recupera l'etichetta
        tag = "neutral"
        if span.text in lexical_memory:
            for label, sentences in lexical_memory[span.text].items():
                if highlighted_sentence in sentences:
                    tag = label
                    break

        if span.text not in results:
            results[span.text] = []

        results[span.text].append(
            {"line": line_number, "sentence": highlighted_sentence, "tag": tag}
        )

    results = dict(sorted(results.items()))
    # print("Lexical results:", results)
    return results


def passive_form_parser(doc_requisiti, content1, passive_memory):
    verbs = [
        token
        for token in doc_requisiti
        if (
            token.pos == VERB
            and token.morph.get("VerbForm") == ["Part"]
            and any(
                child.lemma_ == "be" and child.dep_ == "auxpass"
                for child in token.children
            )
            and not any(
                child.text == "by" and child.dep_ == "agent" for child in token.children
            )
        )
    ]
    sentences = [token.sent for token in verbs]

    results = {}
    for verb, sentence in zip(verbs, sentences):
        # Evidenzia l'istanza specifica del verbo nel contesto
        sentence_start = sentence.start_char
        highlighted_sentence = highlight_specific_instance(
            sentence.text,
            verb.text,
            verb.idx - sentence_start,
            verb.idx - sentence_start + len(verb.text),
        )

        highlighted_sentence = highlighted_sentence.replace("\r", "")

        tag = "neutral"
        if str(verb) in passive_memory:
            for label, sentences in passive_memory[str(verb)].items():
                if highlighted_sentence in sentences:
                    tag = label
                    break

        # Ottieni il numero di riga
        line_number = content1.count("\n", 0, sentence.start_char) + 1

        if str(verb) not in results:
            results[str(verb)] = []

        results[str(verb)].append(
            {"line": line_number, "sentence": highlighted_sentence, "tag": tag}
        )

    results = dict(sorted(results.items()))
    # print("Passive form results:", results)
    return results


def verb_conjunction_parser(doc_requisiti, content1, verb_conjunction_memory):
    def find_matches(token):
        target_verbs = ["provide", "modified", "available", "supplied", "availability"]
        target_conjunctions = ["when", "where", "if"]
        verb = None
        conjunction = None
        if token.text.lower() in target_verbs:
            if token.head.pos_ == "VERB":
                verb = token.text
                for child in token.head.children:
                    if child.text.lower() in target_conjunctions and child.dep_ in [
                        "advmod",
                        "mark",
                    ]:
                        conjunction = child.text
            else:
                verb = token.text
                for child in token.children:
                    if child.text.lower() in target_conjunctions and child.dep_ in [
                        "advmod",
                        "mark",
                    ]:
                        conjunction = child.text
        return verb, conjunction

    results = {}

    for sent in doc_requisiti.sents:
        for token in sent:
            verb, conjunction = find_matches(token)
            if verb and conjunction:
                key = f"{conjunction} {verb}"
                sentence_start = sent.start_char
                highlighted_sentence = highlight_specific_instance(
                    sent.text,
                    verb,
                    token.idx - sentence_start,
                    token.idx - sentence_start + len(verb),
                )

                highlighted_sentence = highlighted_sentence.replace("\r", "")

                tag = "neutral"
                if key in verb_conjunction_memory:
                    for label, sentences in verb_conjunction_memory[key].items():
                        if highlighted_sentence in sentences:
                            tag = label
                            break

                line_number = content1.count("\n", 0, sent.start_char) + 1

                if key not in results:
                    results[key] = []

                results[key].append(
                    {"line": line_number, "sentence": highlighted_sentence, "tag": tag}
                )

    results = dict(sorted(results.items()))
    # print("Verb conjunction results:", results)
    return results


def conjunction_sentence_analyser(doc_requisiti, content1, conjunction_sentence_memory):
    matches = []
    for sent in doc_requisiti.sents:
        for token in sent:
            if token.text.lower() in ("or", "and/or") and token.dep_ == "cc":
                if token.head.pos_ in ("NOUN", "ADP"):
                    matches.append(
                        (token, sent)
                    )  # Capture both the token and the sentence span

    results = {}
    for match_conjunction_token, match_sentence_span in matches:
        match_conjunction = match_conjunction_token.text
        match_sentence = match_sentence_span.text

        if match_conjunction not in results:
            results[match_conjunction] = []

        # Evidenzia l'istanza specifica della congiunzione nel contesto
        sentence_start = match_sentence_span.start_char
        highlighted_sentence = highlight_specific_instance(
            match_sentence,
            match_conjunction,
            match_conjunction_token.idx - sentence_start,
            match_conjunction_token.idx - sentence_start + len(match_conjunction),
        )

        highlighted_sentence = highlighted_sentence.replace("\r", "")

        tag = "neutral"
        if match_conjunction in conjunction_sentence_memory:
            for label, sentences in conjunction_sentence_memory[
                match_conjunction
            ].items():
                if highlighted_sentence in sentences:
                    tag = label
                    break

        line_number = content1.count("\n", 0, match_sentence_span.start_char) + 1

        results[match_conjunction].append(
            {"line": line_number, "sentence": highlighted_sentence, "tag": tag}
        )

    results = dict(sorted(results.items()))
    # print("Conjunction sentence results:", results)
    return results


@app.route("/conta-parole", methods=["POST"])
def conta_parole():
    data = request.json

    if not data:
        return jsonify({"error": "Invalid JSON data"}), 400

    content1 = data.get("content1", "")  # requisiti
    content2 = data.get("content2", "")  # dizionario
    request_name = data.get("requestName", "")
    memory = data.get("memory", {})

    # Estrai i sotto-dizionari da "memory"
    lexical_memory = memory.get("lexical", {})
    passive_memory = memory.get("passive", {})
    verb_conjunction_memory = memory.get("verbConjunction", {})
    conjunction_sentence_memory = memory.get("conjunctionSentence", {})

    doc_requisiti = nlp(content1)
    lexical_results = lexical_analyser(
        doc_requisiti, content1, content2, lexical_memory
    )
    passive_results = passive_form_parser(doc_requisiti, content1, passive_memory)
    verb_conjunction_results = verb_conjunction_parser(
        doc_requisiti, content1, verb_conjunction_memory
    )
    conjunction_sentence_results = conjunction_sentence_analyser(
        doc_requisiti, content1, conjunction_sentence_memory
    )

    # Archiviazione dei dati nel database
    if current_user.is_authenticated:
        combined_results = {
            "lexical_results": lexical_results,
            "passive_form_results": passive_results,
            "verb_conjunction_results": verb_conjunction_results,
            "conjunction_sentence_results": conjunction_sentence_results,
        }
        new_request = Request(
            content1=content1,
            content2=content2,
            user_id=current_user.id,
            request_name=request_name,
            lexical_total_matches=len(lexical_results),
            passive_total_matches=len(passive_results),
            verb_conjunction_total_matches=len(verb_conjunction_results),
            conjunction_sentence_total_matches=len(conjunction_sentence_results),
            results=json.dumps(combined_results, indent=4),
            memory_data=json.dumps(memory),
        )
        db.session.add(new_request)
        db.session.commit()

    return jsonify(
        {
            "lexical_results": {
                "total_matches": len(lexical_results),
                "results": lexical_results,
            },
            "passive_form_results": {
                "total_matches": len(passive_results),
                "results": passive_results,
            },
            "verb_conjunction_results": {
                "total_matches": len(verb_conjunction_results),
                "results": verb_conjunction_results,
            },
            "conjunction_sentence_results": {
                "total_matches": len(conjunction_sentence_results),
                "results": conjunction_sentence_results,
            },
        }
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        start_scheduler()
    app.run(debug=True)
