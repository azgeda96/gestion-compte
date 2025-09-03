from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask import session
from functools import wraps
import sqlite3
import random
import string
from flask_bcrypt import Bcrypt  # <-- Ajoute cette ligne

app = Flask(__name__)
app.secret_key = '123456'  # Remplace par une clé aléatoire (ex: "123456")
bcrypt = Bcrypt(app)  # <-- Initialise bcrypt

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Tables existantes (membres, plateformes, comptes)
    c.execute('''CREATE TABLE IF NOT EXISTS membres
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS plateformes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS comptes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  membre_id INTEGER,
                  plateforme_id INTEGER,
                  user TEXT,
                  mail TEXT,
                  mdp TEXT,
                  FOREIGN KEY(membre_id) REFERENCES membres(id),
                  FOREIGN KEY(plateforme_id) REFERENCES plateformes(id))''')

    # Ajoute des plateformes par défaut si la table est vide
    c.execute("SELECT COUNT(*) FROM plateformes")
    if c.fetchone()[0] == 0:
        plateformes = ["Alldebrid", "Stremio", "Outlook", "Netflix", "Amazon", "Disney+", "Spotify", "Google", "Autre"]
        for p in plateformes:
            c.execute("INSERT INTO plateformes (nom) VALUES (?)", (p,))

    # Nouveaux tables pour le système de connexion
    c.execute('''CREATE TABLE IF NOT EXISTS utilisateurs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT NOT NULL,
                login TEXT UNIQUE NOT NULL,
                mot_de_passe TEXT NOT NULL,
                est_admin INTEGER DEFAULT 0
            )''')
    c.execute('''CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utilisateur_id INTEGER NOT NULL,
                membre_id INTEGER NOT NULL,
                FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id),
                FOREIGN KEY (membre_id) REFERENCES membres(id),
                UNIQUE(utilisateur_id, membre_id)
            )''')

    # Ajoute l'utilisateur admin UNIQUEMENT s'il n'existe pas déjà
    c.execute("SELECT 1 FROM utilisateurs WHERE login='admin'")
    if not c.fetchone():
        hashed_password = bcrypt.generate_password_hash("admin123").decode('utf-8')
        c.execute("INSERT INTO utilisateurs (nom, login, mot_de_passe, est_admin) VALUES (?, ?, ?, ?)",
                  ('Administrateur', 'admin', hashed_password, 1))

    conn.commit()
    conn.close()  # <-- Déplacé à la fin

# Route temporaire pour initialiser la base (à supprimer après utilisation)
#@app.route('/init_db')
#def init_db_route():
#    init_db()
#    return "Base de données initialisée !"

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_admin', False):
            return redirect(url_for('dashboard'))  # Redirige vers le dashboard si pas admin
        return f(*args, **kwargs)
    return decorated_function



def generer_mot_de_passe(longueur=12):
    caracteres = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(caracteres) for _ in range(longueur))


#####  Liste de toutes les routes  #####

# Route temporaire pour initialiser la base (à supprimer après utilisation)
#@app.route('/init_db')
#def init_db_route():
#    init_db()
#    return "Base de données initialisée !"

# Route pour vérifier les tables (optionnelle)
@app.route('/test_db')
def test_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = c.fetchall()
    c.execute("SELECT * FROM utilisateurs;")
    users = c.fetchall()
    conn.close()
    return f"Tables: {tables}<br>Utilisateurs: {users}"

@app.route("/generer_mot_de_passe")
@login_required
def generer_mot_de_passe_route():
    return jsonify({"mdp": generer_mot_de_passe()})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login = request.form["login"]
        password = request.form["password"]
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT id, nom, mot_de_passe, est_admin FROM utilisateurs WHERE login=?", (login,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['user_nom'] = user[1]
            session['user_admin'] = bool(user[3])
            return redirect(url_for('dashboard'))
        else:
            return render_template("login.html", error="Login ou mot de passe incorrect")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/")
@login_required
def dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM membres")
    membres = c.fetchall()
    conn.close()
    return render_template("dashboard.html", membres=membres)

@app.route("/membre/<int:membre_id>")
@login_required
def membre(membre_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT nom FROM membres WHERE id=?", (membre_id,))
    nom = c.fetchone()[0]
    c.execute('''SELECT comptes.id, comptes.plateforme_id, plateformes.nom, comptes.user, comptes.mail, comptes.mdp
                 FROM comptes
                 JOIN plateformes ON comptes.plateforme_id = plateformes.id
                 WHERE comptes.membre_id=?''', (membre_id,))
    comptes = c.fetchall()
    c.execute("SELECT * FROM plateformes")  
    plateformes = c.fetchall()  
    conn.close()
    return render_template("membre.html", nom=nom, comptes=comptes, membre_id=membre_id, plateformes=plateformes)

@app.route("/ajouter_membre", methods=["GET", "POST"])
@login_required
def ajouter_membre():
    if request.method == "POST":
        nom = request.form["nom"]
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO membres (nom) VALUES (?)", (nom,))
        conn.commit()
        conn.close()
        return jsonify({"success": True})  # Réponse JSON pour la requête fetch
    return render_template("ajouter_membre.html")  # (Garde cette ligne pour la compatibilité)

@app.route("/ajouter_compte/<int:membre_id>", methods=["POST"])
@login_required
def ajouter_compte(membre_id):
    plateforme_id = request.form["plateforme_id"]
    user = request.form["user"]
    mail = request.form["mail"]
    mdp = request.form["mdp"]
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO comptes (membre_id, plateforme_id, user, mail, mdp) VALUES (?, ?, ?, ?, ?)",
              (membre_id, plateforme_id, user, mail, mdp))
    conn.commit()
    conn.close()
    return jsonify({"success": True})



@app.route("/modifier_compte/<int:compte_id>", methods=["POST"])
@login_required
def modifier_compte(compte_id):
    plateforme_id = request.form["plateforme_id"]
    user = request.form["user"]
    mail = request.form["mail"]
    mdp = request.form["mdp"]
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE comptes SET plateforme_id=?, user=?, mail=?, mdp=? WHERE id=?",
              (plateforme_id, user, mail, mdp, compte_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})



@app.route("/supprimer_compte/<int:compte_id>/<int:membre_id>")
@login_required
def supprimer_compte(compte_id, membre_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM comptes WHERE id=?", (compte_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("membre", membre_id=membre_id))

@app.route("/parametres")
@login_required
def parametres():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM plateformes")
    plateformes = c.fetchall()

    utilisateurs = []
    is_admin = session.get('user_admin', False)
    if is_admin:  # Seuls les admins voient la liste des utilisateurs
        c.execute("SELECT * FROM utilisateurs")
        utilisateurs = c.fetchall()

    conn.close()
    return render_template("parametres.html", plateformes=plateformes, utilisateurs=utilisateurs)


# Ajouter un utilisateur (admin seulement)
@app.route("/ajouter_utilisateur", methods=["POST"])
@login_required
@admin_required
def ajouter_utilisateur():
    nom = request.form["nom"]
    login = request.form["login"]
    password = request.form["password"]
    est_admin = 1 if request.form.get("est_admin") else 0
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO utilisateurs (nom, login, mot_de_passe, est_admin) VALUES (?, ?, ?, ?)",
              (nom, login, hashed_password, est_admin))
    conn.commit()
    conn.close()
    return redirect(url_for('parametres', onglet-'utilisateurs'))

# Supprimer un utilisateur (admin seulement)
@app.route("/supprimer_utilisateur/<int:utilisateur_id>")
@login_required
@admin_required
def supprimer_utilisateur(utilisateur_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM utilisateurs WHERE id=?", (utilisateur_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('parametres'))

# Modifier un utilisateur (admin seulement)
@app.route("/modifier_utilisateur/<int:utilisateur_id>")
@login_required
@admin_required
def modifier_utilisateur(utilisateur_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM utilisateurs WHERE id=?", (utilisateur_id,))
    utilisateur = c.fetchone()
    conn.close()
    return render_template("modifier_utilisateur.html", utilisateur=utilisateur)

# Gérer les permissions (admin seulement)
@app.route("/gerer_permissions/<int:utilisateur_id>")
@login_required
@admin_required
def gerer_permissions(utilisateur_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT nom FROM utilisateurs WHERE id=?", (utilisateur_id,))
    user_nom = c.fetchone()[0]
    c.execute("SELECT * FROM membres")
    membres = c.fetchall()
    c.execute("SELECT membre_id FROM permissions WHERE utilisateur_id=?", (utilisateur_id,))
    permissions = [p[0] for p in c.fetchall()]
    conn.close()
    return render_template("permissions.html", utilisateur_id=utilisateur_id, user_nom=user_nom, membres=membres, permissions=permissions)

# Ajouter une plateforme (visible par tous)
@app.route("/ajouter_plateforme", methods=["POST"])
@login_required
def ajouter_plateforme():
    nom = request.form["nom"]
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO plateformes (nom) VALUES (?)", (nom,))
    conn.commit()
    conn.close()
    return redirect(url_for('parametres'))

# Modifier une plateforme (visible par tous)
@app.route("/modifier_plateforme/<int:plateforme_id>", methods=["POST"])
@login_required
def modifier_plateforme(plateforme_id):
    nom = request.form["nom"]
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE plateformes SET nom=? WHERE id=?", (nom, plateforme_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

# Supprimer une plateforme (admin seulement)
@app.route("/supprimer_plateforme/<int:plateforme_id>")
@login_required
@admin_required  # <-- Seuls les admins peuvent supprimer
def supprimer_plateforme(plateforme_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM plateformes WHERE id=?", (plateforme_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('parametres'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
