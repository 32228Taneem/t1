from flask import Flask, request, render_template, redirect, url_for, flash, session
import mysql.connector
from flask_session import Session
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'your_secret_key'  # Required for session and flash
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
Session(app)

# MySQL Configuration
mytdb = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Taneem_2002',
    database='sharetech'
)
cursor = mytdb.cursor(buffered=True)

@app.route('/')
def home():
    return render_template('welcome.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('user'):
        if request.method == 'POST':
            aname = request.form['adminName']
            email = request.form['email']
            pwd = request.form['password']

            cursor.execute('SELECT count(admin_email) FROM admins WHERE admin_email=%s', [email])
            bdata = cursor.fetchone()

            if bdata[0] == 1:
                cursor.execute('SELECT password FROM admins WHERE admin_email=%s', [email])
                bpassword = cursor.fetchone()
                cursor.execute('SELECT admin_name FROM admins WHERE admin_name=%s', [aname])
                bname = cursor.fetchone()

                if pwd == bpassword[0].decode('utf-8'):
                    session['user'] = aname
                    return redirect(url_for('admin_panel'))
                else:
                    flash('Wrong password')
                    return redirect(url_for('login'))
            else:
                flash('Email does not exist. Contact admin.')
                return redirect(url_for('home'))

        return render_template('login.html')
    else:
        return redirect(url_for('admin_panel'))

@app.route('/admin_panel')
def admin_panel():
    cursor.execute('SELECT name FROM navbar_items')
    nav_items = [item[0] for item in cursor.fetchall()]
    return render_template('admin_panel.html', navbar_items=nav_items)

@app.route('/add_navbar_item', methods=['POST'])
def add_navbar_item():
    item = request.form['item']
    if item:
        try:
            cursor.execute('INSERT INTO navbar_items (name) VALUES (%s)', (item,))
            mytdb.commit()
        except mysql.connector.IntegrityError:
            flash('Item already exists.')
    return redirect(url_for('admin_panel'))

@app.route('/view_content/<item_name>')
def view_content(item_name):
    cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
    nav_id = cursor.fetchone()
    if not nav_id:
        return 'Navbar item not found'

    cursor.execute('SELECT id, title, content, image_filename FROM subtopics WHERE navbar_id=%s', (nav_id[0],))
    subtopics = [
        {
            'id': row[0],
            'title': row[1],
            'content': row[2],
            'image': url_for('static', filename=f'uploads/{row[3]}') if row[3] else None
        } for row in cursor.fetchall()
    ]
    return render_template('view_content.html', item_name=item_name, subtopics=subtopics)


@app.route('/add_subtopic/<item_name>', methods=['POST'])
def add_subtopic(item_name):
    title = request.form['title']
    content = request.form.get('content')

    cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
    nav_id = cursor.fetchone()
    if nav_id:
        cursor.execute('INSERT INTO subtopics (title, content, navbar_id) VALUES (%s, %s, %s)', (title, content, nav_id[0]))
        mytdb.commit()
    return redirect(url_for('view_content', item_name=item_name))

@app.route('/edit_subtopic/<int:sub_id>', methods=['GET', 'POST'])
def edit_subtopic(sub_id):
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        cursor.execute('UPDATE subtopics SET title=%s, content=%s WHERE id=%s', (title, content, sub_id))
        mytdb.commit()
        # Get the item_name for redirecting
        cursor.execute('SELECT navbar_id FROM subtopics WHERE id=%s', (sub_id,))
        nav_id = cursor.fetchone()[0]
        cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (nav_id,))
        item_name = cursor.fetchone()[0]
        return redirect(url_for('view_content', item_name=item_name))
    else:
        cursor.execute('SELECT title, content, navbar_id FROM subtopics WHERE id=%s', (sub_id,))
        sub = cursor.fetchone()
        cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (sub[2],))
        item_name = cursor.fetchone()[0]
        return render_template('edit_subtopic.html', sub_id=sub_id, title=sub[0], content=sub[1], item_name=item_name)

@app.route('/delete_navbar_item', methods=['POST'])
def delete_navbar_item():
    item = request.form['item']
    cursor.execute('DELETE FROM navbar_items WHERE name=%s', (item,))
    mytdb.commit()
    return redirect(url_for('admin_panel'))

@app.route('/update_navbar_item', methods=['POST'])
def update_navbar_item():
    old_item = request.form['old_item']
    new_item = request.form['new_item']
    cursor.execute('UPDATE navbar_items SET name=%s WHERE name=%s', (new_item, old_item))
    mytdb.commit()
    return redirect(url_for('admin_panel'))


@app.route('/delete_subtopic/<int:sub_id>/<item_name>')
def delete_subtopic(sub_id, item_name):
    cursor.execute('DELETE FROM subtopics WHERE id=%s', (sub_id,))
    mytdb.commit()
    return redirect(url_for('view_content', item_name=item_name))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

app.run(use_reloader=True, debug=True)