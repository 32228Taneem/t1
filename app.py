from flask import Flask,request,render_template,redirect,url_for,flash,session
import mysql.connector
from flask_session import Session

app=Flask(__name__)
app.config['SESSION_TYPE']='filesystem'

navbar_items = ['Python', 'HTML']
subtopic_db = {}
# {
#     'Python': ['Intro', 'Variables'],
#     'HTML': ['Tags', 'Forms']
# }

mytdb=mysql.connector.connect(host='localhost',user='root',password='Taneem_2002',db='sharetech')
Session(app)

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        aname=request.form['adminName']
        email=request.form['email']
        pwd=request.form['password']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(admin_email) from admins where  admin_email=%s',[email])
        bdata=cursor.fetchone()
        if bdata[0]==1:
            cursor.execute('select password from admins where admin_email=%s',[email])
            bpassword=cursor.fetchone()
            cursor.execute('select admin_name from admins where admin_name=%s',[aname])
            bname=cursor.fetchone()
            if pwd==bpassword[0].decode('utf-8') :
                print(session)
                session['user']=aname
                print(session)
                # return 'hiii'
                return redirect(url_for('admin_panel'))
            else:
                flash('wrong password')
                # return ' wrong password'
                return redirect(url_for('login'))
        elif bdata[0]==0:
            flash('email does not exists contact admin')
            return redirect(url_for('home'))
        else:
            return 'something went wrong'

    return render_template('login.html')

@app.route('/admin_panel')
def admin_panel():
    return render_template('admin_panel.html', navbar_items=navbar_items)

@app.route('/add_navbar_item', methods=['POST'])
def add_navbar_item():
    item = request.form['item']
    if item and item not in navbar_items:
        navbar_items.append(item)
        subtopic_db[item] = []
    return redirect(url_for('admin_panel'))

@app.route('/view_content/<item_name>')
def view_content(item_name):
    subtopics = subtopic_db.get(item_name, [])
    return render_template('view_content.html', item_name=item_name, subtopics=subtopics)

@app.route('/add_subtopic/<item_name>', methods=['POST'])
def add_subtopic(item_name):
    title = request.form['name']
    content = request.form.get('content')

    if item_name not in subtopic_db:
        subtopic_db[item_name] = []

    subtopic_db[item_name].append({'title': title, 'content': content})
    return redirect(url_for('add_subtopic.html', item_name=item_name))

# @app.route('/add_subtopic_form/<item_name>')
# def add_subtopic_form(item_name):
#     return render_template('add_subtopic.html', item_name=item_name)


@app.route('/logout')
def logout():
    session.clear()  # Clears all session data (if you're using login sessions)
    return redirect(url_for('login'))  # Redirects to login page (or any page you prefer)

app.run(use_reloader=True,debug=True)