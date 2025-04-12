from flask import Flask,request,render_template,redirect,url_for,flash,session
import mysql.connector
from flask_session import Session

app=Flask(__name__)
app.config['SESSION_TYPE']='filesystem'

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
                return redirect(url_for('adminpannel'))
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

@app.route('/adminpannel')
def adminpannel():
    cursor = mytdb.cursor()
    cursor.execute("SELECT name FROM navbar_items")
    navbar_items = [row[0] for row in cursor.fetchall()]

    cursor.execute("SELECT name FROM sidebar_items")
    sidebar_items = [row[0] for row in cursor.fetchall()]
    
    return render_template('adminpannel.html', navbar_items=navbar_items, sidebar_items=sidebar_items)


@app.route('/add_navbar_item', methods=['POST'])
def add_navbar_item():
    name = request.form['name']
    if name:
        cursor = mytdb.cursor()
        cursor.execute("INSERT INTO navbar_items (name) VALUES (%s)", (name,))
        mytdb.commit()
        flash('Navbar item added successfully')
    return redirect(url_for('adminpannel'))

@app.route('/add_sidebar_item', methods=['GET','POST'])
def add_sidebar_item():
    name = request.form.get('name')
    if name:
        cursor = mytdb.cursor()
        cursor.execute("INSERT INTO sidebar_items (name) VALUES (%s)", (name,))
        mytdb.commit()
        flash('Sidebar item added successfully')
    return redirect(url_for('adminpannel'))

app.run(use_reloader=True,debug=True)