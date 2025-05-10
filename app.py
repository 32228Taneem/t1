from flask import Flask,render_template,url_for,redirect,request,flash,session,jsonify,send_from_directory,json
from otp import genotp
from cmail import sendmail
from tokens import encode,decode
from flask_wtf.csrf import CSRFProtect
import mysql.connector
from flask_session import Session
from werkzeug.utils import secure_filename
import os
import re

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = 'tech$tan111'  # Required for session and flash
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['WTF_CSRF_ENABLED'] = True  # Should be True in production
Session(app)
csrf = CSRFProtect(app)

# MySQL Configuration
mytdb = mysql.connector.connect(
    host='localhost',
    user='root',
    password='Taneem_2002',
    database='sharetech'
)
cursor = mytdb.cursor(buffered=True)

# ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp'}
# app.config['UPLOAD_FOLDER'] = 'static/uploads'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    # cursor = db.cursor()
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')  # Fetch navbar items
    navbar_items = cursor.fetchall()  # Retrieve all navbar items
    return render_template('welcome.html', navbar_items=navbar_items)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not (file and allowed_file(file.filename)):
            return jsonify({'error': 'Allowed file types: png, jpg, jpeg, gif'}), 400

        # Secure filename and handle duplicates
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Handle duplicate files
        counter = 1
        while os.path.exists(upload_path):
            filename = f"{base}_{counter}{ext}"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            counter += 1

        file.save(upload_path)
        return jsonify({
            'location': url_for('uploaded_file', filename=filename, _external=True)
        })

    except Exception as e:
        app.logger.error(f"Upload failed: {str(e)}")
        return jsonify({'error': 'Server error during upload'}), 500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# user ku side panel key sub topics display karnay & o page may nav elements display karnay
@app.route('/view_subtopics/<item_name>')
def view_subtopics(item_name):
    # Fetch navbar items
    cursor.execute('SELECT id, name FROM navbar_items ORDER BY position ASC')
    navbar_items = cursor.fetchall()
    # Fetch navbar item ID
    cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
    nav_id = cursor.fetchone()
    if not nav_id:
        return 'Navbar item not found'
    
    # Fetch subtopics with their sub-subtopics
    cursor.execute('''SELECT id, title, content, image_filename FROM subtopics WHERE navbar_id=%s ORDER BY position''', (nav_id[0],))
    subtopics = []
    for row in cursor.fetchall():
        # Get sub-subtopics for each subtopic
        cursor.execute('''
            SELECT id, title, content 
            FROM sub_subtopics 
            WHERE subtopic_id=%s 
            ORDER BY position
        ''', (row[0],))
        
        sub_subtopics = [
            {
                'id': sub_row[0],
                'title': sub_row[1],
                'content': sub_row[2]
            } for sub_row in cursor.fetchall()
        ]
        
        subtopics.append({
            'id': row[0],
            'title': row[1],
            'content': row[2],
            'image': url_for('static', filename=f'uploads/{row[3]}') if row[3] else None,
            'sub_subtopics': sub_subtopics  # Add sub-subtopics to each subtopic
        })
    
    return render_template(
        'view_subtopics.html',
        item_name=item_name,
        subtopics=subtopics,
        navbar_items=navbar_items
    )

@app.route('/usercreate',methods=['GET','POST'])
def usercreate():
    if request.method=='POST':
        uname=request.form['name']
        uemail=request.form['email']
        uaddress=request.form['address']
        upassword=request.form['password']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(user_email) from usercreate where user_email=%s',[uemail])
        uemail_count=cursor.fetchone()
        if uemail_count[0]==0:
            uotp=genotp()
            userdata={'uname':uname,'uemail':uemail,'upassword':upassword,'uotp':uotp}
            subject='TQ for registering in taneemkart'
            body=f'Ecommers verification otp for user regrestation {uotp}'
            sendmail(to=uemail,subject=subject,body=body)
            flash('OTP has sent to given mail')
            return redirect(url_for('uotp',pudata=encode(data=userdata)))
        elif uemail_count[0]==1:
            flash('email already exist please login')
            return redirect(url_for('userlogin'))
    return render_template('usersignup.html')

@app.route('/uotp/<pudata>',methods=['GET','POST'])
def uotp(pudata):
    if request.method=='POST':
        fuotp=request.form['otp']
        try:
            d_udata=decode(data=pudata)
        except Exception as e:
            print(e)
            flash('something went wrong')
            return redirect(url_for('usercreate'))
        else:
            if fuotp==d_udata['uotp']:
                cursor=mytdb.cursor(buffered=True)
                cursor.execute('insert into usercreate( user_email,username,password) values(%s,%s,%s)',[d_udata['uemail'],d_udata['uname'],d_udata['upassword']])
                mytdb.commit()
                cursor.close()
                flash('reg success')
                return redirect(url_for('userlogin'))
            else:
                flash('otp is wrong')
                return redirect(url_for('usercreate'))
    return render_template('userotp.html')

@app.route('/userlogin',methods=['GET','POST'])
def userlogin():
    if not session.get('user'):
        if request.method=='POST':
                log_uemail=request.form['email']
                log_upassword=request.form['password']
                try:
                    cursor=mytdb.cursor(buffered=True)
                    cursor.execute('select count(user_email) from usercreate where user_email=%s',[log_uemail])
                    stored_emailcount=cursor.fetchone()
                except Exception as e:
                    print(e)
                    flash('something went wrong connection error')
                    return redirect(url_for('userlogin'))
                else:
                    if stored_emailcount[0]==1:
                        cursor.execute('select password from usercreate where user_email=%s',[log_uemail])
                        stored_password=cursor.fetchone()
                        print(stored_password)
                        if log_upassword==stored_password[0].decode('utf-8'):
                            print(session)
                            session['user']=log_uemail
                            if not session.get(log_uemail):
                                session[log_uemail]={}
                            print(session)
                            return redirect(url_for('index')) # ya asal readreview page aanaaa
                        else:
                            flash('wrong pass')
                            return redirect(url_for('userlogin'))
                    else:
                        flash('wrong email')
                        return redirect(url_for('userlogin'))
        return render_template('userlogin.html')
    else:
        return redirect(url_for('index'))
    
@app.route('/userforgot',methods=['GET','POST'])
def userforgot():
    if request.method=='POST':
        forgot_useremail=request.form['uemail']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(user_email) from usercreate where user_email=%s',[forgot_useremail])
        stored_email=cursor.fetchone()
        if stored_email[0]==1:
            subject='reset link for user'
            body=f"click on the link to update ur password:{url_for('user_password_update',token=encode(data=forgot_useremail),_external=True)}" # _external=true likhay nai tho o data pura text kay naad jata
            sendmail(to=forgot_useremail,subject=subject,body=body)
            flash(f'reset link has sent to given mail {forgot_useremail}')
            return redirect(url_for('userforgot'))
        elif stored_email[0]==0:
            flash('no email regestered please check')
            return redirect(url_for('userlogin'))
    return render_template('userforfot.html')

@app.route('/user_password_update/<token>',methods=['GET','POST'])
def user_password_update(token):
    if request.method=='POST':
        try:
            npassword=request.form['npassword']
            cpassword=request.form['cpassword']
            dtoken=decode(data=token) #detoken the encrpt email
        except Exception as e:
            print(e)
            flash('something went wrong')
            return redirect(url_for('userlogin'))
        else:
            if npassword==cpassword:
                cursor=mytdb.cursor(buffered=True)
                cursor.execute('update usercreate set password=%s where user_email=%s',[npassword,dtoken])
                mytdb.commit()
                flash('password updated succesfully')
                return redirect(url_for('userlogin'))
            else:
                flash('password mismaitches')
                return redirect(url_for('ad_password_update',token=token))
    return render_template('newuserpassword.html')

@app.route('/userlogout')
def userlogout():
    if session.get('user'):
        session.pop('user')
        return redirect(url_for('index'))
    return redirect(url_for('userlogin'))


@app.route('/admincreate',methods=['GET','POST'])
def admincreate():
    if request.method=='POST':
        #print(request.form) form ka data kaisa aata hey kako dekhnay aisa likhtey
        aname=request.form['username']
        aemail=request.form['email']
        password=request.form['password']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(admin_email) from admins where admin_email=%s',[aemail])
        email_count=cursor.fetchone()
        if email_count[0]==0:
            otp=genotp()
            admindata={'aname':aname,'aemail':aemail,'password':password,'aotp':otp}
            subject='TQ for registering in this website'
            body=f'admin verification otp for admin regrestation {otp}'
            sendmail(to=aemail,subject=subject,body=body)
            flash('OTP has sent to given mail')
            return redirect(url_for('otp',padata=encode(data=admindata)))
        elif email_count[0]==1:
            flash('email already exist please login')
            return redirect(url_for('login'))
    return render_template('admincreate.html')

@app.route('/otp/<padata>',methods=['GET','POST'])
def otp(padata):
    if request.method=='POST':
        fotp=request.form['otp']
        try:
            d_data=decode(data=padata)
        except Exception as e:
            print(e)
            flash('something went wrong')
            return redirect(url_for('admincreate'))
        else:
            if fotp==d_data['aotp']:
                cursor=mytdb.cursor(buffered=True)
                cursor.execute('insert into admins(admin_email, admin_name,password) values(%s,%s,%s)',[d_data['aemail'],d_data['aname'],d_data['password']])
                mytdb.commit()
                cursor.close()
                flash('reg success')
                return redirect(url_for('login'))
            else:
                flash('otp is wrong')
                return redirect(url_for('admincreate'))
    return render_template('adminotp.html')

@app.route('/adminforgot',methods=['GET','POST'])
def adminforgot():
    if request.method=='POST':
        forgot_email=request.form['email']
        cursor=mytdb.cursor(buffered=True)
        cursor.execute('select count(email) from admincreate where email=%s',[forgot_email])
        stored_email=cursor.fetchone()
        if stored_email[0]==1:
            subject='reset link for admin '
            body=f"click on the link to update ur password:{url_for('ad_password_update',token=encode(data=forgot_email),_external=True)}" # _external=true likhay nai tho o data pura text kay naad jata
            sendmail(to=forgot_email,subject=subject,body=body)
            flash(f'reset link has sent to given mail {forgot_email}')
            return redirect(url_for('adminforgot'))
        elif stored_email[0]==0:
            flash('no email regestered please check')
            return redirect(url_for('login'))
    return render_template('forgot.html')

@app.route('/ad_password_update/<token>',methods=['GET','POST'])
def ad_password_update(token):
    if request.method=='POST':
        try:
            npassword=request.form['npassword']
            cpassword=request.form['cpassword']
            dtoken=decode(data=token) #detoken the encrpt email
        except Exception as e:
            print(e)
            flash('something went wrong')
            return redirect(url_for('login'))
        else:
            if npassword==cpassword:
                cursor=mytdb.cursor(buffered=True)
                cursor.execute('update admincreate set password=%s where email=%s',[npassword,dtoken])
                mytdb.commit()
                flash('password updated succesfully')
                return redirect(url_for('login'))
            else:
                flash('password mismaitches')
                return redirect(url_for('ad_password_update',token=token))
    return render_template('newpassword.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('Admin_mail'):
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
                    session['Admin_mail'] = email
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
    cursor.execute('SELECT name FROM navbar_items ORDER BY position')
    nav_items = [item[0] for item in cursor.fetchall()]
    return render_template('admin_panel.html', navbar_items=nav_items)


@app.route('/add_navbar_item', methods=['POST'])
def add_navbar_item():
    if session.get('Admin_mail'):
        item = request.form['item']
        # adminName=session['user']
        cursor.execute('select admin_id from admins where admin_email=%s',(session['Admin_mail'],))
        adminId=cursor.fetchone()[0]
        session['Admin_id']=adminId
        print(adminId)
        print(session['Admin_mail'])
        print(session['Admin_id'])
        if item:
            try:
                # Get the current maximum position from the navbar_items table
                cursor.execute('SELECT MAX(position) FROM navbar_items')
                max_position = cursor.fetchone()[0]
                
                # If no items exist, start from position 1
                new_position = max_position + 1 if max_position is not None else 1
                
                # Insert the new item into the navbar_items table with the assigned position
                cursor.execute('INSERT INTO navbar_items (name, position,admin_id,created_at) VALUES (%s,%s, %s,CURRENT_TIMESTAMP)', (item, new_position,session['Admin_id']))
                mytdb.commit()
            except mysql.connector.IntegrityError:
                flash('Item already exists.')
        
        return redirect(url_for('admin_panel'))
    else:
        return redirect(url_for('login'))


@app.route('/view_content/<item_name>')
def view_content(item_name):
    try:
        # 1. Get the navbar item ID
        cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
        nav_id = cursor.fetchone()
        if not nav_id:
            return 'Navbar item not found', 404

        # 2. Get all subtopics for this navbar item
        cursor.execute('''
            SELECT id, title, content, image_filename 
            FROM subtopics 
            WHERE navbar_id=%s 
            ORDER BY position
        ''', (nav_id[0],))
        
        subtopics = []
        for subtopic_row in cursor.fetchall():
            # 3. Get ALL sub-subtopics for this subtopic
            cursor.execute('''
                SELECT id, title, content
                FROM sub_subtopics
                WHERE subtopic_id=%s
                ORDER BY id
            ''', (subtopic_row[0],))
            
            subsubtopics = []
            for subsub_row in cursor.fetchall():
                subsubtopics.append({
                    'id': subsub_row[0],
                    'title': subsub_row[1],
                    'content': subsub_row[2]
                })
            
            # 4. Add to subtopics list WITH subsubtopics
            subtopics.append({
                'id': subtopic_row[0],
                'title': subtopic_row[1],
                'content': subtopic_row[2],
                'image': url_for('static', filename=f'uploads/{subtopic_row[3]}') if subtopic_row[3] else None,
                'sub_subtopics': subsubtopics,  # This makes the down arrow appear
                'has_subsub': len(subsubtopics) > 0  # Alternative approach
            })
        
        return render_template('view_content.html', 
                            item_name=item_name, 
                            subtopics=subtopics)
    
    except Exception as e:
        return str(e), 500


@app.route('/add_subtopic/<item_name>', methods=['POST'])
def add_subtopic(item_name):
    if session.get('Admin_mail'):
        title = request.form['title']
        content = request.form.get('content')

        cursor.execute('SELECT id FROM navbar_items WHERE name=%s', (item_name,))
        nav_id = cursor.fetchone()
        cursor.execute('select admin_id from admins where admin_email=%s',(session['Admin_mail'],))
        adminId=cursor.fetchone()[0]
        session['Admin_id']=adminId
        if nav_id:
            cursor.execute('INSERT INTO subtopics (title, content, navbar_id,admin_id) VALUES (%s,%s, %s, %s)', (title, content, nav_id[0],session['Admin_id']))
            mytdb.commit()
        return redirect(url_for('view_content', item_name=item_name))
    else:
        return redirect(url_for('login'))

@app.route('/edit_subtopic/<int:sub_id>', methods=['GET', 'POST'])
def edit_subtopic(sub_id):
    if session.get('Admin_mail'):
        if request.method == 'POST':
            title = request.form['title']
            content = request.form['content']
            cursor.execute('UPDATE subtopics SET title=%s, admin_id=%s, content=%s WHERE id=%s', (title, session['Admin_id'], content, sub_id))
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
    else:
        return redirect(url_for('login'))

@app.route('/delete_navbar_item', methods=['POST'])
def delete_navbar_item():
    if session.get('Admin_mail'):
        item = request.form['item']
        cursor.execute('DELETE FROM navbar_items WHERE name=%s', (item,))
        mytdb.commit()
        return redirect(url_for('admin_panel'))
    else:
        return redirect(url_for('login'))

@app.route('/delete_subtopic/<int:sub_id>/<item_name>')
def delete_subtopic(sub_id, item_name):
    if session.get('Admin_mail'):
        cursor.execute('DELETE FROM subtopics WHERE id=%s', (sub_id,))
        mytdb.commit()
        return redirect(url_for('view_content', item_name=item_name))
    else:
        return redirect(url_for('login'))


@app.route('/update_navbar_item', methods=['POST'])
def update_navbar_item():
    if session.get('Admin_mail'):
        old_item = request.form['old_item']
        new_item = request.form['new_item']
        cursor.execute('UPDATE navbar_items SET name=%s,admin_id=%s, WHERE name=%s', (new_item,session['Admin_id'], old_item))
        mytdb.commit()
        return redirect(url_for('admin_panel'))
    return redirect(url_for('login'))

@app.route('/update_navbar_order', methods=['POST'])
def update_navbar_order():
    if session.get('Admin_mail'):
        order = request.json.get('order')
        if not order:
            return {'status': 'No order provided'}, 400

        for position, item_name in enumerate(order, start=1):
            cursor.execute('UPDATE navbar_items SET position=%s,admin_id=%s, WHERE name=%s', (position,session['Admin_id'], item_name))

        mytdb.commit()
        return {'status': 'success'}
    return redirect(url_for('login'))

@app.route('/update_subtopic_order', methods=['POST'])
def update_subtopic_order():
    if session.get('Admin_mail'):
        order = request.json.get('order')
        print(f"Received order: {order}")  # Log the order
        if not order:
            return {'status': 'No order provided'}, 400
        try:
            for position, sub_id in enumerate(order, start=1):
                print(f"Updating subtopic {sub_id} to position {position}")  # Log each update
                cursor.execute('UPDATE subtopics SET position=%s,admin_id=%s WHERE id=%s', (position,session['Admin_id'], sub_id))
            mytdb.commit()
            return {'status': 'success', 'message': 'Order updated successfully'}
        except Exception as e:
            mytdb.rollback()
            print(f"Error: {e}")
            return {'status': 'error', 'message': str(e)}, 500
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    if session.get('Admin_mail'):
        session.clear()
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

# sub-sub-topics key routes ya c
@app.route('/get_sub_subtopics/<int:subtopic_id>')
def get_sub_subtopics(subtopic_id):
    try:
        cursor.execute('''
            SELECT id, title, content 
            FROM sub_subtopics 
            WHERE subtopic_id=%s
            ORDER BY id
        ''', (subtopic_id,))
        
        subsubtopics = []
        for row in cursor.fetchall():
            subsubtopics.append({
                'id': row[0],
                'title': row[1],
                'content': row[2]
            })
        
        return jsonify(subsubtopics)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/add_sub_subtopic', methods=['POST'])
def add_sub_subtopic():
    if session.get('Admin_mail'):
        try:
            subtopic_id = request.form.get('parent_subtopic_id')
            title = request.form.get('title')
            content = request.form.get('content', '')
            
            if not subtopic_id or not title:
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400
                
            cursor.execute('''
                INSERT INTO sub_subtopics (subtopic_id, title, content,admin_id)
                VALUES (%s, %s, %s,%s)
            ''', (subtopic_id, title, content,session['Admin_id']))
            mytdb.commit()
            
            # Get the newly created sub-subtopic
            cursor.execute('SELECT id, title, content FROM sub_subtopics WHERE id = LAST_INSERT_ID()')
            new_subsub = cursor.fetchone()
            
            return jsonify({
                'success': True,
                'newSubSubtopic': {
                    'id': new_subsub[0],
                    'title': new_subsub[1],
                    'content': new_subsub[2]
                }
            })
        except Exception as e:
            mytdb.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return redirect(url_for('login'))
    
@app.route('/update_subsubtopic_order', methods=['POST'])
def update_subsubtopic_order():
    if session.get('Admin_mail'):
        order = request.json.get('order')
        parent_id = request.json.get('parent_id')
        print(f"Received order: {order} for parent {parent_id}")  # Log the order
        
        if not order or not parent_id:
            return {'status': 'No order or parent_id provided'}, 400
        
        try:
            for position, subsub_id in enumerate(order, start=1):
                print(f"Updating subsubtopic {subsub_id} to position {position}")  # Log each update
                cursor.execute('''
                    UPDATE sub_subtopics 
                    SET position=%s 
                    WHERE id=%s AND subtopic_id=%s
                ''', (position, subsub_id, parent_id))
            
            mytdb.commit()
            return {'status': 'success', 'message': 'Sub-subtopic order updated successfully'}
        
        except Exception as e:
            mytdb.rollback()
            print(f"Error: {e}")  # Log the error
            return {'status': 'error', 'message': str(e)}, 500
    else:
        return redirect(url_for('login'))
    
@app.route('/delete_sub_subtopic/<int:subsub_id>', methods=['DELETE'])
def delete_sub_subtopic(subsub_id):
    if session.get('Admin_mail'):
        try:
            # Get redirect info first
            cursor.execute('''
                SELECT ni.name 
                FROM sub_subtopics ss
                JOIN subtopics st ON ss.subtopic_id = st.id
                JOIN navbar_items ni ON st.navbar_id = ni.id
                WHERE ss.id = %s
            ''', (subsub_id,))
            result = cursor.fetchone()
            
            if not result:
                return jsonify({'success': False, 'message': 'Not found'}), 404
                
            # Perform deletion
            cursor.execute('DELETE FROM sub_subtopics WHERE id = %s', (subsub_id,))
            mytdb.commit()
            
            return jsonify({
                'success': True,
                'redirect_url': url_for('view_subtopics', item_name=result[0])
            })
            
        except Exception as e:
            mytdb.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
    else:
        return redirect(url_for('login'))

@app.route('/edit_subsubtopic/<int:subsub_id>', methods=['GET', 'POST'])
def edit_subsubtopic(subsub_id):
    if session.get('Admin_mail'):
        if request.method == 'POST':
            # Handle form submission (UPDATE)
            title = request.form['title']
            content = request.form['content']
            
            # 1. Update the sub-subtopic
            cursor.execute('''
                UPDATE sub_subtopics 
                SET title=%s, content=%s ,admin_id
                WHERE id=%s
            ''', (title, content,session['Admin_id'], subsub_id))
            mytdb.commit()
            
            # 2. Get navbar_id (EXACTLY like your subtopic route)
            cursor.execute('SELECT subtopic_id FROM sub_subtopics WHERE id=%s', (subsub_id,))
            subtopic_id = cursor.fetchone()[0]
            
            cursor.execute('SELECT navbar_id FROM subtopics WHERE id=%s', (subtopic_id,))
            nav_id = cursor.fetchone()[0]
            
            # 3. Get item_name for redirect (identical to your approach)
            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (nav_id,))
            item_name = cursor.fetchone()[0]
            
            return redirect(url_for('view_content', item_name=item_name))
        
        else:
            # Handle GET request (show edit form)
            # 1. Get sub-subtopic data (matching your subtopic pattern)
            cursor.execute('''
                SELECT title, content, subtopic_id 
                FROM sub_subtopics 
                WHERE id=%s
            ''', (subsub_id,))
            subsub = cursor.fetchone()
            
            # 2. Get navbar_id (same as your approach)
            cursor.execute('SELECT navbar_id FROM subtopics WHERE id=%s', (subsub[2],))
            nav_id = cursor.fetchone()[0]
            
            # 3. Get item_name (identical to your subtopic route)
            cursor.execute('SELECT name FROM navbar_items WHERE id=%s', (nav_id,))
            item_name = cursor.fetchone()[0]
            
            return render_template('edit_subsubtopic.html', 
                                subsub_id=subsub_id,
                                title=subsub[0],
                                content=subsub[1],
                                item_name=item_name)
    else:
        return redirect(url_for('login'))

app.run(use_reloader=True, debug=True)