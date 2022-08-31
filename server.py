import bcrypt
from flask import Flask, render_template,session,g,redirect,request,url_for,flash,send_file
from flask_mail import Mail,Message
import os,math
from flask_mysqldb import MySQL
import pandas,re
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv


##---------creating flask app object----------
app=Flask(__name__)

##---------connecting to db server----------
app.config["MYSQL_HOST"]="localhost"
app.config["MYSQL_USER"]="root"
app.config["MYSQL_PASSWORD"]=os.getenv('MYSQL_PASSWORD')
app.config["MYSQL_DB"]="ictlibrary"
app.config['MYSQL_CURSORCLASS']="DictCursor"

##---------connecting to Mail server----------
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] =os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] ="zjjjsgqjmvxrvzry"
app.config['MAIL_DEFAULT_SENDER'] =os.getenv('MAIL_USERNAME')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

UPLOAD_FOLDER = 'static/books'
UPLOAD_FOLDER1 = 'static'
app.config['UPLOAD_FOLDER'] =  UPLOAD_FOLDER
app.config['UPLOAD_FOLDER1'] =  UPLOAD_FOLDER1

load_dotenv()
mysql=MySQL(app)
mail=Mail(app)
app.secret_key=os.urandom(64).hex()

ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


##---------About Page----------
@app.route('/about')
def about():
    cur=mysql.connection.cursor()
    cur.execute("select * from category ORDER BY catName")
    cats=cur.fetchall()
    cur.close()
    session["surname"]=g.lname
    nameOfUser=session['surname']
    return render_template('about.html',nameOfUser=nameOfUser,cats=cats)


#----------------------------------------    
#-------------user login-------------
#----------------------------------------
@app.route('/',methods=['POST','GET'])
def  login():
    msg=""

    if request.method=='GET':
        return render_template('index.html')
    else:
        email=request.form["email"]
        password=request.form["password"].encode('utf-8')
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM USERS WHERE EMAIL=%s",[email])
        account=cur.fetchone()
        
        if account:            
                hash_password=account['userPassword']
                if bcrypt.checkpw(password,hash_password.encode('utf-8')):
                    session['type']='user'
                    session['loggedin']=True        
                    session['id']=account["userId"]
                    session['surname']=account["lastName"]
                    session['email']=account["email"]
                    nameOfUser=session['surname']
                    return redirect(url_for('dashboard'))
                else:
                    msg='Password is Incorrect'
        else:
            msg="account does not exist"
    
    return render_template('index.html',msg=msg)

#----------------------------------------    
#-------------user dashboard-------------
#----------------------------------------
@app.route('/dashboard',methods=['POST','GET'])
def dashboard():
    if g.loggedin!=True:
        return redirect(url_for('login'))
    g.lname=session['surname']
    nameOfUser=g.lname
    cur=mysql.connection.cursor()
    cur.execute("select * from category ORDER BY catName")
    cats=cur.fetchall()
    cur.close()
    return render_template('dashboard.html',cats=cats,nameOfUser=nameOfUser)

#-------------------------------------    
#---------------View books------------
#-------------------------------------
@app.route('/viewbooks/<int:cat>',defaults={'page':1})
@app.route('/viewbooks/<int:cat>/<int:page>')
def books(page,cat):
    if g.loggedin!=True:
        return redirect(url_for('login'))
    limit=8
    offset=(limit*page) - limit
    next=page+1
    previous=page-1
    cur=mysql.connection.cursor()
    cur.execute("select count(bookId) as 'count' from books where catId=%s",[cat])
    num=cur.fetchall()
    numdict=num[0]
    total_items=numdict["count"]
    total_pages=math.ceil(total_items/limit)
    nameOfUser=session['surname']

    cur.execute("select * from books where catId=%s order by bookId desc limit %s offset %s ",(cat,limit,offset))
    books=cur.fetchall()
    cur.execute("select * from category ORDER BY catName")
    cats=cur.fetchall()
    return render_template('books.html',books=books,page=total_pages,next=next,prev=previous,nameOfUser=nameOfUser,cats=cats,cat=cat)


    
  

#---------------------------------
#---------DOWNLOAD book-----------
#---------------------------------
@app.route('/downloadbook/<int:itemid>',methods=["POST","GET"])
def downloadbook(itemid):
    if g.loggedin!=True:
        return redirect(url_for('login'))
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM books where bookId=%s",[itemid])
    books=cur.fetchall()
    book=books[0]

    filename=book['bookName']
    path=book['bookPath']
    
    return send_file(path, attachment_filename=filename, mimetype='application/pdf') 

#---------------------------------
#-----------Profile-------------
#---------------------------------
@app.route('/profile',methods=["POST","GET"])
def profile():
    if g.loggedin!=True:
        return redirect(url_for('login'))
    g.lname=session['surname']
    g.id=session['id']
    nameOfUser=g.lname
    cur=mysql.connection.cursor()
    cur.execute("select * from category ORDER BY catName")
    cats=cur.fetchall()
    cur.execute('SELECT firstName,lastName,email FROM USERS WHERE userId=%s',[g.id])
    item=cur.fetchone()
    return render_template('profile.html',nameOfUser=nameOfUser,item=item,cats=cats)
    


#---------------------------------
#-----Updatee Profile Password----
#---------------------------------
@app.route('/updatepassword',methods=["POST","GET"])
def updatePassword():
    if request.method=="POST":
        password=request.form['password'].encode('utf-8')
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        confirmPassword=request.form["confirmPassword"].encode('utf-8')
        if password!=confirmPassword:
            flash('Passwords do not match') 
            return redirect(url_for('profile')) 
        else:
            cur=mysql.connection.cursor()
            cur.execute("UPDATE USERS SET userPassword=%s where userId=%s",[hash_password,g.id])
            mysql.connection.commit()
            flash('Password Updated Successfully')
            return redirect(url_for('profile'))   
    

#---------------------------------
#------Forgot Password page-------
#---------------------------------
@app.route('/forgotpassword',methods=["POST",'GET'])
def forgotPassword():
    if request.method=='POST':
        email=request.form['email']
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM  USERS WHERE EMAIL=%s",[email])
        account=cur.fetchone()
        if account:
            token = ts.dumps(email, salt='email-confirm-key')

            reset_url = url_for(
            'user_reset',
            token=token,
            _external=True)

            html = render_template('resetpasswordmail.html',reset_url=reset_url)

        # compose email
            msg=Message(recipients = [email])
            msg.subject="Reset Password"
            msg.html=html
            mail.send(msg)
            flash('A reset link has been sent to your mail')
            return redirect(url_for("home"))
        else:
            msg1="No account with this mail found"
            return render_template('forgotpassword.html',msg=msg1)
    else:
        return render_template('forgotpassword.html')

#---------------------------------
#--------Reset Password page---------
#---------------------------------
@app.route('/resetpassword/<token>',methods=["POST",'GET'])
def user_reset(token):
    try:
        email = ts.loads(token, salt="email-confirm-key", max_age=86400)
        if request.method=='GET':
            return render_template('resetpassword.html',email=email)
        
    except:
        msg='Link expired'
        return render_template('forgotpassword.html',msg=msg)

#---------------------------------
#--------Reset Password ---------
#---------------------------------
@app.route('/resetuserpassword',methods=["POST","GET"])
def newuserPassword():
        password=request.form['password'].encode('utf-8')
        email=request.form['email']
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        cur=mysql.connection.cursor()
        cur.execute("UPDATE USERS SET userPassword=%s WHERE email=%s",[hash_password,email])
        mysql.connection.commit()
        flash('Password reset successful.')
        return redirect(url_for('login'))




#...........................................
#...........................................
#................ADMIN PAGES................
#...........................................
#...........................................

@app.route('/admin/',methods=['POST','GET'])
def adminIndex():
    return render_template('admin/index.html')

#---------------------------------
#-------------signUp--------------
#---------------------------------

@app.route('/admin/signup',methods=["POST","GET"])
def adminSignup():
    if request.method=='POST':
        username=request.form['username']
        email=request.form['email']
        password=request.form['password'].encode('utf-8')
        confirmPassword=request.form["confirmPassword"].encode('utf-8')
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())

        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM  ADMIN WHERE EMAIL=%s",[email])
        account=cur.fetchall()
        if account:
            msg="account already exist"
            return render_template('signup.html',msg=msg)
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
        elif password!=confirmPassword:
            msg = 'Passwords do not match'
        else:
            cur.execute("INSERT INTO ADMIN(email,username,password) values (%s,%s,%s)",[email,username,hash_password])
            mysql.connection.commit()
            cur.execute("SELECT * FROM ADMIN WHERE email= %s",[email])
            account= cur.fetchone()
            cur.close()
            session['loggedin']=True
            session['id']=account["adminId"]
            session['email']=account["email"]
            nameOfUser='admin'
            mysql.connection.commit()
#           cur.execute("SELECT * FROM users WHERE email= %s",[email])
 #           account= cur.fetchone()
 #           cur.close()
 #           session['loggedin']=True
 #           session['id']=account["lecId"]
  #          session['surname']=account["lastName"]
 #           session['email']=account["email"]
 #           nameOfUser=session['surname']

 #           return render_template('dashboard.html',nameOfUser=nameOfUser)
            
            token = ts.dumps(email, salt='email-confirm-key')

            confirm_url = url_for(
            'admin_confirm',
            token=token,
            _external=True)

            html = render_template(
            'verifymail.html',
            confirm_url=confirm_url)

        # compose email
            msg=Message(sender="mensahmolar@gmail.com",recipients = [email])
            msg.subject="Confirm your email"
            msg.html=html
            mail.send(msg)
            return redirect(url_for("adminIndex"))

    return render_template('admin/index.html',msg=msg)


#---------------------------------
#-------------logIn--------------
#---------------------------------
@app.route('/admin/login',methods=["POST","GET"])
def adminLogin():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password'].encode('utf-8')
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM ADMIN WHERE USERNAME=%s",[username])
        account=cur.fetchone()
        cur.close()
        if account:

                hash_password=account['password']
                if bcrypt.checkpw(password,hash_password.encode('utf-8')):
                    session["type"]='admin'
                    session["loggedin"]=True        
                    session["id"]=account["adminId"]
                    session["email"]=account["email"]
                    session["surname"]=account['username']

                   
                    return redirect(url_for('adminDashboard'))
                else:
                    msg='Password is Incorrect'   
        else:
            msg="account does not exist"
    
    return render_template('admin/index.html',msg=msg)

#---------------------------------
#-----------Admin Profile---------
#---------------------------------
@app.route('/admin/profile',methods=["POST","GET"])
def adminProfile():
    if g.loggedin==True:
        itemid=g.id
        cur=mysql.connection.cursor()
        cur.execute('SELECT username,email FROM ADMIN WHERE adminId=%s',[itemid])
        item=cur.fetchone()
        nameOfUser='admin'
        return render_template('admin/profile.html',item=item,nameOfUser=nameOfUser,itemid=itemid)
    else:
        return redirect(url_for('adminIndex'))

    

#---------------------------------
#-----Update Profile Password----
#---------------------------------
@app.route('/admin/updatepassword',methods=["POST","GET"])
def updateAdminPassword():
    g.id=session['id']
    if request.method=="POST":
        password=request.form['password'].encode('utf-8')
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        confirmPassword=request.form["confirmPassword"].encode('utf-8')
        if password!=confirmPassword:
            flash('Passwords do not match') 
            return redirect(url_for('adminProfile')) 
        else:
            cur=mysql.connection.cursor()
            cur.execute("UPDATE ADMIN SET password=%s where adminId=%s",[hash_password,g.id])
            mysql.connection.commit()
            flash('Password Updated Successfully')
            return redirect(url_for("adminProfile"))

#----------------------------------------    
#-------------admin dashboard------------
#----------------------------------------
@app.route('/admin/dashboard',methods=['POST','GET'])
def adminDashboard():
    if not g.type == 'admin':
        return redirect(url_for('adminIndex'))
    cur=mysql.connection.cursor()
    cur.execute("select * from category ORDER BY catName")
    cats=cur.fetchall()
    cur.close()

    return render_template('admin/dashboard.html',cats=cats,nameOfUser='Admin')


#---------------------------------
#-------------userslist-----------
#---------------------------------

@app.route('/admin/userslist',methods=["POST","GET"])
def userslist():
    if not g.type == 'admin':
        return redirect(url_for('adminIndex'))
 
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM USERS")
    users=cur.fetchall()
    tableName='USERS'
    nameOfUser='admin'
    return render_template('admin/userslist.html',tableName=tableName,users=users,nameOfUser=nameOfUser)


#---------------------------------
#------------edit user--------------
#---------------------------------
@app.route('/admin/edituser/<int:itemid>',methods=["POST","GET"])
def editUser(itemid):
    if not g.type=='admin':
        return redirect(url_for('adminIndex'))
#        cur=mysql.connection.cursor()
    cur=mysql.connection.cursor()
    cur.execute("SELECT * FROM USERS where userId=%s",[itemid])
    item=cur.fetchone()
    nameOfUser='admin'
    return render_template('admin/edituser.html',item=item,nameOfUser=nameOfUser) 



#---------------------------------
#------------update user----------
#---------------------------------
@app.route('/admin/updateuser/<int:itemid>',methods=["POST","GET"])
def updateUser(itemid):
    #if not g.type=='admin':
#        return redirect('/admin/index.html')
        
    if request.method=="POST":
        password=request.form['password'].encode('utf-8')
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        cur=mysql.connection.cursor()
        cur.execute("UPDATE USERS SET userPassword=%s where userId=%s",[hash_password,itemid])
        mysql.connection.commit()
        flash('Password Updated Successfully')
        return redirect(url_for('userslist'))

#---------------------------------
#------------delete user----------
#---------------------------------
@app.route('/admin/deleteuser/<int:itemid>',methods=["POST","GET"])
def deleteUser(itemid):
    #if not g.type=='admin':
#        return redirect('/admin/index.html')
        
    if request.method=="POST":
        password=request.form['password'].encode('utf-8')
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        cur=mysql.connection.cursor()
        cur.execute("DELETE from USERS where userId=%s",[itemid])
        mysql.connection.commit()
        flash('User Deleted Successfully')
        return redirect(url_for('userslist'))

#---------------------------------
#------------add user----------
#---------------------------------
@app.route('/admin/adduser',methods=["POST","GET"])
def addUser():
    if not g.type=='admin':
        return redirect(url_for('adminIndex'))

    if request.method=="POST":
        email=request.form['email']
        lname=request.form['lname']
        fname=request.form['fname']
        password=request.form['password'].encode('utf-8')
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        cur=mysql.connection.cursor()
        cur.execute('INSERT INTO USERS(firstName,lastName,userPassword,email) VALUES (%s,%s,%s,%s)',[fname,lname,hash_password,email])
        mysql.connection.commit()
        flash('User added successfully')
        return redirect(url_for('userslist')) 
    else:
        return render_template('admin/adduser.html',nameOfUser='Admin')


#-------------------------------------    
#-------------upload books------------
#-------------------------------------
@app.route('/admin/uploadbook',methods=['POST','GET'])
def adminUpload():
    if not g.type == 'admin':
        return redirect(url_for('adminIndex'))

    if request.method=='GET':
        cur=mysql.connection.cursor()
        cur.execute("select * from category")
        cats=cur.fetchall()
        cur.close()
        return render_template('admin/uploadbook.html',cats=cats,nameOfUser='Admin')

    else:
        bookName=request.form['bookName']
        uploaded_file=request.files['file']
        img=request.files['image']      
        category=request.form['category']
        if uploaded_file.filename != '':
            # set the file path
            imageName=img.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], uploaded_file.filename)
            img_path = os.path.join(app.config['UPLOAD_FOLDER1'], img.filename)
            cur=mysql.connection.cursor()
            cur.execute("SELECT count(bookId) as 'count' FROM books WHERE bookPath=%s",[file_path])
            results1=cur.fetchall()
            results=results1[0]
            result=results["count"]
            if result >= 1:
                msg="Upload failed, File already exist"
                return render_template('admin/uploadbook.html',nameOfUser='Admin',msg=msg)
        
            # save the file
            uploaded_file.save(file_path)
            img.save(img_path)
        cur.execute("insert into books(bookPath,bookName,imageName,catId) values (%s,%s,%s,%s)",[file_path,bookName,imageName,category])
        mysql.connection.commit()
        flash('upload successful')
    return render_template('admin/uploadbook.html',nameOfUser='Admin')

#-------------------------------------    
#---------------View books------------
#-------------------------------------
@app.route('/admin/viewbooks/<int:cat>',defaults={'page':1})
@app.route('/admin/viewbooks/<int:cat>/<int:page>')
def viewBooks(page,cat):
    if not g.type == 'admin':
        return redirect(url_for('adminIndex'))
    limit=15
    offset=(limit*page) - limit
    next=page+1
    previous=page-1
    cur=mysql.connection.cursor()
    cur.execute("select count(bookId) as 'count' from books where catId=%s",[cat])
    num=cur.fetchall()
    numdict=num[0]
    total_items=numdict["count"]
    total_pages=math.ceil(total_items/limit)

    cur.execute("select * from books where catId=%s order by bookId desc limit %s offset %s ",(cat,limit,offset))
    books=cur.fetchall()
    return render_template('admin/viewbooks.html',books=books,page=total_pages,next=next,prev=previous,nameOfUser='Admin')

#---------------------------------
#--------delete book----------
#---------------------------------
@app.route('/admin/deletebook/<itemid>',methods=["POST","GET"])
def deletebook(itemid):
    if not g.type=='admin':
        return redirect(url_for('adminIndex'))
    cur=mysql.connection.cursor()
    cur.execute("DELETE FROM books where bookId=%s",[itemid])
    mysql.connection.commit()
    flash('Book Deleted')
    return redirect(url_for('adminDashboard'))

#--------------------------------------------
#---------------VIEW CATEGORY----------------
#--------------------------------------------
@app.route('/admin/category',methods=["POST","GET"])
def category():
    cur=mysql.connection.cursor()
    cur.execute("select * from category")
    cats=cur.fetchall()
    cur.close()
    return render_template('admin/category.html',cats=cats,nameOfUser='Admin')

#---------------------------------
#---------add category-----------
#---------------------------------
@app.route('/admin/addcategory',methods=["POST","GET"])
def addcategory():
    if not g.type=='admin':
        return redirect(url_for('adminIndex'))
    catname=request.form["catname"]
    cur=mysql.connection.cursor()
    cur.execute('INSERT INTO category(catName) VALUES (%s)',[catname])
    mysql.connection.commit()
    flash('Category Item Added successfully')
    return redirect(url_for('category'))

#---------------------------------
#--------delete category----------
#---------------------------------
@app.route('/admin/deletecategory/<itemid>',methods=["POST","GET"])
def deletecategory(itemid):
    if not g.type=='admin':
        return redirect(url_for('adminIndex'))
    cur=mysql.connection.cursor()
    cur.execute("DELETE FROM category where catId=%s",[itemid])
    mysql.connection.commit()
    flash('Category Item Deleted')
    return redirect(url_for('category'))

#---------------------------------
#------Forgot Password page-------
#---------------------------------
@app.route('/admin/forgotpassword',methods=["POST",'GET'])
def adminforgotPassword():
    if request.method=='POST':
        email=request.form['email']
        cur=mysql.connection.cursor()
        cur.execute("SELECT * FROM  ADMIN WHERE EMAIL=%s",[email])
        account=cur.fetchone()
        if account:
            token = ts.dumps(email, salt='email-confirm-key')

            reset_url = url_for(
            'admin_reset',
            token=token,
            _external=True)

            html = render_template('admin/resetpasswordmail.html',reset_url=reset_url)

        # compose email
            msg=Message(recipients = [email])
            msg.subject="Reset Password"
            msg.body=html
            mail.send(msg)
            return redirect(url_for("adminIndex"))
        else:
            msg1="No account with this mail found"
            return render_template('admin/forgotpassword.html',msg=msg1)
    else:
        return render_template('admin/forgotpassword.html')

#---------------------------------
#--------Reset Password page---------
#---------------------------------
@app.route('/admin/resetpassword/<token>',methods=["POST",'GET'])
def admin_reset(token):
    try:
        email = ts.loads(token, salt="email-confirm-key", max_age=86400)
        if request.method=='GET':
            return render_template('admin/resetpassword.html',email=email)
        
    except:
        msg='Link expired'
        return render_template('admin/forgotpassword.html',msg=msg)

#---------------------------------
#--------Reset Password ---------
#---------------------------------
@app.route('/admin/resetadminpassword',methods=["POST","GET"])
def newadminPassword():
        password=request.form['password'].encode('utf-8')
        email=request.form['email']
        hash_password=bcrypt.hashpw(password,bcrypt.gensalt())
        cur=mysql.connection.cursor()
        cur.execute("UPDATE ADMIN SET password=%s WHERE email=%s",[hash_password,email])
        mysql.connection.commit()
        flash('Password reset successful.')
        return redirect(url_for('adminIndex'))
            
@app.route('/logout')
def logout():
        # Remove session data, this will log the user out
   session.pop('loggedin', None)
   session.pop('id', None)
   session.pop('email', None)
   session.pop('type', None)
   session.pop('surname', None)
   # Redirect to login page
   return redirect(request.referrer)

#----------------------------------------------------
#-----the real deal....performs this action every time any request is made
@app.before_request
def before_request():
    g.type=None
    g.loggedin= None
    g.id=None
    g.email=None
    g.lname=None
 
    if 'loggedin' in session:
        g.type=session['type']
        g.loggedin= session['loggedin']
        g.id=session['id']
        g.email=session['email']
        g.lname=session['surname']
        

@app.errorhandler(404)
def page_not_found(e):
    if g.loggedin==True:
        session['surname']=g.lname
        nameOfUser=session['surname']
        return render_template("404.html",nameOfUser=nameOfUser)
    else:
        return render_template("404.html")


##makes sure pages are not cached after requests 
'''this is done to prevent a user from accesing pages after logout'''
@app.after_request
def after_request(response):
    response.headers['Cache-control']='no-cache,no-store, must-revalidate'
    return response

        


        
        
        
     


if __name__=="__main__":
    app.run(debug=True)