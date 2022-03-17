from flask import Flask,render_template,request,session,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager
from flask_login import login_required,current_user
from flask_mail import Mail
import json

app = Flask(__name__)
app.secret_key='s3cr3t'

#DB Connection
local_server = True
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+mysqlconnector://root:@localhost/kabaddi"
db = SQLAlchemy(app)

#User access
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Table Classes
class User(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key=True)
    username = db.Column(db.String(50))
    email = db.Column(db.String(50),unique=True)
    password = db.Column(db.String(100))


class Teams(db.Model):
    tid = db.Column(db.Integer, primary_key = True)
    Tname = db.Column(db.String(20))
    HCity = db.Column(db.String(20))
    Total_matches = db.Column(db.Integer)
    Total_wins = db.Column(db.Integer)

class Players(db.Model):
    pid = db.Column(db.Integer, primary_key = True)
    Name = db.Column(db.String(20))
    Age = db.Column(db.Integer)
    tid = db.Column(db.Integer, db.ForeignKey('teams.tid'), nullable=False)
    Type = db.Column(db.String)

class Matches(db.Model):
    mno = db.Column(db.Integer, primary_key = True)
    Venue = db.Column(db.String(20))
    Date = db.Column(db.String())
    Time = db.Column(db.String())
    Team_1 = db.Column(db.Integer, db.ForeignKey('teams.tid'), nullable=False)
    Team_2 = db.Column(db.Integer, db.ForeignKey('teams.tid'), nullable=False)

class Player_stats(db.Model):
    pid = db.Column(db.Integer, db.ForeignKey('players.pid'), nullable=False, primary_key = True)
    Total_matches = db.Column(db.Integer)
    Total_points = db.Column(db.Integer)

class Team_stats(db.Model):
    tid = db.Column(db.Integer, db.ForeignKey('teams.tid'), nullable=False, primary_key = True)
    mno = db.Column(db.Integer, db.ForeignKey('matches.mno'), nullable=False, primary_key = True)
    Status = db.Column(db.String(2))

class Trigger_teams(db.Model):
    tgid = db.Column(db.Integer, primary_key = True)
    tid = db.Column(db.Integer)
    TName = db.Column(db.String(50))
    Total_wins = db.Column(db.Integer)
    action = db.Column(db.String(50))
    timestamp = db.Column(db.String(50))

@app.route("/")
def index():
    return render_template('index.html')

@app.route('/signup',methods=['POST','GET'])
def signup():
    if request.method == "POST":
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email = email).first()
        if user:
            flash("Email already exists","warning")
            return render_template('/signup.html')
        encpassword = generate_password_hash(password)

        new_user = db.engine.execute(f"INSERT INTO `user` (`username`,`email`,`password`) VALUES ('{username}','{email}','{encpassword}')")

        flash("Account created, please login","success")
        return render_template('login.html')
    return render_template('/signup.html')

@app.route('/login',methods=['POST','GET'])
def login():
    if request.method == "POST":
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password,password):
            login_user(user)
            flash("Logged in succesfully","primary")
            return redirect(url_for('index'))
        else:
            flash("Invalid Credentials","danger")
            return render_template('login.html')    

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout SuccessFul","warning")
    return redirect(url_for('index'))

@app.route('/players')
@login_required
def players(): 
    query = db.engine.execute(f"SELECT * FROM `players`")
    return render_template('players.html', query = query)

@app.route('/teams')
@login_required
def teams(): 
    query = db.engine.execute(f"SELECT * FROM `teams`")
    return render_template('teams.html', query = query)

@app.route('/add_player', methods = ['POST','GET'])
@login_required
def add_player():
    teams = db.engine.execute("SELECT * FROM `teams`") 
    if request.method=="POST":
        pid = request.form.get('pid')
        Name = request.form.get('name')
        Age = request.form.get('age')
        tid = request.form.get('tid')
        Type = request.form.get('type')
        query = db.engine.execute(f"INSERT INTO `players` (`pid`,`Name`,`Age`,`tid`,`Type`) VALUES ('{pid}','{Name}','{Age}','{tid}','{Type}')")
        flash("New player added","primary")
        return redirect('players')

    return render_template('add_player.html', teams = teams)

@app.route("/delete/<string:pid>",methods=['POST','GET'])
@login_required
def delete_player(pid):
    db.engine.execute(f"DELETE FROM `players` WHERE `players`.`pid`={pid}")
    flash("Player Deleted Successfully","danger")
    return redirect('/players')

@app.route("/edit/<string:pid>",methods=['POST','GET'])
@login_required
def edit_player(pid):
    posts = Players.query.filter_by(pid=pid).first()
    teams = db.engine.execute("SELECT * FROM `teams`")
    p_team = db.session.query(Players, Teams.Tname).filter(Teams.tid == Players.tid).filter(Players.pid == pid)
    p_type = db.session.query(Players.Type, Teams).filter(Teams.tid == Players.tid).filter(Players.pid == pid)
    if request.method == "POST":
        pid = request.form.get('pid')
        Name = request.form.get('name')
        Age = request.form.get('age')
        tid = request.form.get('tid')
        Type = request.form.get('type')
        db.engine.execute(f"UPDATE `players` SET `Name` = '{Name}', `Age` = '{Age}', `tid` = '{tid}', `Type` = '{Type}' WHERE `players`.`pid` = {pid}")
        flash("Player Updated","success")
        return redirect('/players')
    
    return render_template('edit_player.html', posts = posts, teams = teams, p_team = p_team, p_type = p_type)

@app.route('/add_team', methods = ['POST','GET'])
@login_required
def add_team():
    teams = db.engine.execute("SELECT * FROM `teams`") 
    if request.method == "POST":
        tid = request.form.get('tid')
        TName = request.form.get('Tname')
        HCity = request.form.get('HCity')
        Total_matches = request.form.get('Total_matches')
        Total_wins = request.form.get('Total_wins')
        query = db.engine.execute(f"INSERT INTO `teams` (`tid`,`TName`,`HCity`,`Total_matches`,`Total_wins`) VALUES ('{tid}','{TName}','{HCity}','{Total_matches}','{Total_wins}')")
        flash("New team added","primary")
        return redirect('teams')

    return render_template('add_team.html', teams = teams)

@app.route("/delete_team/<string:tid>",methods=['POST','GET'])
@login_required
def delete_team(tid):
    db.engine.execute(f"DELETE FROM `teams` WHERE `teams`.`tid`={tid}")
    flash("Team Deleted Successfully","danger")
    return redirect('/teams')

@app.route("/edit_team/<string:tid>",methods=['POST','GET'])
@login_required
def edit_team(tid):
    posts = Teams.query.filter_by(tid = tid).first()
    if request.method == "POST":
        # tid = request.form.get('tid')
        TName = request.form.get('Tname')
        HCity = request.form.get('HCity')
        Total_matches = request.form.get('Total_matches')
        Total_wins = request.form.get('Total_wins')
        db.engine.execute(f"UPDATE `teams` SET `TName` = '{TName}', `HCity` = '{HCity}', `Total_matches` = '{Total_matches}', `Total_wins` = '{Total_wins}' WHERE `teams`.`tid` = {tid}")
        flash("Team Updated","success")
        return redirect('/teams')
    
    return render_template('edit_team.html', posts = posts)

@app.route('/matches')
@login_required
def matches(): 
    query = db.engine.execute(f"SELECT * FROM `matches`")
    return render_template('matches.html', query = query)

@app.route('/add_match', methods = ['POST','GET'])
@login_required
def add_match():
    teams = db.engine.execute("SELECT * FROM `teams`")
    teams1 = db.engine.execute("SELECT * FROM `teams`")
    teams2 = db.engine.execute("SELECT * FROM `teams`") 
    if request.method == "POST":
        mno = request.form.get('mno')
        Venue = request.form.get('Venue')
        Date = request.form.get('Date')
        Time = request.form.get('Time')
        Team_1 = request.form.get('Team_1')
        Team_2 = request.form.get('Team_2')
        query = db.engine.execute(f"INSERT INTO `matches` (`mno`,`Venue`,`Date`,`Time`,`Team_1`,`Team_2`) VALUES ('{mno}','{Venue}','{Date}','{Time}','{Team_1}','{Team_2}')")
        flash("New match added","primary")
        return redirect('matches')

    return render_template('add_match.html', teams = teams, teams1 = teams1, teams2 = teams2)

@app.route("/delete_match/<string:mno>",methods=['POST','GET'])
@login_required
def delete_match(mno):
    db.engine.execute(f"DELETE FROM `matches` WHERE `matches`.`mno`={mno}")
    flash("Match Deleted Successfully","danger")
    return redirect('/matches')

@app.route("/edit_match/<string:mno>",methods=['POST','GET'])
@login_required
def edit_match(mno):
    posts = Matches.query.filter_by(mno = mno).first()
    venue = db.session.query(Matches, Teams.HCity).filter(Matches.Venue == Teams.HCity).filter(Matches.mno == mno)
    teams = db.engine.execute("SELECT * FROM `teams`")
    team_name1 = db.session.query(Matches, Teams.Tname).filter(Matches.Team_1 == Teams.tid).filter(Matches.mno == mno)
    team_name2 = db.session.query(Matches, Teams.Tname).filter(Matches.Team_2 == Teams.tid).filter(Matches.mno == mno)
    teams1 = db.engine.execute("SELECT * FROM `teams`")
    teams2 = db.engine.execute("SELECT * FROM `teams`")
    if request.method == "POST":
        # mno = request.form.get('mno')
        Venue = request.form.get('Venue')
        Date = request.form.get('Date')
        Time = request.form.get('Time')
        Team_1 = request.form.get('Team_1')
        Team_2 = request.form.get('Team_2')
        db.engine.execute(f"UPDATE `matches` SET `Venue` = '{Venue}', `Date` = '{Date}', `Time` = '{Time}', `Team_1` = '{Team_1}', `Team_2` = '{Team_2}' WHERE `matches`.`mno` = {mno}")
        flash("Match Updated","success")
        return redirect('/matches')
    
    return render_template('edit_match.html', posts = posts, venue = venue, teams = teams, team_name1 = team_name1, teams1 = teams1, teams2 = teams2, team_name2 = team_name2)

@app.route('/playerstats')
@login_required
def playerstats(): 
    query = db.engine.execute(f"SELECT * FROM `player_stats`")
    return render_template('playerstats.html', query = query)

@app.route('/add_playerstats', methods = ['POST','GET'])
@login_required
def add_playerstats(): 
    if request.method == "POST":
        pid = request.form.get('pid')
        Total_matches = request.form.get('Total_matches')
        Total_points = request.form.get('Total_points')
        query = db.engine.execute(f"INSERT INTO `player_stats` (`pid`,`Total_matches`,`Total_points`) VALUES ('{pid}','{Total_matches}','{Total_points}')")
        flash("New stat added","primary")
        return redirect('playerstats')

    return render_template('add_playerstats.html')

@app.route("/delete_playerstats/<string:pid>",methods=['POST','GET'])
@login_required
def delete_playerstats(pid):
    db.engine.execute(f"DELETE FROM `player_stats` WHERE `player_stats`.`pid`={pid}")
    flash("Stat Deleted Successfully","danger")
    return redirect('/playerstats')

@app.route("/edit_playerstats/<string:pid>",methods=['POST','GET'])
@login_required
def edit_playerstats(pid):
    posts = Player_stats.query.filter_by(pid = pid).first()
    if request.method == "POST":
        # tid = request.form.get('tid')
        Total_matches = request.form.get('Total_matches')
        Total_points = request.form.get('Total_points')
        db.engine.execute(f"UPDATE `player_stats` SET `Total_matches` = '{Total_matches}', `Total_points` = '{Total_points}' WHERE `player_stats`.`pid` = {pid}")
        flash("Stat Updated","success")
        return redirect('/playerstats')
    
    return render_template('edit_playerstats.html', posts = posts)

@app.route('/teamstats')
@login_required
def teamstats(): 
    query = db.engine.execute(f"SELECT * FROM `team_stats`")
    return render_template('teamstats.html', query = query)

@app.route('/add_teamstats', methods = ['POST','GET'])
@login_required
def add_teamstats():
    teams = db.engine.execute("SELECT * FROM `teams`")
    matches = db.engine.execute("SELECT * FROM `matches`") 
    if request.method == "POST":
        tid = request.form.get('tid')
        mno = request.form.get('mno')
        Status = request.form.get('Status')
        query = db.engine.execute(f"INSERT INTO `team_stats` (`tid`,`mno`,`Status`) VALUES ('{tid}','{mno}','{Status}')")
        flash("New stat added","primary")
        return redirect('teamstats')

    return render_template('add_teamstats.html', teams = teams, matches = matches)

@app.route("/delete_teamstats/<string:tid>/<string:mno>",methods=['POST','GET'])
@login_required
def delete_teamstats(tid, mno):
    db.engine.execute(f"DELETE FROM `team_stats` WHERE `team_stats`.`tid`={tid} and `team_stats`.`mno`={mno}")
    flash("Stat Deleted Successfully","danger")
    return redirect('/teamstats')

@app.route("/edit_teamstats/<string:tid>",methods=['POST','GET'])
@login_required
def edit_teamstats(tid):
    posts = Team_stats.query.filter_by(tid = tid).first()
    matches = db.engine.execute("SELECT * FROM `matches`")
    if request.method == "POST":
        # tid = request.form.get('tid')
        mno = request.form.get('mno')
        Status = request.form.get('Status')
        db.engine.execute(f"UPDATE `team_stats` SET `mno` = '{mno}', `Status` = '{Status}' WHERE `team_stats`.`tid` = {tid}")
        flash("Stat Updated","success")
        return redirect('/teamstats')
    
    return render_template('edit_teamstats.html', posts = posts, matches = matches)

@app.route('/trigger_teams')
@login_required
def trigger_teams(): 
    query = db.engine.execute(f"SELECT * FROM `trigger_teams`")
    return render_template('trigger_teams.html', query = query)

app.run(debug = True)