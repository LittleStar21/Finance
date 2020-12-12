import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    owned = db.execute("SELECT symbol, name, shares, price, total FROM owned WHERE user_id = :user_id", user_id=user_id)
    money = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"]
    total = money
    for mine in owned:
        total += mine["total"]
    return render_template("index.html", owned=owned, money=money, total=total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("The symbol cannot be blank", 400)

        shares = int(request.form.get("shares"))
        if not shares:
            return apology("Missing shares", 400)
        if shares <= 0:
            return apology("Shares must be positive integer", 400)

        user_id = session["user_id"]
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=user_id)[0]["cash"]

        search = lookup(symbol)
        if not search:
            return apology("Not a valid symbol")
        price = search["price"]
        name = search["name"]
        total = price * shares

        # Not enough cash
        if total > cash:
            return apology("Not enough cash", 400)

        # Add transaction into purchases
        db.execute("INSERT INTO purchases (user_id, symbol, name, quantity, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                    user_id, symbol, name, shares, price, total)

        # If already owned
        search = db.execute("SELECT shares, total FROM owned WHERE user_id = :user_id AND symbol = :symbol", user_id=user_id, symbol=symbol)
        if search:
            newShare = search[0]["shares"] + shares
            newTotal = search[0]["total"] + total
            print(search[0]["total"])
            print(newTotal)
            db.execute("UPDATE owned SET shares = :shares WHERE user_id = :user_id AND symbol = :symbol",
                        shares=newShare, user_id=user_id, symbol=symbol)
            db.execute("UPDATE owned SET total = :newTotal WHERE user_id = :user_id AND symbol = :symbol",
                        newTotal=newTotal, user_id=user_id, symbol=symbol)
        # New stocks
        else:
            db.execute("INSERT INTO owned (user_id, symbol, name, shares, price, total) values (?, ?, ?, ?, ?, ?)",
                        user_id, symbol, name, shares, price, total)


        # Update user money
        db.execute("UPDATE users SET cash = :value WHERE id = :user_id",
                    value=cash - (price * shares), user_id=user_id)

        # Go back
        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT symbol, name, quantity, price, total, time FROM purchases WHERE user_id = :user_id",
                            user_id=session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        if not symbol:
            return apology("No symbol entered", 403)

        quote = lookup(symbol)
        if not quote:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=usd(quote["price"]))

    else:
        return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # Checks username
        username = request.form.get("username")
        if not username:
            return apology("You must provide a username", 403)
        if db.execute("SELECT * from users WHERE username = :username", username=username):
            return apology("The username has already registered", 403)

        # Checks password
        password = request.form.get("password")
        if not password:
            return apology("You must provide a password", 403)
        if not password == request.form.get("password_again"):
            return apology("Passwords don't match", 400)

        # Insert new username and password
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashed_pass)",
                    username=username, hashed_pass=generate_password_hash(password))
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        sharesToSell = int(request.form.get("shares"))
        symbol = request.form.get("symbol").upper()

        # Get owned stock
        owned = db.execute("SELECT shares FROM owned WHERE symbol = :symbol AND user_id = :user_id", symbol=symbol, user_id=session["user_id"])[0]["shares"]

        # Not enough stock
        if owned < sharesToSell:
            return apology("You don't have that much", 403)

        # Update user cash
        search = lookup(symbol)
        price = search["price"]
        totalPrice = price * sharesToSell
        newMoney = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])[0]["cash"] + totalPrice
        db.execute("UPDATE users SET cash = :cash", cash = newMoney)

        # Update purchase
        db.execute("INSERT INTO purchases (user_id, symbol, name, quantity, price, total) VALUES (?, ?, ?, ?, ?, ?)",
                    session["user_id"], symbol, search["name"], -1 * sharesToSell, price, totalPrice)

        # Update user stock and total
        shares = owned - sharesToSell
        total = shares * price
        if shares > 0:
            db.execute("UPDATE owned SET shares = :shares, total = :total WHERE user_id = :user_id AND symbol = :symbol",
                        shares=shares, total=total, user_id=session["user_id"], symbol=symbol)
        else:
            db.execute("DELETE FROM owned WHERE user_id = :user_id AND symbol = :symbol",
                        user_id=session["user_id"], symbol=symbol)

        # Go back
        return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM owned WHERE user_id = :user_id", user_id=session["user_id"])
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)