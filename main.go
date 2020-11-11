package main

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type auth struct {
	Username string
	Password []byte
	Ballot   string
	Status   string
	Count1   int
	Count2   int
}

var templates *template.Template
var store = sessions.NewCookieStore([]byte("secret"))

func indexGetHandler(w http.ResponseWriter, r *http.Request) {

	session, _ := store.Get(r, "session")
	registeredUser, _ := session.Values["username"]
	registeredHashedPassword, _ := session.Values["password"]
	ballot, _ := session.Values["ballot"]
	status, _ := session.Values["status"]

	count1 := countBallot("human")
	count2 := countBallot("humanoid")

	if registeredUser == nil || registeredHashedPassword == nil || status == nil {
		templates.ExecuteTemplate(w, "index.html", auth{Count1: count1, Count2: count2})
		return
	}

	if ballot == nil {
		ballot = ""
	}

	templates.ExecuteTemplate(w, "index.html",
		auth{Username: registeredUser.(string), Ballot: ballot.(string),
			Password: registeredHashedPassword.([]byte), Status: status.(string),
			Count1: count1, Count2: count2})
}

func indexPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	ballot := r.PostForm.Get("ballot")

	session, _ := store.Get(r, "session")
	username, _ := session.Values["username"]
	password, _ := session.Values["password"]

	if username == nil || password == nil {
		http.Redirect(w, r, "/login", 302)
		return
	}

	var updateStatus = updateUser(username.(string), password.([]byte), ballot)

	session.Values["status"] = updateStatus
	if updateStatus == "update successful" {
		session.Values["ballot"] = ballot
	}
	session.Save(r, w)

	http.Redirect(w, r, "/", 302)
}

func ballotGetHandler(w http.ResponseWriter, r *http.Request) {
	ballot := queryAll()
	templates.ExecuteTemplate(w, "ballot.html", ballot)
}

func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	registeredUser, _ := session.Values["username"]
	userBallot, _ := session.Values["ballot"]
	//registeredHashedPassword, _ := session.Values["password"]
	status, _ := session.Values["status"]

	if userBallot == nil {
		userBallot = ""
	}

	if registeredUser == nil || status == nil {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}

	templates.ExecuteTemplate(w, "login.html",
		auth{Username: registeredUser.(string), Ballot: userBallot.(string),
			Status: status.(string)})

}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	var userAuth auth
	userAuth = findUser(username)
	if userAuth.Status != "voter found" {
		templates.ExecuteTemplate(w, "login.html",
			auth{Status: "voter not exist"})
		return
	}

	err := bcrypt.CompareHashAndPassword(userAuth.Password, []byte(password))

	if err != nil || username != userAuth.Username {
		templates.ExecuteTemplate(w, "login.html",
			auth{Status: "username password mismatch"})
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["username"] = username
	session.Values["ballot"] = userAuth.Ballot
	session.Values["password"] = userAuth.Password
	session.Values["status"] = "logged in as " + username
	session.Save(r, w)

	http.Redirect(w, r, "/", 302)

}

func logoutGetHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["username"] = nil
	session.Values["password"] = nil
	session.Values["status"] = nil
	session.Values["ballot"] = nil
	session.Save(r, w)

	templates.ExecuteTemplate(w, "logout.html", nil)
}

func registerGetHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "register.html", nil)
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	cost := bcrypt.DefaultCost
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		templates.ExecuteTemplate(w, "register.html", auth{Status: "password not accepted"})
		return
	}

	status := addUser(username, hashedPassword)

	session, _ := store.Get(r, "session")
	session.Values["username"] = username
	session.Values["status"] = status
	session.Save(r, w)

	http.Redirect(w, r, "/login", 302)
}

func addUser(user string, password []byte) string {
	client, err := mongo.NewClient(options.Client().ApplyURI(GetConnectionString()))
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 100*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		return "error connecting to database"
	}
	defer client.Disconnect(ctx)

	electionDatabase := client.Database("sample_election")
	votersCollection := electionDatabase.Collection("voters")

	//check if voter exist
	var userAuth auth
	userAuth = findUser(user)
	if userAuth.Status == "voter found" {
		return "You are registered already, please log in."
	}

	address, err := votersCollection.InsertOne(ctx, bson.D{
		{"user", user},
		{"password", password},
		{"ballot", ""},
	})
	if err != nil {
		return "error adding new voter"
	}

	fmt.Println("inserted", user, "@ ", address)
	return "new volter profile created"
}

func findUser(user string) auth {
	client, err := mongo.NewClient(options.Client().ApplyURI(GetConnectionString()))
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 100*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		return auth{Status: "error connecting to database"}
	}
	defer client.Disconnect(ctx)

	electionDatabase := client.Database("sample_election")
	votersCollection := electionDatabase.Collection("voters")

	filterCursor, err := votersCollection.Find(ctx, bson.M{"user": user})
	defer filterCursor.Close(ctx)
	if err != nil {
		return auth{Status: "voter not found"}
	}

	var userAuth bson.M
	var userLiscense string
	var userPassword []byte
	var userBallot string

	filterCursor.Next(ctx)
	if err = filterCursor.Decode(&userAuth); err != nil {
		return auth{Status: "error connecting to database 2"}
	}

	for k, v := range userAuth {
		if k == "user" {
			userLiscense = v.(string)
		}
		if k == "ballot" {
			userBallot = v.(string)
		}
		if k == "password" {
			userPassword = v.(primitive.Binary).Data
			//fmt.Println(reflect.TypeOf(v))
		}
	}

	return auth{Username: userLiscense, Password: userPassword, Ballot: userBallot, Status: "voter found"}
}

func updateUser(registeredUser string, registeredHashedPassword []byte, ballot string) string {

	var userAuth auth
	userAuth = findUser(registeredUser)
	if userAuth.Status != "voter found" {
		return "not registered"
	}

	if bytes.Compare(userAuth.Password, registeredHashedPassword) != 0 || registeredUser != userAuth.Username {
		return "wrong credential"
	}

	client, err := mongo.NewClient(options.Client().ApplyURI(GetConnectionString()))
	if err != nil {
		return "database not exist"
	}
	ctx, _ := context.WithTimeout(context.Background(), 100*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		return "error connecting to database"
	}
	defer client.Disconnect(ctx)

	electionDatabase := client.Database("sample_election")
	votersCollection := electionDatabase.Collection("voters")

	userUpdate, err := votersCollection.UpdateOne(
		ctx,
		bson.M{"user": userAuth.Username},
		bson.M{"$set": bson.M{"ballot": ballot}})

	if err != nil {
		return "update failed"
	}
	fmt.Println(userUpdate.ModifiedCount, " updated")

	return "update successful"
}

func countBallot(ballot string) int {
	client, err := mongo.NewClient(options.Client().ApplyURI(GetConnectionString()))
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 100*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	electionDatabase := client.Database("sample_election")
	votersCollection := electionDatabase.Collection("voters")

	filterCursor, err := votersCollection.Find(ctx, bson.M{"ballot": ballot})
	defer filterCursor.Close(ctx)
	if err != nil {
		log.Fatal(err)
	}
	var countFiltered []bson.M
	if err = filterCursor.All(ctx, &countFiltered); err != nil {
		log.Fatal(err)
	}

	return len(countFiltered)
}

func queryAll() map[string]string {
	client, err := mongo.NewClient(options.Client().ApplyURI(GetConnectionString()))
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 100*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	electionDatabase := client.Database("sample_election")
	votersCollection := electionDatabase.Collection("voters")
	cursor, err := votersCollection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)

	profileArray := make(map[string]string)
	for cursor.Next(ctx) {
		var profile bson.M
		if err = cursor.Decode(&profile); err != nil {
			log.Fatal(err)
		}
		profileArray[profile["user"].(string)] = profile["ballot"].(string)
	}

	return profileArray
}

func open(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}

func main() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
	r := mux.NewRouter()
	r.HandleFunc("/", indexGetHandler).Methods("GET")
	r.HandleFunc("/", indexPostHandler).Methods("POST")
	r.HandleFunc("/ballot", ballotGetHandler).Methods("GET")
	r.HandleFunc("/login", loginGetHandler).Methods("GET")
	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/logout", logoutGetHandler).Methods("GET")
	r.HandleFunc("/register", registerGetHandler).Methods("GET")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	fs := http.FileServer(http.Dir("./static/"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	http.Handle("/", r)
	//open("http://localhost:8000/")
	port := os.Getenv("PORT")
	http.ListenAndServe(":"+port, nil)
}
