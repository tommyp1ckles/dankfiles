package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// users are added at startup
var users = map[string][]byte{}

type Logger struct {
	Handler http.Handler
}

func (l Logger) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("%s - %s request\n", req.Method, req.URL)
	l.Handler.ServeHTTP(w, req)
}

type LoginMiddleware struct {
	Key []byte
}

const PasswordSalt = "pjsalt"

func hash(pass string) ([]byte, error) {
	salt := []byte(PasswordSalt)
	dk, err := scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32)
	if err != nil {
		log.Fatal(err)
	}
	return dk, err
}

func equal(a, b []byte) bool {
	for i, _ := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (l *LoginMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		panic(err)
	}
	user := req.Form.Get("user")
	pass := req.Form.Get("password")
	hashed, err := hash(pass)

	if err != nil {
		w.Write([]byte("could not do authentication (failed to hash)"))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	realHashed, ok := users[user]
	if !ok || !equal(hashed, realHashed) {
		w.Write([]byte("authentication failed"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user"] = "slothluv"
	claims["expiry"] = fmt.Sprintf("%d", time.Now().UTC().
		Add(time.Hour*24).Unix())

	output, err := token.SignedString(l.Key)
	if err != nil {
		panic(err)
	}

	cookie := http.Cookie{
		Name:  "auth",
		Value: output,
	}
	http.SetCookie(w, &cookie)
	w.Header().Set("Location", "/fs/")
	w.WriteHeader(http.StatusMovedPermanently)
	w.Write([]byte(output))
}

type JWTAuthMiddleware struct {
	Key            []byte
	AuthCookieName string
	Handler        http.Handler
}

func (am JWTAuthMiddleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	c, err := req.Cookie(am.AuthCookieName)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	t, err := jwt.Parse(c.Value, func(token *jwt.Token) (interface{}, error) {
		return am.Key, nil
	})
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, ok := (t.Claims.(jwt.MapClaims))["user"]
	if !ok {
		log.Error("Bad Auth Token: no user")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	log.WithField("user", t.Claims.(jwt.MapClaims)["user"]).Println("Validated user token")

	am.Handler.ServeHTTP(w, req)
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UsersConfig struct {
	Users []User `json:"users"`
}

func ReadUsers() (*UsersConfig, error) {
	users := &UsersConfig{}
	fd, err := os.Open("users.json")
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func main() {
	type Config struct {
		Port     string `json:"port"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
		FS       string `json:"fs"`
	}

	// read in config
	conf := &Config{}
	configFile, err := os.Open("./config.json")
	if err != nil {
		log.WithError(err).Fatalln("Could not open config file")
	}
	b, err := ioutil.ReadAll(configFile)
	if err != nil {
		log.WithError(err).Fatalln("Could not read config file")
	}
	err = json.Unmarshal(b, conf)
	if err != nil {
		log.WithError(err).Fatalln("Could not unmarshal config")
	}

	// init
	uc, err := ReadUsers()
	if err != nil {
		log.Fatalln(err)
	}

	for _, u := range uc.Users {
		log.WithField("user", u.Username).Println("Adding user")
		p, err := base64.StdEncoding.DecodeString(u.Password)
		if err != nil {
			log.WithError(err).WithField("user", u.Username).
				Fatalln("Could not decode user password")
		}
		users[u.Username] = p
	}

	rid, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}

	key := []byte(rid.String())

	r := mux.NewRouter()
	authApp := &LoginMiddleware{
		Key: key,
	}
	r.Handle("/login", authApp)
	r.Handle("/index", http.FileServer(http.Dir("./index.html")))

	// Make FS server
	fs := http.FileServer(http.Dir(conf.FS))
	authenticatedFS := JWTAuthMiddleware{
		Key:            key,
		AuthCookieName: "auth",
		Handler:        fs,
	}
	r.PathPrefix("/fs/").Handler(
		http.StripPrefix("/fs/", authenticatedFS),
	)

	// Make static server
	static := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/").Handler(
		//http.StripPrefix("/static/", static),
		static,
	)
	app := &Logger{
		Handler: r,
	}

	if conf.CertFile != "" {
		log.Println("Starting TLS Server")
		log.Fatalln(http.ListenAndServeTLS(
			conf.Port,
			conf.CertFile,
			conf.KeyFile,
			app,
		))
	} else {
		log.Println("Starting Server")
		log.Fatalln(http.ListenAndServe(
			conf.Port,
			app,
		))
	}
}
