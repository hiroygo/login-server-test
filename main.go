package main

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/stretchr/gomniauth"
	"github.com/stretchr/gomniauth/providers/google"
	"github.com/stretchr/objx"
	"github.com/stretchr/signature"
)

var sessions sync.Map

type templateHandler struct {
	templ *template.Template
}

func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{}
	if c, err := r.Cookie("username"); err == nil {
		b, err := base64.StdEncoding.DecodeString(c.Value)
		if err != nil {
			log.Println("DecodeString error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		data["username"] = string(b)
	}
	if err := t.templ.Execute(w, data); err != nil {
		log.Println("Execute error: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func newTemplateHandler(templatePath string) *templateHandler {
	t := &templateHandler{}
	t.templ = template.Must(template.ParseFiles(templatePath))
	return t
}

type authHandler struct {
	next http.Handler
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err == nil {
		b, err := base64.StdEncoding.DecodeString(c.Value)
		if err != nil {
			log.Println("DecodeString error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, ok := sessions.Load(string(b))
		if !ok {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		a.next.ServeHTTP(w, r)
		return
	}
	if err == http.ErrNoCookie {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	log.Println("Cookie error: ", err)
	w.WriteHeader(http.StatusInternalServerError)
}

func MustAuth(h http.Handler) http.Handler {
	return &authHandler{next: h}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	ss := strings.Split(r.URL.Path, "/")
	if len(ss) != 4 {
		log.Printf("len(Split(%v)) returns %v\n", r.URL.Path, len(ss))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	action := ss[2]
	provider := ss[3]
	switch action {
	case "login":
		provider, err := gomniauth.Provider(provider)
		if err != nil {
			log.Println("Provider error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		loginURL, err := provider.GetBeginAuthURL(nil, nil)
		if err != nil {
			log.Println("GetBeginAuthURL error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Location", loginURL)
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	case "callback":
		provider, err := gomniauth.Provider(provider)
		if err != nil {
			log.Println("Provider error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		creds, err := provider.CompleteAuth(objx.MustFromURLQuery(r.URL.RawQuery))
		if err != nil {
			log.Println("CompleteAuth error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		user, err := provider.GetUser(creds)
		if err != nil {
			log.Println("GetUser error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		session, err := uuid.NewRandom()
		if err != nil {
			log.Println("NewRandom error: ", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sessions.Store(session.String(), struct{}{})
		http.SetCookie(w, &http.Cookie{
			Name:  "username",
			Value: base64.StdEncoding.EncodeToString([]byte(user.Name())),
			Path:  "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: base64.StdEncoding.EncodeToString([]byte(session.String())),
			Path:  "/",
		})
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
}

func main() {
	addr := "localhost:8080"

	clientId := os.Getenv("AUTH_GOOGLE_ID")
	if clientId == "" {
		log.Fatal("AUTH_GOOGLE_ID is empty")
	}
	clientSecret := os.Getenv("AUTH_GOOGLE_SECRET")
	if clientSecret == "" {
		log.Fatal("AUTH_GOOGLE_SECRET is empty")
	}
	gomniauth.SetSecurityKey(signature.RandomKey(64))
	gomniauth.WithProviders(
		google.New(clientId, clientSecret, fmt.Sprintf("http://%v/auth/callback/google", addr)),
	)

	http.Handle("/", MustAuth(newTemplateHandler(filepath.FromSlash(`templates/index.html`))))
	http.Handle("/login", newTemplateHandler(filepath.FromSlash(`templates/login.html`)))
	http.HandleFunc("/auth/", loginHandler)
	log.Println("server is running: ", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
