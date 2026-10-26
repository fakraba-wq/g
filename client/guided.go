package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed gui/*
var guidedAssets embed.FS

type guidedState struct {
	Phase      string      `json:"phase"`
	Message    string      `json:"message"`
	Count      int         `json:"count"`
	Report     *scanReport `json:"report,omitempty"`
	ReportPath string      `json:"reportPath,omitempty"`
}
type guidedApp struct {
	mu             sync.Mutex
	token          string
	origin         string
	config         launchConfig
	state          guidedState
	scanCancel     context.CancelFunc
	jobID          uint64
	currentSession session
	currentServer  string
	client         *http.Client
	done           chan struct{}
	closeOnce      sync.Once
}

func newGuidedApp(config launchConfig) *guidedApp {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return &guidedApp{token: hex.EncodeToString(bytes), config: config, state: guidedState{Phase: "idle", Message: "Choisissez ce que vous autorisez à vérifier."}, client: &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return errors.New("redirection refusée; utilisez l'adresse HTTPS finale")
	}}, done: make(chan struct{})}
}
func (app *guidedApp) phase(phase, message string) {
	app.mu.Lock()
	app.state.Phase = phase
	app.state.Message = message
	app.mu.Unlock()
}
func (app *guidedApp) snapshot() guidedState { app.mu.Lock(); defer app.mu.Unlock(); return app.state }
func (app *guidedApp) isBusy() bool {
	p := app.state.Phase
	return p == "connecting" || p == "scanning" || p == "sharing"
}
func (app *guidedApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if "http://"+r.Host != app.origin || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != app.origin) {
		http.Error(w, "Origin refused", 403)
		return
	}
	token := r.Header.Get("X-Crimson-Token")
	if token == "" && r.Method == "GET" {
		token = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(app.token)) != 1 {
		http.Error(w, "Local access token required", 403)
		return
	}
	reply := func(status int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(value)
	}
	fail := func(status int, message string) { reply(status, map[string]string{"error": message}) }
	var body struct {
		Server    string `json:"server"`
		Code      string `json:"code"`
		Folder    string `json:"folder"`
		Processes bool   `json:"processes"`
		Modules   bool   `json:"modules"`
		Integrity bool   `json:"integrity"`
		Boot      bool   `json:"boot"`
		Activity  bool   `json:"activity"`
		Consent   bool   `json:"consent"`
	}
	if r.Method == "POST" {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			fail(415, "JSON requis")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&body) != nil {
			fail(400, "Requête invalide")
			return
		}
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/":
		content, _ := guidedAssets.ReadFile("gui/index.html")
		t, err := template.New("index").Parse(string(content))
		if err != nil {
			fail(500, "Interface indisponible")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		t.Execute(w, map[string]string{"Token": app.token})
	case r.Method == "GET" && (r.URL.Path == "/app.js" || r.URL.Path == "/style.css" || r.URL.Path == "/logo.png"):
		content, err := guidedAssets.ReadFile("gui" + r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		types := map[string]string{"/app.js": "text/javascript; charset=utf-8", "/style.css": "text/css; charset=utf-8", "/logo.png": "image/png"}
		w.Header().Set("Content-Type", types[r.URL.Path])
		w.Write(content)
	case r.Method == "GET" && r.URL.Path == "/api/config":
		reply(200, app.config)
	case r.Method == "GET" && r.URL.Path == "/api/status":
		reply(200, app.snapshot())
	case r.Method == "GET" && r.URL.Path == "/api/report":
		state := app.snapshot()
		if state.Report == nil {
			fail(404, "Aucun rapport disponible")
			return
		}
		w.Header().Set("Content-Disposition", "attachment; filename=crimson-report.json")
		reply(200, state.Report)
	case r.Method == "POST" && r.URL.Path == "/api/folder":
		app.mu.Lock()
		busy := app.isBusy()
		app.mu.Unlock()
		if busy {
			fail(409, "Une vérification est déjà en cours")
			return
		}
		path, err := pickFolder()
		if err != nil {
			fail(400, err.Error())
			return
		}
		reply(200, map[string]string{"folder": path})
	case r.Method == "POST" && r.URL.Path == "/api/scan":
		server, err := validateServer(body.Server)
		if err != nil {
			fail(400, err.Error())
			return
		}
		if !validCode(strings.ToUpper(body.Code)) {
			fail(400, "Entrez le PIN de votre invitation, pas votre mot de passe.")
			return
		}
		if !body.Consent {
			fail(400, "Confirmez votre autorisation avant de commencer.")
			return
		}
		if body.Folder == "" && !body.Processes && !body.Modules && !body.Boot && !body.Activity {
			fail(400, "Choisissez au moins une source de données à vérifier.")
			return
		}
		if body.Folder != "" {
			if !localInputPath(body.Folder) {
				fail(400, "Choisissez un dossier local, pas un partage réseau.")
				return
			}
			info, err := os.Lstat(body.Folder)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				fail(400, "Choisissez un dossier accessible, pas un lien.")
				return
			}
		}
		app.mu.Lock()
		if app.isBusy() {
			app.mu.Unlock()
			fail(409, "Une vérification est déjà en cours")
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		app.scanCancel = cancel
		app.jobID++
		jobID := app.jobID
		app.state = guidedState{Phase: "connecting", Message: "Connexion à la session…"}
		app.currentServer = server
		app.currentSession = session{}
		app.mu.Unlock()
		go app.scan(ctx, server, strings.ToUpper(body.Code), body.Folder, scanOptions{Processes: body.Processes, Modules: body.Modules, Integrity: body.Integrity, Boot: body.Boot, Activity: body.Activity}, jobID)
		reply(202, map[string]bool{"started": true})
	case r.Method == "POST" && r.URL.Path == "/api/cancel":
		app.mu.Lock()
		if app.scanCancel != nil {
			app.scanCancel()
		}
		app.mu.Unlock()
		reply(200, map[string]bool{"cancelRequested": true})
	case r.Method == "POST" && r.URL.Path == "/api/share":
		if !body.Consent {
			fail(400, "Confirmez l'envoi du rapport.")
			return
		}
		app.mu.Lock()
		if app.state.Phase != "ready" || app.state.Report == nil {
			app.mu.Unlock()
			fail(409, "Le rapport n'est pas prêt.")
			return
		}
		report := app.state.Report
		current := app.currentSession
		server := app.currentServer
		app.state.Phase = "sharing"
		app.state.Message = "Envoi du rapport autorisé…"
		app.mu.Unlock()
		if err := post(app.client, server+"/api/sessions/"+current.SessionID+"/report", current.UploadToken, report, nil); err != nil {
			app.phase("ready", "Envoi impossible : "+err.Error()+". Le rapport reste sur votre PC.")
			fail(400, err.Error())
			return
		}
		app.phase("submitted", "Rapport envoyé. Le staff peut maintenant le consulter.")
		reply(200, map[string]bool{"submitted": true})
	case r.Method == "POST" && r.URL.Path == "/api/quit":
		app.mu.Lock()
		if app.scanCancel != nil {
			app.scanCancel()
		}
		app.mu.Unlock()
		reply(200, map[string]bool{"closed": true})
		app.closeOnce.Do(func() { close(app.done) })
	default:
		http.NotFound(w, r)
	}
}
func (app *guidedApp) scan(ctx context.Context, server, code, folder string, options scanOptions, jobID uint64) {
	defer func() {
		app.mu.Lock()
		if app.jobID == jobID {
			app.scanCancel = nil
		}
		app.mu.Unlock()
	}()
	var current session
	if err := postContext(ctx, app.client, server+"/api/sessions/redeem", "", map[string]string{"code": code}, &current); err != nil {
		app.phase("error", "Session indisponible : "+err.Error()+". Vérifiez le serveur et créez un nouveau code si nécessaire.")
		return
	}
	if len(current.SessionID) != 36 || len(current.UploadToken) != 64 || strings.ContainsAny(current.SessionID, "/\\") {
		app.phase("error", "Réponse de session invalide.")
		return
	}
	app.mu.Lock()
	app.currentSession = current
	app.mu.Unlock()
	app.phase("scanning", "Lecture des fichiers autorisés. Aucun contenu de fichier n'est envoyé.")
	report, err := scanWithOptions(ctx, folder, options, func(count int) { app.mu.Lock(); app.state.Count = count; app.mu.Unlock() })
	if err != nil {
		if errors.Is(err, context.Canceled) {
			app.phase("error", "Vérification arrêtée. Aucun rapport envoyé. Créez une nouvelle session pour recommencer.")
		} else {
			app.phase("error", err.Error())
		}
		return
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		app.phase("error", "Impossible de créer le rapport.")
		return
	}
	file, err := os.CreateTemp("", "crimson-report-*.json")
	if err != nil {
		app.phase("error", "Impossible d'enregistrer le rapport local.")
		return
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		app.phase("error", "Impossible d'enregistrer le rapport local.")
		return
	}
	app.mu.Lock()
	app.state = guidedState{Phase: "ready", Message: "Rapport prêt. Consultez-le avant de choisir de l'envoyer.", Count: len(report.Results), Report: &report, ReportPath: file.Name()}
	app.mu.Unlock()
}
func runGuided(server, code string, noOpen bool) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	app := newGuidedApp(launchConfig{Server: server, Code: code})
	app.origin = "http://" + listener.Addr().String()
	service := &http.Server{Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 2 * time.Minute, MaxHeaderBytes: 16384}
	serveErr := make(chan error, 1)
	go func() { serveErr <- service.Serve(listener) }()
	url := app.origin + "/?token=" + app.token
	fmt.Println("CRIMSON PC CHECK — interface guidée")
	fmt.Println("Laissez cette fenêtre ouverte. Votre navigateur affiche les boutons de vérification.")
	fmt.Println("Adresse privée locale :", url)
	if !noOpen {
		if err := openBrowser(url); err != nil {
			fmt.Println("Ouverture automatique impossible. Ouvrez l'adresse locale ci-dessus.")
		}
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	select {
	case <-app.done:
	case <-timer.C:
	case err := <-serveErr:
		if err != http.ErrServerClosed {
			return err
		}
	}
	app.mu.Lock()
	if app.scanCancel != nil {
		app.scanCancel()
	}
	app.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return service.Shutdown(ctx)
}
