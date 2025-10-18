package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/MokshShahh/Chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// to store the no of times /app is hit
type apiConfig struct {
	fileserverHits atomic.Int32
	DB             *database.Queries
}

// adding middleware to /app
// is a method as it needs access to fileserver hits
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// returns total hits on /app
// accessible at /api/metrics
func (cfg *apiConfig) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	w.Write([]byte(fmt.Sprintf(`<html>
									<body>
										<h1>Welcome, Chirpy Admin</h1>
										<p>Chirpy has been visited %d times!</p>
									</body>
									</html>`, hits)))
}

// resets fileserverhits
// accessible at /api/reset (post)
func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("could not load .env")
	}
	platform := os.Getenv("PLATFORM")
	if platform == "dev" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		cfg.fileserverHits.Store(0)
		w.Write([]byte("OK"))
		//deleting all users
		cfg.DB.ResetUsers(r.Context())
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
	}
}

// just to check if server is ready
func handlerReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(http.StatusText(http.StatusOK)))
}

// add chirp to db
// has to be less than 140 chars long
// accessible at /api/chirps (post)
func (cfg *apiConfig) addChirp(w http.ResponseWriter, r *http.Request) {
	type param struct {
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}
	decoder := json.NewDecoder(r.Body)
	params := param{}
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(500)
		response := map[string]string{"error": "Something went wrong with JSON decoding"}
		data, _ := json.Marshal(response)
		w.Write(data)
		log.Printf("JSON decoding error: %v", err)
		return
	}
	text := params.Body
	if len(text) > 140 {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(400)
		response := map[string]string{"error": "Chirp too long"}
		data, _ := json.Marshal(response)
		w.Write(data)
		return
	}

	dbParams := database.CreateChirpParams{
		Body:   params.Body,
		UserID: params.UserID,
	}
	data, err := cfg.DB.CreateChirp(r.Context(), dbParams)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(500)
		response := map[string]string{"error": "Could not add to db"}
		data, _ := json.Marshal(response)
		w.Write(data)
		log.Printf("Database error: %v", err)
		return
	}

	type Chirp struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	chirpp := Chirp{
		ID:        data.ID,
		CreatedAt: data.CreatedAt,
		UpdatedAt: data.UpdatedAt,
		Body:      data.Body,
		UserID:    data.UserID,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	res, _ := json.Marshal(chirpp)
	w.Write(res)
}

// returns all chirps ordered in ascending order of creation time
// GET @ /api/chirps
func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	type Chirp struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}
	data, err := cfg.DB.GetAllChirps(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("Database error fetching chirps: %v", err)
		return
	}
	chirps := []Chirp{}
	for _, dbChirp := range data {
		chirps = append(chirps, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	res, err := json.Marshal(chirps)
	if err != nil {
		log.Printf("JSON marshaling error: %v", err)
		return
	}
	w.Write(res)

}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	type Chirp struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Body      string    `json:"body"`
		UserID    uuid.UUID `json:"user_id"`
	}

	idString := r.PathValue("id")
	id, err := uuid.Parse(idString)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		response := map[string]string{"error": "Invalid Chirp ID"}
		data, _ := json.Marshal(response)
		w.Write(data)
		return
	}

	data, err := cfg.DB.GetOneChirp(r.Context(), id)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			response := map[string]string{"error": "Chirp not found"}
			data, _ := json.Marshal(response)
			w.Write(data)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		response := map[string]string{"error": "Could not fetch chirp"}
		data, _ := json.Marshal(response)
		w.Write(data)
		log.Printf("Database error fetching chirp: %v", err)
		return
	}

	chirp := Chirp{
		ID:        data.ID,
		CreatedAt: data.CreatedAt,
		UpdatedAt: data.UpdatedAt,
		Body:      data.Body,
		UserID:    data.UserID,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	res, err := json.Marshal(chirp)
	if err != nil {
		log.Printf("JSON marshaling error: %v", err)
		return
	}
	w.Write(res)
}

// adds a user using the CreateUser() from sqlc
// accepts email in body of post request
// needs to access DB therefore is a methode of apiconfig
// accessible at /api/users
func (cfg *apiConfig) addUser(w http.ResponseWriter, r *http.Request) {
	//easier to return the user that the db returns
	type User struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}
	//to decode the payload
	type param struct {
		Email string
	}

	decoder := json.NewDecoder(r.Body)
	params := param{}
	err := decoder.Decode(&params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(500)
		response := map[string]string{"error": "Something went wrong"}
		data, err := json.Marshal(response)
		if err != nil {
			log.Printf("something wrong with json encoding of the error message")
			return
		}
		w.Write(data)
		return
	}
	email := params.Email
	usr, err := cfg.DB.CreateUser(r.Context(), email)
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(500)
		response := map[string]string{"error": "Something went wrong"}
		data, err := json.Marshal(response)
		if err != nil {
			log.Printf("something wrong with json encoding")
			return
		}
		w.Write(data)
		return
	}
	user := User{
		ID:        usr.ID,
		CreatedAt: usr.CreatedAt,
		UpdatedAt: usr.UpdatedAt,
		Email:     usr.Email,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	data, err := json.Marshal(user)
	if err != nil {
		return
	}
	w.Write(data)
}

func main() {
	//psql config
	err := godotenv.Load()
	if err != nil {
		log.Fatal("could not load .env")
	}
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL is not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Can't connect to database:", err)
	}
	dbQueries := database.New(db)
	const port = "8080"
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		DB:             dbQueries,
	}

	//handler (maps routes to fucntions)
	mux := http.NewServeMux()

	//all the routes available in this app
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", handlerReadiness)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metrics)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirps)
	mux.HandleFunc("GET /api/chirps/{id}", apiCfg.getChirp)
	mux.HandleFunc("POST /api/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/chirps", apiCfg.addChirp)
	mux.HandleFunc("POST /api/users", apiCfg.addUser)

	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	//server config
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Serving on port: %s\n", port)
	//stops running if theres something wrong else doesnt stop till keyboard interrupt
	log.Fatal(srv.ListenAndServe())
}
