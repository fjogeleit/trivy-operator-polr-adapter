package server

import (
	"log"
	"net/http"

	"k8s.io/client-go/dynamic"

	"github.com/fjogeleit/trivy-operator-polr-adapter/pkg/crd"
)

type Server struct {
	validator crd.Validator
	client    dynamic.ResourceInterface
	mux       *http.ServeMux
	http      *http.Server
}

func (s *Server) HealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.validator(r.Context(), s.client); err != nil {
			log.Printf("[ERROR] %s\n", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
}

func (s *Server) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.validator(r.Context(), s.client); err != nil {
			log.Printf("[ERROR] %s\n", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
}

func (s *Server) Start() error {
	return s.http.ListenAndServe()
}

func New(client dynamic.ResourceInterface, validator crd.Validator, port int) *Server {
	mux := http.NewServeMux()

	server := &Server{
		mux:       mux,
		client:    client,
		validator: validator,
		http: &http.Server{
			Addr:    ":8080",
			Handler: mux,
		},
	}

	server.mux.HandleFunc("/healthz", server.HealthzHandler())
	server.mux.HandleFunc("/ready", server.ReadyHandler())

	return server
}
