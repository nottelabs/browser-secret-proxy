// Command http-resolver is a reference detokenize service for
// browser-secret-proxy's http resolver. It answers from a JSON file and
// accepts only clients with a certificate from -client-ca.
//
// The values file maps each stand-in to its real value, as a string or as an
// object with the hosts it may go to:
//
//	{
//	  "tok_standin_123": "<real API token>",
//	  "4242424242424242": {"real": "<real card number>", "hosts": ["api.payments.example"]}
//	}
//
// It is a starting point for testing, not a production service: a real one
// looks values up in your vault and decides per principal_id.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"time"
)

type value struct {
	Real  string   `json:"real"`
	Hosts []string `json:"hosts,omitempty"`
}

func (v *value) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, &v.Real); err == nil {
		return nil
	}
	var entry struct {
		Real  *string  `json:"real"`
		Hosts []string `json:"hosts"`
	}
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	if entry.Real == nil {
		// Without it the entry would answer an empty value.
		return errors.New("an entry without \"real\"")
	}
	v.Real, v.Hosts = *entry.Real, entry.Hosts
	return nil
}

// handler answers detokenize requests from values.
func handler(values map[string]value) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			StandIns    []string `json:"stand_ins"`
			Host        string   `json:"host"`
			PrincipalID string   `json:"principal_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, "want {stand_ins, host, principal_id}", http.StatusBadRequest)
			return
		}
		// Leave out what you do not know or what may not go to req.Host:
		// the proxy then refuses the request.
		out := map[string]value{}
		for _, s := range req.StandIns {
			if v, ok := values[s]; ok {
				out[s] = v
			}
		}
		log.Printf("principal %q, host %q: %d of %d stand-ins resolved", req.PrincipalID, req.Host, len(out), len(req.StandIns))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"values": out})
	})
	return mux
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "address to listen on")
	cert := flag.String("cert", "", "PEM server certificate")
	key := flag.String("key", "", "PEM server key")
	clientCA := flag.String("client-ca", "", "PEM CA that issues the proxy's client certificate")
	valuesFile := flag.String("values", "", "JSON file of stand-in to real value")
	flag.Parse()

	data, err := os.ReadFile(*valuesFile)
	if err != nil {
		log.Fatal(err)
	}
	var values map[string]value
	if err := json.Unmarshal(data, &values); err != nil {
		log.Fatalf("%s: want a JSON object of stand-in to real value", *valuesFile)
	}
	caPEM, err := os.ReadFile(*clientCA)
	if err != nil {
		log.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		log.Fatalf("%s: no PEM certificate", *clientCA)
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           handler(values),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
		},
	}
	log.Printf("listening on %s with %d stand-ins", *listen, len(values))
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
