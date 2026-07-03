package app

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/elloloop/identity/pkg/samlidp"
)

// samlMetadataPath is the well-known path the IdP serves its SAML
// EntityDescriptor XML on. SPs are configured with this URL to import the
// IdP's signing certificate and SSO/SLO endpoints.
const samlMetadataPath = "/saml/metadata"

// samlHandler is the browser-facing SAML IdP surface. In this slice it
// serves IdP metadata; the interactive SSO POST/Redirect binding and SLO
// are mounted by the same handler once the SSO-completion session bridge
// lands (see PR notes). It is registered only when the issuer is enabled,
// so a disabled deployment returns 404 (route never mounted) — preserving
// the gate-off invariant.
type samlHandler struct {
	issuer samlidp.Issuer
	logger *zap.Logger
}

// register mounts the SAML routes on mux only when the issuer is enabled.
// When disabled it mounts nothing, so /saml/* yields the mux's 404.
func (h *samlHandler) register(mux *http.ServeMux) {
	if h.issuer == nil || !h.issuer.Enabled() {
		return
	}
	mux.HandleFunc(samlMetadataPath, h.metadata)
}

func (h *samlHandler) metadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	md, err := h.issuer.Metadata()
	if err != nil {
		h.logger.Error("saml_metadata_failed", zap.Error(err))
		http.Error(w, "metadata unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(md)
}
