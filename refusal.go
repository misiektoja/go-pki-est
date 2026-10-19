/*
Copyright (c) 2026 the go-pki-est contributors.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package est

import (
	"context"
	"errors"
	"net/http"
	"path"

	"github.com/go-chi/chi"
)

// Refusal describes a request the server refused without asking the CA.
type Refusal struct {
	// Operation is the last segment of the request path, such as
	// "simpleenroll" or "simplereenroll".
	Operation string

	// AdditionalPathSegment is the optional label from the request path.
	AdditionalPathSegment string

	// Status is the HTTP status code sent to the client.
	Status int

	// Reason is the error text sent to the client.
	Reason string

	// Request is the refused request. Its body may already have been read.
	Request *http.Request
}

// RefusalRecorder records the requests the server refuses without asking the
// CA, such as a malformed request, an unsupported content type or a renewal
// whose subject changed. Authentication failures from CheckBasicAuth and
// errors returned by the CA are not reported, because the host made those
// decisions. Server faults are not reported either.
//
// RecordRefusal runs before the response is written, with a context that is
// not cancelled when the client disconnects, so it must bound its own work.
// A returned error is logged and does not change the response.
type RefusalRecorder interface {
	RecordRefusal(ctx context.Context, refusal Refusal) error
}

// refuse reports a refusal the server made itself to the configured recorder
// and writes the error to the client.
func refuse(w http.ResponseWriter, r *http.Request, msg string, err error) {
	ctx := r.Context()

	var estErr Error
	if rec := refusalsFromContext(ctx); rec != nil && errors.As(err, &estErr) &&
		estErr.StatusCode() < http.StatusInternalServerError {
		refusal := Refusal{
			Operation:             path.Base(r.URL.Path),
			AdditionalPathSegment: chi.URLParam(r, apsParamName),
			Status:                estErr.StatusCode(),
			Reason:                estErr.Error(),
			Request:               r,
		}
		if recErr := rec.RecordRefusal(context.WithoutCancel(ctx), refusal); recErr != nil {
			LoggerFromContext(ctx).Errorw(logMsgRefusalRecordFailed, logFieldError, recErr.Error())
		}
	}

	writeOnError(ctx, w, msg, err)
}
