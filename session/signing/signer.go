package signing

import (
	"context"
	"encoding/json"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/moby/buildkit/session"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func SignAttestation(ctx context.Context, statement intoto.Statement, sm *session.Manager, sessionID string) (stmt *dsse.Envelope, err error) {
	//TODO: check options to see if signing is required, and only then do anything
	group := session.NewGroup(sessionID)
	var resp *SigningResponse
	err = sm.Any(ctx, group, func(ctx context.Context, id string, c session.Caller) error {
		client := NewSignerVerifierClient(c.Conn())
		data, err := json.Marshal(statement)
		if err != nil {
			return err
		}
		resp, err = client.SignAttetation(ctx, &SigningRequest{
			Statement: data,
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	env := &dsse.Envelope{}
	err = json.Unmarshal(resp.Envelope, env)
	if err != nil {
		return nil, err
	}
	return env, nil
}
