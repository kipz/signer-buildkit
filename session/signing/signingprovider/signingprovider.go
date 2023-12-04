package signingprovider

import (
	"context"
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/signing"
	"github.com/openpubkey/openpubkey/parties"

	att "github.com/openpubkey/signed-attestation"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func NewSigningProvider() session.Attachable {
	return &signingProvider{}
}

func (sp *signingProvider) Register(server *grpc.Server) {
	signing.RegisterSignerVerifierServer(server, sp)
}

type signingProvider struct {
}

func (vp *signingProvider) SignAttetation(ctx context.Context, req *signing.SigningRequest) (*signing.SigningResponse, error) {
	var stmt intoto.Statement
	err := json.Unmarshal(req.Statement, &stmt)
	if err != nil {
		return nil, err
	}
	logrus.Info("Signing attestation %", stmt.PredicateType)
	env, err := SignInTotoStatement(ctx, stmt)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return &signing.SigningResponse{
		Envelope: data,
	}, nil
}

func SignInTotoStatement(ctx context.Context, stmt intoto.Statement) (*dsse.Envelope, error) {
	provider, err := parties.NewMockOpenIdProvider()

	s, err := dsse.NewEnvelopeSigner(att.NewOPKSignerVerifier(provider))
	if err != nil {
		return nil, fmt.Errorf("error creating dsse signer: %w", err)
	}

	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}

	env, err := s.SignPayload(ctx, intoto.PayloadType, payload)
	if err != nil {
		return nil, err
	}

	return env, nil
}
